// FastAPI adapter (spec section 8.2): decorated endpoints, APIRouter prefixes, include_router
// across modules, and Depends/Security guards on endpoints, decorators, routers and the app (section 8.3).

import {
  args,
  callee,
  calleeName,
  calleePath,
  callsIn,
  elements,
  exprPath,
  imports,
  isCall,
  kids,
  kwarg,
  params,
  positionalArgs,
  pyParam,
  stringValue,
  topLevel,
  unwrap,
  walk,
} from "../ast.js";
import { FASTAPI_SECURITY_CLASSES, type GuardMatcher, pyDecoratorRateLimited } from "../auth-guards.js";
import type { ProjectContext } from "../context.js";
import type { ParsedFile, SyntaxNode } from "../parse.js";
import { resolvePyBinding } from "../resolve.js";
import { joinPaths, normaliseFastapiPath } from "./paths.js";
import type { AdapterContext, RawEntry } from "./types.js";

const METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "api_route"]);

interface PyObj {
  key: string;
  file: string;
  pf: ParsedFile;
  name: string;
  isApp: boolean;
  prefix: string;
  deps: SyntaxNode[];
}

interface Include {
  parent: PyObj;
  target: PyObj | null;
  prefix: string;
  deps: SyntaxNode[];
}

interface GuardHit {
  guard: string;
  via: "dependency" | "router" | "server";
  param?: string;
}

export function fastapiAdapter(a: AdapterContext): RawEntry[] {
  const { ctx, unit, guards } = a;
  const objs = new Map<string, PyObj>();
  const files = ctx.codeFiles(unit, "py");

  for (const file of files) {
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const [name, decl] of topLevel(pf)) {
      const v = unwrap(decl.value);
      if (!v || !isCall(v)) continue;
      const ctor = calleePath(v);
      if (ctor !== "FastAPI" && ctor !== "APIRouter" && !/\.(?:FastAPI|APIRouter)$/.test(ctor)) continue;
      const isApp = /FastAPI$/.test(ctor);
      objs.set(`${file}#${name}`, {
        key: `${file}#${name}`,
        file,
        pf,
        name,
        isApp,
        prefix: normalisePrefix(stringValue(kwarg(v, "prefix")) ?? ""),
        deps: elements(kwarg(v, "dependencies")),
      });
    }
  }

  // include_router edges
  const includes: Include[] = [];
  for (const parent of objs.values()) {
    walk(parent.pf.root, (n) => {
      if (n.type !== "call") return true;
      if (calleePath(n) !== `${parent.name}.include_router`) return true;
      const first = positionalArgs(n)[0] ?? kwarg(n, "router");
      includes.push({
        parent,
        target: first ? resolveRouter(ctx, parent.pf, first, objs, unit.root) : null,
        prefix: normalisePrefix(stringValue(kwarg(n, "prefix")) ?? ""),
        deps: elements(kwarg(n, "dependencies")),
      });
      return true;
    });
  }
  const included = new Set(includes.map((i) => i.target?.key).filter(Boolean));
  const appSlowApi = new Set<string>();
  for (const o of objs.values()) {
    if (o.isApp && /add_middleware\s*\(\s*SlowAPIMiddleware/.test(o.pf.source)) appSlowApi.add(o.key);
  }

  const out: RawEntry[] = [];
  const emit = (obj: PyObj, prefix: string, inherited: { node: SyntaxNode; via: "router" | "server"; file: string }[], rateLimited: boolean, seen: Set<string>) => {
    if (seen.has(obj.key)) return;
    const nextSeen = new Set(seen).add(obj.key);
    const ownDeps = obj.deps.map((d) => ({ node: d, via: obj.isApp ? ("server" as const) : ("router" as const), file: obj.file }));
    const chain = [...inherited, ...ownDeps];
    const fullPrefix = joinPaths(prefix, obj.prefix);
    const rl = rateLimited || appSlowApi.has(obj.key);
    for (const ep of endpointsOf(obj)) {
      const path = joinPaths(fullPrefix, ep.path);
      const hits: GuardHit[] = [];
      for (const d of chain) {
        const g = dependencyGuard(ctx, obj.pf.file === d.file ? obj.pf : (ctx.parse(d.file) ?? obj.pf), d.node, guards, unit.root);
        if (g) hits.push({ guard: g, via: d.via });
      }
      for (const d of ep.decoratorDeps) {
        const g = dependencyGuard(ctx, obj.pf, d, guards, unit.root);
        if (g) hits.push({ guard: g, via: "dependency" });
      }
      const guardParams: string[] = [];
      for (const p of params(ep.fn)) {
        const info = pyParam(p);
        if (!info) continue;
        const dep = paramDependency(ctx, obj.pf, info.type, info.default, unit.root);
        if (!dep) continue;
        const g = dependencyGuard(ctx, obj.pf, dep, guards, unit.root);
        if (g) {
          hits.push({ guard: g, via: "dependency", param: info.name });
          guardParams.push(info.name);
        }
      }
      let auth: RawEntry["auth"] | undefined;
      const best = hits.find((h) => h.via === "dependency") ?? hits[0];
      if (best) auth = { guarded: true, via: best.via, guard: best.guard };
      for (const method of ep.methods) {
        out.push({
          kind: "http_route",
          service: "api",
          framework: "fastapi",
          method,
          path,
          file: obj.file,
          line: ep.decorator.startPosition.row + 1,
          handlers: [{ file: obj.file, pf: obj.pf, node: ep.fn }],
          middleware: [],
          registration: { file: obj.file, pf: obj.pf, node: ep.decorator },
          ...(auth ? { auth } : {}),
          // Request input only: dependency parameters (Depends/Security) and framework objects are not input.
          inputNames: params(ep.fn)
            .map((p) => pyParam(p))
            .filter((p): p is NonNullable<typeof p> => !!p && !!p.name)
            .filter((p) => !paramDependency(ctx, obj.pf, p.type, p.default, unit.root) && !/^(?:Request|Response|BackgroundTasks|WebSocket|HTTPConnection)$/.test(p.type?.text ?? ""))
            .map((p) => p.name),
          guardParams,
          rateLimited: rl || pyDecoratorRateLimited(ep.decorators),
        });
      }
    }
    for (const inc of includes) {
      if (inc.parent.key !== obj.key || !inc.target) continue;
      const incDeps = inc.deps.map((d) => ({ node: d, via: "router" as const, file: obj.file }));
      emit(inc.target, joinPaths(fullPrefix, inc.prefix), [...chain, ...incDeps], rl, nextSeen);
    }
  };
  const roots = [...objs.values()].filter((o) => o.isApp || !included.has(o.key)).sort((x, y) => (x.key < y.key ? -1 : 1));
  for (const r of roots) emit(r, "", [], false, new Set());
  return out;
}

function normalisePrefix(p: string): string {
  if (!p) return "";
  return normaliseFastapiPath(p).replace(/\/+$/, "");
}

interface Endpoint {
  fn: SyntaxNode;
  decorator: SyntaxNode;
  decorators: SyntaxNode[];
  methods: string[];
  path: string;
  decoratorDeps: SyntaxNode[];
}

function endpointsOf(obj: PyObj): Endpoint[] {
  const out: Endpoint[] = [];
  for (const def of obj.pf.root.descendantsOfType("decorated_definition")) {
    if (!def) continue;
    const fn = def.childForFieldName("definition");
    if (!fn || fn.type !== "function_definition") continue;
    const decorators = kids(def).filter((k) => k.type === "decorator");
    for (const d of decorators) {
      const call = kids(d)[0];
      if (!call || !isCall(call)) continue;
      const path = calleePath(call);
      const m = new RegExp(`^${obj.name}\\.(\\w+)$`).exec(path);
      if (!m || !METHODS.has(m[1]!)) continue;
      const p = stringValue(positionalArgs(call)[0] ?? kwarg(call, "path"));
      if (p === null) continue;
      let methods: string[];
      if (m[1] === "api_route") {
        const ms = elements(kwarg(call, "methods"))
          .map((e) => stringValue(e))
          .filter((x): x is string => !!x);
        methods = ms.length ? ms.map((x) => x.toUpperCase()) : ["GET"];
      } else methods = [m[1]!.toUpperCase()];
      out.push({ fn, decorator: d, decorators, methods, path: normaliseFastapiPath(p), decoratorDeps: elements(kwarg(call, "dependencies")) });
    }
  }
  return out;
}

/** Resolve the first argument of include_router to a router object (local, `module.router`, or `from x import router`). */
function resolveRouter(ctx: ProjectContext, pf: ParsedFile, expr: SyntaxNode, objs: Map<string, PyObj>, unitRoot: string): PyObj | null {
  const u = unwrap(expr);
  if (!u) return null;
  if (u.type === "identifier") {
    const local = objs.get(`${pf.file}#${u.text}`);
    if (local) return local;
    const imp = imports(pf).find((b) => b.local === u.text);
    if (imp && imp.imported !== "*") {
      const r = resolvePyBinding(ctx, pf.file, imp.source, imp.imported, imp.level, unitRoot);
      if (r?.attr) return objs.get(`${r.file}#${r.attr}`) ?? null;
    }
    return null;
  }
  if (u.type === "attribute") {
    const objNode = unwrap(u.childForFieldName("object"));
    const attr = u.childForFieldName("attribute")?.text ?? "";
    if (objNode?.type !== "identifier") return null;
    const imp = imports(pf).find((b) => b.local === objNode.text);
    if (!imp) return null;
    const r = imp.imported === "*" ? resolvePyBinding(ctx, pf.file, "", imp.source, 0, unitRoot) : resolvePyBinding(ctx, pf.file, imp.source, imp.imported, imp.level, unitRoot);
    if (!r) return null;
    return objs.get(`${r.file}#${r.attr ?? attr}`) ?? (r.attr === null ? (objs.get(`${r.file}#${attr}`) ?? null) : null);
  }
  return null;
}

/** The dependency callable of a parameter: `= Depends(x)`, `Annotated[T, Depends(x)]`, or an alias of that. */
function paramDependency(ctx: ProjectContext, pf: ParsedFile, type: SyntaxNode | null, dflt: SyntaxNode | null, unitRoot: string): SyntaxNode | null {
  const fromCall = (n: SyntaxNode | null): SyntaxNode | null => {
    const u = unwrap(n);
    if (u && isCall(u) && /^(?:Depends|Security|fastapi\.Depends|fastapi\.Security)$/.test(calleePath(u))) return u;
    return null;
  };
  const d = fromCall(dflt);
  if (d) return d;
  if (!type) return null;
  const t = kids(type)[0] ?? type;
  const fromAnnotated = (n: SyntaxNode): SyntaxNode | null => {
    if (n.type === "subscript" && /(?:^|\.)Annotated$/.test(exprPath(n.childForFieldName("value")))) {
      for (const s of n.childrenForFieldName("subscript")) {
        const hit = s ? fromCall(s) : null;
        if (hit) return hit;
      }
    }
    if (n.type === "generic_type" && /Annotated/.test(n.text)) {
      for (const c of n.descendantsOfType("call")) {
        const hit = c ? fromCall(c) : null;
        if (hit) return hit;
      }
    }
    return null;
  };
  const direct = fromAnnotated(t);
  if (direct) return direct;
  if (t.type === "identifier") {
    // Type alias: CurrentUser = Annotated[User, Depends(get_current_user)] (same file or imported)
    const local = topLevel(pf).get(t.text);
    if (local) {
      const v = unwrap(local.value);
      if (v) return fromAnnotated(v);
    }
    const imp = imports(pf).find((b) => b.local === t.text);
    if (imp && imp.imported !== "*") {
      const r = resolvePyBinding(ctx, pf.file, imp.source, imp.imported, imp.level, unitRoot);
      const tpf = r?.attr ? ctx.parse(r.file) : null;
      const decl = tpf ? topLevel(tpf).get(r!.attr!) : null;
      const v = decl ? unwrap(decl.value) : null;
      if (v) return fromAnnotated(v);
    }
  }
  return null;
}

/** If a `Depends(x)` / `Security(x)` expression depends on a guard, return the guard name (follows functions up to 3 levels). */
export function dependencyGuard(ctx: ProjectContext, pf: ParsedFile, depExpr: SyntaxNode, guards: GuardMatcher, unitRoot: string, depth = 0): string | null {
  if (depth > 3) return null;
  const u = unwrap(depExpr);
  if (!u || !isCall(u)) return null;
  if (!/^(?:Depends|Security|fastapi\.Depends|fastapi\.Security)$/.test(calleePath(u))) return null;
  const target = unwrap(positionalArgs(u)[0] ?? kwarg(u, "dependency"));
  if (!target) return null;
  const name = target.type === "identifier" ? target.text : target.type === "attribute" ? (target.childForFieldName("attribute")?.text ?? "") : isCall(target) ? calleeName(target) : "";
  if (guards.isGuardName(name, "fastapi")) return name;
  // An instance of a security scheme class: oauth2_scheme = OAuth2PasswordBearer(...)
  const { def, defPf } = lookupPy(ctx, pf, target, unitRoot);
  if (def && isCall(def) && FASTAPI_SECURITY_CLASSES.has(calleeName(def))) return `${name} (${calleeName(def)})`;
  if (isCall(target) && FASTAPI_SECURITY_CLASSES.has(calleeName(target))) return calleeName(target);
  // A dependency function that itself depends on a guard.
  if (def && def.type === "function_definition" && defPf) {
    for (const p of params(def)) {
      const info = pyParam(p);
      if (!info) continue;
      const inner = paramDependency(ctx, defPf, info.type, info.default, unitRoot);
      if (inner) {
        const g = dependencyGuard(ctx, defPf, inner, guards, unitRoot, depth + 1);
        if (g) return `${name} → ${g}`;
      }
    }
    for (const c of callsIn(def)) {
      if (guards.isGuardName(calleeName(c), "fastapi")) return `${name} → ${calleeName(c)}`;
    }
  }
  return null;
}

function lookupPy(ctx: ProjectContext, pf: ParsedFile, target: SyntaxNode, unitRoot: string): { def: SyntaxNode | null; defPf: ParsedFile | null } {
  if (target.type !== "identifier") return { def: null, defPf: null };
  const local = topLevel(pf).get(target.text);
  if (local) return { def: unwrap(local.value), defPf: pf };
  const imp = imports(pf).find((b) => b.local === target.text);
  if (imp && imp.imported !== "*") {
    const r = resolvePyBinding(ctx, pf.file, imp.source, imp.imported, imp.level, unitRoot);
    const tpf = r?.attr ? ctx.parse(r.file) : null;
    const decl = tpf ? topLevel(tpf).get(r!.attr!) : null;
    if (decl && tpf) return { def: unwrap(decl.value), defPf: tpf };
  }
  return { def: null, defPf: null };
}

export { args, callee };
