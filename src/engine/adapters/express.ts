// Express adapter (spec section 8.2): routes registered on apps and routers, prefixes from
// `app.use('/prefix', router)` across relative imports, and middleware guards (section 8.3).

import {
  args,
  callee,
  calleeName,
  closest,
  elements,
  enclosingFunction,
  exportsOf,
  exprPath,
  functionBody,
  importOf,
  isCall,
  isFunction,
  kids,
  resolveFunction,
  resolveLocal,
  stringValue,
  unwrap,
  walk,
} from "../ast.js";
import type { MiddlewareRef } from "../inventory-types.js";
import type { ParsedFile, SyntaxNode } from "../parse.js";
import { resolveJsModule } from "../resolve.js";
import type { AdapterContext, RawEntry } from "./types.js";
import { joinPaths, normaliseExpressPath } from "./paths.js";

const METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all"]);
const IMPLICIT_NAMES = /^(?:app|router|api|routes|server|[a-z]\w*Router)$/;

interface RouterObj {
  key: string;
  file: string;
  name: string;
  isApp: boolean;
  /** Function (or program) in which the object is declared. */
  scope: SyntaxNode;
  pf: ParsedFile;
}

interface Registration {
  order: number;
  file: string;
  pf: ParsedFile;
  node: SyntaxNode;
}

interface RouteReg extends Registration {
  method: string;
  paths: string[];
  middleware: MiddlewareRef[];
  handler: SyntaxNode | null;
  wrappers: string[];
}

interface UseReg extends Registration {
  prefix: string;
  middleware: MiddlewareRef[];
  mountExprs: SyntaxNode[];
  mounts: RouterObj[];
}

interface ObjState {
  obj: RouterObj;
  routes: RouteReg[];
  uses: UseReg[];
  mounted: boolean;
}

export function expressAdapter(a: AdapterContext): RawEntry[] {
  const { ctx, unit } = a;
  const states = new Map<string, ObjState>();
  const byFile = new Map<string, RouterObj[]>();

  const files = ctx.codeFiles(unit, "js");
  // Pass 1: router objects.
  for (const file of files) {
    const pf = ctx.parse(file);
    if (!pf) continue;
    const objs: RouterObj[] = [];
    walk(pf.root, (n) => {
      if (n.type !== "variable_declarator") return true;
      const name = n.childForFieldName("name");
      const value = unwrap(n.childForFieldName("value"));
      if (name?.type !== "identifier" || !value || !isCall(value)) return true;
      const kind = routerKind(value, pf);
      if (!kind) return true;
      const scope = enclosingFunction(n) ?? pf.root;
      objs.push({ key: `${file}#${name.text}#${n.startIndex}`, file, name: name.text, isApp: kind === "app", scope, pf });
      return true;
    });
    byFile.set(file, objs);
    for (const o of objs) states.set(o.key, { obj: o, routes: [], uses: [], mounted: false });
  }

  const findObj = (pf: ParsedFile, name: string, at: SyntaxNode): RouterObj | null => {
    let best: RouterObj | null = null;
    for (const o of byFile.get(pf.file) ?? []) {
      if (o.name !== name) continue;
      if (at.startIndex < o.scope.startIndex || at.endIndex > o.scope.endIndex) continue;
      if (!best || o.scope.startIndex >= best.scope.startIndex) best = o;
    }
    return best;
  };

  const implicitObj = (pf: ParsedFile, name: string, at: SyntaxNode): RouterObj => {
    const scope = enclosingFunction(at) ?? pf.root;
    const key = `${pf.file}#${name}#implicit${scope.startIndex}`;
    let st = states.get(key);
    if (!st) {
      const obj: RouterObj = { key, file: pf.file, name, isApp: false, scope, pf };
      st = { obj, routes: [], uses: [], mounted: false };
      states.set(key, st);
      byFile.set(pf.file, [...(byFile.get(pf.file) ?? []), obj]);
    }
    return st.obj;
  };

  // Pass 2: registrations.
  for (const file of files) {
    const pf = ctx.parse(file);
    if (!pf) continue;
    walk(pf.root, (n) => {
      if (n.type !== "call_expression") return true;
      const fn = callee(n);
      if (fn?.type !== "member_expression") return true;
      const method = fn.childForFieldName("property")?.text ?? "";
      const recv = unwrap(fn.childForFieldName("object"));
      if (!recv) return true;
      if (method === "use" && recv.type === "identifier") {
        const obj = findObj(pf, recv.text, n) ?? (IMPLICIT_NAMES.test(recv.text) ? implicitObj(pf, recv.text, n) : null);
        if (obj) states.get(obj.key)!.uses.push(parseUse(n, pf));
        return true;
      }
      if (!METHODS.has(method)) return true;
      // router.route('/x').get(h).post(h)
      let base = recv;
      let routePath: SyntaxNode | null = null;
      while (isCall(base)) {
        const inner = callee(base);
        if (inner?.type !== "member_expression") break;
        const prop = inner.childForFieldName("property")?.text ?? "";
        if (prop === "route") {
          routePath = args(base)[0] ?? null;
          base = unwrap(inner.childForFieldName("object")) ?? base;
          break;
        }
        if (!METHODS.has(prop)) break;
        base = unwrap(inner.childForFieldName("object")) ?? base;
      }
      if (base.type !== "identifier") return true;
      const obj = findObj(pf, base.text, n) ?? (IMPLICIT_NAMES.test(base.text) ? implicitObj(pf, base.text, n) : null);
      if (!obj) return true;
      const all = args(n);
      const pathArgs = routePath ? [routePath] : all.slice(0, 1);
      const rest = routePath ? all : all.slice(1);
      if (!routePath && (all.length < 2 || !isPathLike(all[0]!, pf))) return true;
      const paths = pathArgs.flatMap((p) => pathValues(p, pf));
      const { middleware, handler, wrappers } = splitHandlers(rest, pf);
      states.get(obj.key)!.routes.push({ order: n.startIndex, file, pf, node: n, method: method === "all" ? "*" : method.toUpperCase(), paths, middleware, handler, wrappers });
      return true;
    });
  }

  // Pass 3: resolve mounts.
  for (const st of states.values()) {
    for (const u of st.uses) {
      for (const expr of u.mountExprs) {
        const target = resolveRouterExpr(expr, u.pf);
        if (target) {
          u.mounts.push(target);
          const ts = states.get(target.key);
          if (ts) ts.mounted = true;
        } else {
          u.middleware.push(middlewareRef(expr, u.file));
        }
      }
    }
  }

  function resolveRouterExpr(expr: SyntaxNode, pf: ParsedFile, depth = 0): RouterObj | null {
    if (depth > 4) return null;
    const e = unwrap(expr);
    if (!e) return null;
    if (e.type === "identifier") {
      const local = findObj(pf, e.text, e);
      if (local) return local;
      const imp = importOf(pf, e.text);
      if (imp) return resolveImported(pf, imp.source, imp.imported === "*" ? "default" : imp.imported, depth);
      const decl = resolveLocal(pf, e.text, e);
      if (decl && isCall(decl)) return resolveRouterExpr(decl, pf, depth + 1);
      return null;
    }
    if (e.type === "member_expression") {
      const objName = unwrap(e.childForFieldName("object"));
      const prop = e.childForFieldName("property")?.text ?? "";
      if (objName?.type === "identifier") {
        const imp = importOf(pf, objName.text);
        if (imp) return resolveImported(pf, imp.source, prop, depth);
      }
      return null;
    }
    if (isCall(e)) {
      const fnNode = callee(e);
      if (fnNode?.type === "identifier" && fnNode.text === "require") {
        const spec = stringValue(args(e)[0] ?? null);
        return spec ? resolveImported(pf, spec, "default", depth) : null;
      }
      // Router factory: f(...) returning a router declared inside f.
      if (fnNode?.type === "identifier") {
        const local = resolveFunction(pf, fnNode, e);
        if (local) return returnedRouter(local, pf);
        const imp = importOf(pf, fnNode.text);
        if (imp) {
          const file = resolveJsModule(ctx, pf.file, imp.source);
          const tpf = file ? ctx.parse(file) : null;
          const fn = tpf ? exportsOf(tpf).get(imp.imported === "*" ? "default" : imp.imported) : null;
          if (tpf && fn && isFunction(fn)) return returnedRouter(fn, tpf);
        }
      }
    }
    return null;
  }

  function resolveImported(pf: ParsedFile, spec: string, name: string, depth: number): RouterObj | null {
    const file = resolveJsModule(ctx, pf.file, spec);
    const tpf = file ? ctx.parse(file) : null;
    if (!tpf) return null;
    const value = exportsOf(tpf).get(name);
    if (!value) return null;
    if (value.type === "identifier") {
      return (byFile.get(tpf.file) ?? []).find((o) => o.name === value.text && o.scope.type === "program") ?? null;
    }
    if (isCall(value)) {
      // `export default Router()` style: the declarator is the object itself.
      const decl = value.parent?.type === "variable_declarator" ? value.parent.childForFieldName("name")?.text : null;
      if (decl) return (byFile.get(tpf.file) ?? []).find((o) => o.name === decl) ?? null;
      return resolveRouterExpr(value, tpf, depth + 1);
    }
    if (isFunction(value)) return returnedRouter(value, tpf);
    return null;
  }

  function returnedRouter(fn: SyntaxNode, pf: ParsedFile): RouterObj | null {
    const body = functionBody(fn);
    if (!body) return null;
    if (body.type !== "statement_block") {
      const v = unwrap(body);
      return v?.type === "identifier" ? findObj(pf, v.text, v) : null;
    }
    let found: RouterObj | null = null;
    walk(body, (n) => {
      if (found) return false;
      if (n.id !== fn.id && isFunction(n)) return false;
      if (n.type === "return_statement") {
        const v = unwrap(kids(n)[0] ?? null);
        if (v?.type === "identifier") found = findObj(pf, v.text, v);
      }
      return true;
    });
    return found;
  }

  // Pass 4: walk from roots (apps and never-mounted routers), composing prefixes and middleware.
  const out: RawEntry[] = [];
  const emit = (st: ObjState, prefix: string, inherited: InheritedMw[], via: Set<string>) => {
    if (via.has(st.obj.key)) return;
    const seen = new Set(via).add(st.obj.key);
    for (const r of st.routes) {
      for (const p of r.paths) {
        const full = joinPaths(prefix, p);
        const active = [...inherited, ...activeUses(st, r.order, p).map((m) => ({ ref: m, level: "router" as const }))];
        out.push({
          kind: "http_route",
          service: "api",
          framework: "express",
          method: r.method,
          path: full,
          file: r.file,
          line: r.node.startPosition.row + 1,
          handlers: r.handler ? resolveHandler(r.handler, r.pf, ctx) : [],
          middleware: [...active.map((x) => x.ref), ...r.middleware],
          middlewareLevels: [...active.map((x) => x.level), ...r.middleware.map(() => "middleware" as const)],
          wrappers: r.wrappers,
          registration: { file: r.file, pf: r.pf, node: r.node },
        });
      }
    }
    for (const u of st.uses) {
      if (!u.mounts.length) continue;
      const before = activeUses(st, u.order, u.prefix || "/").map((m) => ({ ref: m, level: "router" as const }));
      const own = u.middleware.map((m) => ({ ref: m, level: "router" as const }));
      for (const m of u.mounts) {
        const ms = states.get(m.key);
        if (ms) emit(ms, joinPaths(prefix, u.prefix), [...inherited, ...before, ...own], seen);
      }
    }
  };
  const roots = [...states.values()].filter((s) => s.obj.isApp || !s.mounted).sort((x, y) => (x.obj.key < y.obj.key ? -1 : 1));
  for (const st of roots) emit(st, "", [], new Set());
  return out;
}

type InheritedMw = { ref: MiddlewareRef; level: "router" };

/** Middleware from `obj.use(...)` calls (without a mounted router) registered before `order` whose prefix covers `path`. */
function activeUses(st: ObjState, order: number, path: string): MiddlewareRef[] {
  const out: MiddlewareRef[] = [];
  for (const u of st.uses) {
    if (u.order >= order || u.mounts.length) continue;
    if (u.prefix && !pathUnder(path, u.prefix)) continue;
    out.push(...u.middleware);
  }
  return out;
}

function pathUnder(path: string, prefix: string): boolean {
  const p = prefix.replace(/\/+$/, "");
  return p === "" || path === p || path.startsWith(`${p}/`);
}

function routerKind(call: SyntaxNode, pf: ParsedFile): "app" | "router" | null {
  const path = exprPath(callee(call));
  if (path === "express") return "app";
  if (path === "express.Router" || path === "Router" || path === "express.default.Router") {
    if (path === "Router") {
      const imp = importOf(pf, "Router");
      if (imp && imp.source !== "express") return null;
    }
    return "router";
  }
  if (/^\w+\.Router$/.test(path)) {
    const head = path.split(".")[0]!;
    const imp = importOf(pf, head);
    if (imp?.source === "express") return "router";
  }
  return null;
}

function isPathLike(n: SyntaxNode, pf: ParsedFile): boolean {
  const u = unwrap(n);
  if (!u) return false;
  if (u.type === "regex" || u.type === "array") return true;
  const s = stringValue(u);
  if (s !== null) return s.startsWith("/") || s === "*" || s.startsWith("*");
  if (u.type === "template_string") return true;
  if (u.type === "identifier" || u.type === "member_expression") {
    if (isFunction(resolveLocal(pf, u.type === "identifier" ? u.text : "", u))) return false;
    return !isCall(u);
  }
  return false;
}

/** Route path values: literal strings (normalised), arrays of them, or the written expression in braces. */
function pathValues(n: SyntaxNode, pf: ParsedFile): string[] {
  const u = unwrap(n);
  if (!u) return [];
  if (u.type === "array") return elements(u).flatMap((e) => pathValues(e, pf));
  const s = stringValue(u);
  if (s !== null) return [normaliseExpressPath(s)];
  if (u.type === "identifier") {
    const v = resolveLocal(pf, u.text, u);
    const sv = stringValue(v);
    if (sv !== null) return [normaliseExpressPath(sv)];
  }
  return [`{${u.text.replace(/\s+/g, "")}}`];
}

function parseUse(n: SyntaxNode, pf: ParsedFile): UseReg {
  const all = args(n);
  let prefix = "";
  let rest = all;
  const first = all[0] ? unwrap(all[0]) : null;
  if (first) {
    const s = stringValue(first);
    if (s !== null) {
      prefix = normaliseExpressPath(s);
      rest = all.slice(1);
    } else if (first.type === "array") {
      rest = all.slice(1);
      prefix = pathValues(first, pf)[0] ?? "";
    }
  }
  const middleware: MiddlewareRef[] = [];
  const mountExprs: SyntaxNode[] = [];
  for (const arg of rest.flatMap((x) => (unwrap(x)?.type === "array" ? elements(x) : [x]))) {
    if (mightBeRouter(arg, pf)) mountExprs.push(arg);
    else middleware.push(middlewareRef(arg, pf.file));
  }
  return { order: n.startIndex, file: pf.file, pf, node: n, prefix, middleware, mountExprs, mounts: [] };
}

/** Anything that is not obviously middleware may be a router: identifiers, require(), factory calls, members. */
function mightBeRouter(n: SyntaxNode, pf: ParsedFile): boolean {
  const u = unwrap(n);
  if (!u || isFunction(u)) return false;
  if (u.type === "identifier") return true;
  if (u.type === "member_expression") return true;
  if (isCall(u)) {
    const name = calleeName(u);
    if (name === "require") return true;
    const c = callee(u);
    if (c?.type === "identifier") return !!resolveFunction(pf, c, u) || !!importOf(pf, c.text);
  }
  return false;
}

export function middlewareRef(n: SyntaxNode, file: string): MiddlewareRef {
  const u = unwrap(n) ?? n;
  let name: string;
  if (isCall(u)) name = calleeName(u);
  else name = exprPath(u).split(".").pop() ?? u.text;
  return { file, node: u, name };
}

function splitHandlers(rest: SyntaxNode[], pf: ParsedFile): { middleware: MiddlewareRef[]; handler: SyntaxNode | null; wrappers: string[] } {
  const flat = rest.flatMap((x) => (unwrap(x)?.type === "array" ? elements(x) : [x]));
  if (flat.length === 0) return { middleware: [], handler: null, wrappers: [] };
  const last = flat[flat.length - 1]!;
  const wrappers: string[] = [];
  let handler: SyntaxNode | null = unwrap(last);
  // Unwrap handler wrappers: asyncHandler(fn), withAuth(fn), catchAsync(fn)
  while (handler && isCall(handler)) {
    const inner = args(handler).find((x) => isFunction(unwrap(x)) || unwrap(x)?.type === "identifier" || unwrap(x)?.type === "member_expression" || isCall(unwrap(x)));
    if (!inner) break;
    wrappers.push(calleeName(handler));
    handler = unwrap(inner);
  }
  const middleware = flat.slice(0, -1).map((m) => middlewareRef(m, pf.file));
  // A last argument that is not a function and wraps none (`app.get("/x", security.isAuthorized())`) is middleware
  // itself — the real handler is mounted elsewhere — so it takes part in guard detection.
  if (handler && !isFunction(handler) && wrappers.length === 0 && isCall(handler)) middleware.push(middlewareRef(handler, pf.file));
  return { middleware, handler, wrappers };
}

/** Resolve a handler expression to function nodes: inline functions, same-file functions, or exports of relative imports. */
export function resolveHandler(n: SyntaxNode, pf: ParsedFile, ctx: AdapterContext["ctx"], depth = 0): { file: string; pf: ParsedFile; node: SyntaxNode }[] {
  const u = unwrap(n);
  if (!u || depth > 3) return [];
  if (isFunction(u)) return [{ file: pf.file, pf, node: u }];
  // Handler factory: `getUserProfile()` returns the real handler (`return async (req, res) => {...}`).
  if (isCall(u)) {
    const factory = resolveHandler(callee(u) ?? u, pf, ctx, depth + 1)[0];
    const returned = factory ? returnedFunction(factory.node) : null;
    return factory && returned ? [{ file: factory.file, pf: factory.pf, node: returned }] : [];
  }
  if (u.type === "identifier") {
    const local = resolveFunction(pf, u, u);
    if (local) return [{ file: pf.file, pf, node: local }];
    const imp = importOf(pf, u.text);
    if (imp) {
      const file = resolveJsModule(ctx, pf.file, imp.source);
      const tpf = file ? ctx.parse(file) : null;
      const fn = tpf ? exportsOf(tpf).get(imp.imported === "*" ? "default" : imp.imported) : null;
      if (tpf && fn && isFunction(fn)) return [{ file: tpf.file, pf: tpf, node: fn }];
    }
    return [];
  }
  if (u.type === "member_expression") {
    const obj = unwrap(u.childForFieldName("object"));
    const prop = u.childForFieldName("property")?.text ?? "";
    if (obj?.type === "identifier") {
      const imp = importOf(pf, obj.text);
      if (imp) {
        const file = resolveJsModule(ctx, pf.file, imp.source);
        const tpf = file ? ctx.parse(file) : null;
        if (tpf) {
          const exp = exportsOf(tpf);
          const direct = exp.get(prop);
          if (direct && isFunction(direct)) return [{ file: tpf.file, pf: tpf, node: direct }];
          const container = exp.get(imp.imported === "*" ? "default" : imp.imported);
          const viaObj = container ? propFunction(container, prop) : null;
          if (viaObj) return [{ file: tpf.file, pf: tpf, node: viaObj }];
        }
      }
      const local = resolveLocal(pf, obj.text, u);
      const viaLocal = local ? propFunction(local, prop) : null;
      if (viaLocal) return [{ file: pf.file, pf, node: viaLocal }];
    }
  }
  return [];
}

/** The function a factory returns directly (`return (req, res) => {...}` or an arrow body that is a function). */
function returnedFunction(fn: SyntaxNode): SyntaxNode | null {
  const body = functionBody(fn);
  if (!body) return null;
  if (isFunction(unwrap(body))) return unwrap(body);
  let found: SyntaxNode | null = null;
  walk(body, (n) => {
    if (found) return false;
    if (n.id !== fn.id && isFunction(n)) return false;
    if (n.type === "return_statement") {
      const v = unwrap(kids(n)[0] ?? null);
      if (v && isFunction(v)) found = v;
    }
    return true;
  });
  return found;
}

function propFunction(container: SyntaxNode, prop: string): SyntaxNode | null {
  const u = unwrap(container);
  if (!u || u.type !== "object") return null;
  for (const c of kids(u)) {
    if (c.type === "pair" && c.childForFieldName("key")?.text === prop) {
      const v = unwrap(c.childForFieldName("value"));
      if (v && isFunction(v)) return v;
    }
    if (c.type === "method_definition" && c.childForFieldName("name")?.text === prop) return c;
  }
  return null;
}

export { closest };
