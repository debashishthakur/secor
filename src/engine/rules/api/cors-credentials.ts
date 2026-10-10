// api/cors-credentials (spec section 8.5): any origin allowed together with credentials.
// cors({ origin: true | "*" | (o, cb) => cb(null, true), credentials: true }); a manual Access-Control-Allow-Origin
// taken from the request's Origin header with Access-Control-Allow-Credentials: true; FastAPI
// CORSMiddleware(allow_origins=["*"] or allow_origin_regex=".*", allow_credentials=True).

import {
  anchorText,
  booleanValue,
  calleeName,
  callsIn,
  descendants,
  elements,
  enclosingFunction,
  endLine,
  exportsOf,
  functionBody,
  isCall,
  isFunction,
  kids,
  kwarg,
  line,
  paramNames,
  positionalArgs,
  prop,
  resolveLocal,
  stringValue,
  topLevel,
  unwrap,
  walk,
} from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import { findingId } from "../../finding.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";
import { type TemplateTarget, apiEntries, entryTarget, testTemplate } from "./common.js";

const ID = "api/cors-credentials";
const WHY = "Allowing any origin together with credentials lets any website send signed-in requests to this API and read the responses.";
const FIX = "List allowed origins explicitly.";

const ACAO = "access-control-allow-origin";
const ACAC = "access-control-allow-credentials";
const ORIGIN_READ = /headers\??\.origin\b|headers\s*\[\s*["']origin["']\s*\]|\.get\(\s*["']origin["']\s*\)|\.header\(\s*["']origin["']\s*\)/i;
const ANY_ORIGIN_REGEX = /^\^?(?:\.\*|\.\+|\(\.\*\)|\(\.\+\))\$?$/;

/** Resolve an identifier to its local value (same function, then top level). */
function valueOf(pf: ParsedFile, n: SyntaxNode | null, at: SyntaxNode): SyntaxNode | null {
  const u = unwrap(n);
  if (u?.type === "identifier") return unwrap(resolveLocal(pf, u.text, at)) ?? u;
  return u;
}

// ---------------------------------------------------------------- cors({ ... })

/** `(origin, cb) => cb(null, true)` or `cb(null, origin)` with no condition: allows every origin. */
function allowsEveryOrigin(fn: SyntaxNode): boolean {
  const names = paramNames(fn);
  const originName = names[0];
  const cbName = names[1];
  const body = functionBody(fn);
  if (!body || !cbName) return false;
  let conditional = false;
  walk(body, (n) => {
    if (["if_statement", "ternary_expression", "switch_statement"].includes(n.type)) conditional = true;
    if (n.type === "binary_expression" && ["&&", "||", "??"].includes(n.childForFieldName("operator")?.text ?? "")) conditional = true;
    return !conditional;
  });
  if (conditional) return false;
  return callsIn(body).some((c) => {
    if (calleeName(c) !== cbName) return false;
    const [err, ok] = positionalArgs(c);
    return unwrap(err ?? null)?.type === "null" && (booleanValue(ok ?? null) === true || (!!originName && unwrap(ok ?? null)?.text === originName));
  });
}

function corsPackageHit(pf: ParsedFile, call: SyntaxNode): boolean {
  const name = calleeName(call);
  if (name !== "cors" && name !== "enableCors") return false;
  const opts = valueOf(pf, positionalArgs(call)[0] ?? null, call);
  if (!opts || opts.type !== "object") return false;
  if (booleanValue(prop(opts, "credentials")) !== true) return false;
  const origin = valueOf(pf, prop(opts, "origin"), call);
  if (!origin) return false;
  if (booleanValue(origin) === true || stringValue(origin) === "*") return true;
  if (elements(origin).some((e) => stringValue(e) === "*")) return true;
  return isFunction(origin) && allowsEveryOrigin(origin);
}

// ---------------------------------------------------------------- manual headers

interface HeaderSite {
  node: SyntaxNode;
  value: SyntaxNode;
}

/** `res.setHeader(name, v)` / `headers.set(name, v)` / `{ [name]: v }` / Python `headers[name] = v`. */
function headerSites(root: SyntaxNode, header: string): HeaderSite[] {
  const out: HeaderSite[] = [];
  walk(root, (n) => {
    if (isCall(n)) {
      const [k, v] = positionalArgs(n);
      if (k && v && stringValue(k)?.toLowerCase() === header) out.push({ node: n, value: v });
    } else if (n.type === "pair") {
      const key = n.childForFieldName("key");
      const v = n.childForFieldName("value");
      const ks = key ? (stringValue(key) ?? key.text) : "";
      if (v && ks.toLowerCase() === header) out.push({ node: n, value: v });
    } else if (n.type === "assignment") {
      const left = n.childForFieldName("left");
      const right = n.childForFieldName("right");
      if (left?.type === "subscript" && right && stringValue(left.childForFieldName("subscript"))?.toLowerCase() === header) out.push({ node: n, value: right });
    }
    return true;
  });
  return out;
}

/** The value reads the request's Origin header (directly or through a local). */
function readsOrigin(pf: ParsedFile, v: SyntaxNode): { yes: boolean; name: string | null } {
  const u = unwrap(v);
  if (!u) return { yes: false, name: null };
  if (ORIGIN_READ.test(u.text)) return { yes: true, name: null };
  for (const id of u.type === "identifier" ? [u] : descendants(u, "identifier")) {
    const decl = resolveLocal(pf, id.text, id);
    if (decl && ORIGIN_READ.test(decl.text)) return { yes: true, name: id.text };
    // const { origin } = req.headers
    if (!decl && id.text === "origin" && /\{\s*[^}]*\borigin\b[^}]*\}\s*=\s*\w+(?:\.\w+)*\.headers\b/.test(pf.source)) return { yes: true, name: id.text };
  }
  return { yes: false, name: null };
}

function isTrue(v: SyntaxNode): boolean {
  return booleanValue(v) === true || stringValue(v)?.toLowerCase() === "true";
}

const ALLOWLIST_TEST = /\.(?:includes|has|indexOf|test|match|startsWith|endsWith|some|find)\s*\(|===|!==|==|!=|\bnot\s+in\b|\bin\b/;

/** An if / ternary / switch in the function that compares the origin with something: treated as an allowlist check. */
function originChecked(scope: SyntaxNode, name: string | null): boolean {
  const re = new RegExp(`\\b${name ?? "origin"}\\b|${ORIGIN_READ.source}`, "i");
  let hit = false;
  walk(scope, (n) => {
    if (hit) return false;
    const cond = n.type === "if_statement" || n.type === "while_statement" ? n.childForFieldName("condition") : n.type === "ternary_expression" || n.type === "conditional_expression" ? (n.childForFieldName("condition") ?? kids(n)[1] ?? null) : n.type === "switch_statement" ? n.childForFieldName("value") : null;
    if (cond && re.test(cond.text) && ALLOWLIST_TEST.test(cond.text)) hit = true;
    return !hit;
  });
  return hit;
}

function manualHits(pf: ParsedFile): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  const origins = headerSites(pf.root, ACAO);
  if (!origins.length) return out;
  const creds = headerSites(pf.root, ACAC).filter((s) => isTrue(s.value));
  if (!creds.length) return out;
  for (const site of origins) {
    const r = readsOrigin(pf, site.value);
    if (!r.yes) continue;
    const scope = enclosingFunction(site.node);
    const sameScope = creds.some((c) => enclosingFunction(c.node)?.id === scope?.id) || !scope;
    if (!sameScope && !creds.some((c) => !enclosingFunction(c.node))) continue;
    if (scope && originChecked(scope, r.name)) continue;
    out.push(site.node);
  }
  return out;
}

// ---------------------------------------------------------------- FastAPI CORSMiddleware

function pyHit(pf: ParsedFile, call: SyntaxNode): boolean {
  const isCors = calleeName(call) === "CORSMiddleware" || positionalArgs(call).some((a) => unwrap(a)?.text === "CORSMiddleware");
  if (!isCors) return false;
  const creds = kwarg(call, "allow_credentials");
  if (creds?.type !== "true") return false;
  const pyValue = (n: SyntaxNode | null) => {
    const u = unwrap(n);
    if (u?.type !== "identifier") return u;
    return unwrap(resolveLocal(pf, u.text, call) ?? topLevel(pf).get(u.text)?.value ?? null) ?? u;
  };
  const origins = pyValue(kwarg(call, "allow_origins"));
  if (elements(origins).some((e) => stringValue(e) === "*")) return true;
  const re = stringValue(pyValue(kwarg(call, "allow_origin_regex")));
  return re !== null && ANY_ORIGIN_REGEX.test(re);
}

// ---------------------------------------------------------------- templates

function templateTarget(ctx: ProjectContext, unit: UnitInfo, file: string): TemplateTarget {
  const entries = apiEntries(ctx).filter((e) => e.internal.unit === unit && e.kind === "http_route");
  const inFile = entries.find((e) => e.file === file);
  if (inFile) return entryTarget(inFile);
  const rep = entries.find((e) => e.method === "GET") ?? entries[0];
  if (unit.framework === "nextjs") {
    const isMiddleware = /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.[jt]s$/.test(file);
    if (isMiddleware) {
      const pf = ctx.parse(file);
      const exps = pf ? exportsOf(pf) : new Map<string, SyntaxNode>();
      const exportName = exps.has("middleware") ? "middleware" : exps.has("proxy") ? "proxy" : "default";
      return { unit, framework: "nextjs", method: rep?.method ?? "GET", path: rep?.path ?? "/api", file, exportName, variant: "middleware" };
    }
  }
  return rep ? entryTarget(rep) : { unit, framework: unit.framework, method: "GET", path: "/" };
}

export const corsCredentials = defineRule({
  id: ID,
  title: "Any origin allowed with credentials",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => ctx.hasUnit("api"),
  check(ctx, emit) {
    const seenFiles = new Set<string>();
    for (const unit of ctx.unitsOf("api")) {
      for (const file of ctx.codeFiles(unit)) {
        if (seenFiles.has(file)) continue;
        seenFiles.add(file);
        const text = ctx.read(file) ?? "";
        if (!/cors|CORSMiddleware|access-control-allow-origin/i.test(text)) continue;
        const pf = ctx.parse(file);
        if (!pf) continue;
        const hits: SyntaxNode[] = [];
        if (pf.lang === "python") {
          for (const c of callsIn(pf.root)) if (isCall(c) && pyHit(pf, c)) hits.push(c);
          hits.push(...manualHits(pf));
        } else {
          for (const c of callsIn(pf.root)) if (isCall(c) && corsPackageHit(pf, c)) hits.push(c);
          hits.push(...manualHits(pf));
        }
        for (const node of hits.sort((a, b) => a.startIndex - b.startIndex)) {
          const anchor = anchorText(node);
          const id = findingId(ID, file, anchor);
          emit({
            severity: "high",
            service: "api",
            file,
            line: line(node),
            endLine: endLine(node),
            anchor,
            evidence: anchor,
            why: WHY,
            fix: { summary: FIX, testTemplate: testTemplate(ctx, ID, id, templateTarget(ctx, unit, file)) },
          });
        }
      }
    }
  },
});
