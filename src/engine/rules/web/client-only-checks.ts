// web/client-only-checks: Role check only in the UI (spec 8.5). A client component shows an element only
// on a role condition and the element's event handler calls a server action or an API route that does
// not check the role on the server.

import { nextMiddleware } from "../../adapters/nextjs.js";
import { args, callee, collapse, exportsOf, exprPath, hasDirective, importOf, isCall, isFunction, kids, objectProps, resolveFunction, resolveLocal, stringValue, unwrap, walk } from "../../ast.js";
import { callsOneLevel } from "../../auth-guards.js";
import { clientGraph } from "../../client-graph.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import { guardMatcherFor } from "../../inventory.js";
import type { InventoryEntry } from "../../inventory-types.js";
import { langForFile, type ParsedFile, type SyntaxNode } from "../../parse.js";
import { redact } from "../../redact.js";
import { resolveJsModule } from "../../resolve.js";
import { defineRule, SOURCES } from "../types.js";

const WHY = "Hiding an element from non-admins in the browser does not stop anyone from calling the server action or API route directly, so the role must also be checked on the server.";

const ROLE_IDENT = /^(?:(?:is|has|can)_?)?(?:super_?)?(?:admin|administrator|superuser|staff|moderator)s?$|^(?:user_?|current_?)?roles?$|^permissions?$/i;
const ROLE_VALUE = /^(?:admin|administrator|super_?admin|superuser|owner|staff|moderator)$/i;
const ROLE_CALL = /^(?:has|check|is|require|assert|ensure)_?(?:role|permission|admin)s?$/i;
/** Server side: any name mentioning admin / role / permission (spec: guard names matching (?i)admin|role|permission). */
const SERVER_ROLE = /admin|role|permission/i;

const NAME_NODES = new Set(["identifier", "property_identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern"]);

/** Does a client-side condition test a role (role === 'admin', isAdmin, user.role, permissions.includes(…))? */
export function isRoleCondition(cond: SyntaxNode): boolean {
  let hit = false;
  walk(cond, (n) => {
    if (hit) return false;
    if (isFunction(n)) return false;
    if (NAME_NODES.has(n.type) && ROLE_IDENT.test(n.text)) hit = true;
    else if (isCall(n) && ROLE_CALL.test(exprPath(callee(n)).split(".").pop() ?? "")) hit = true;
    else if (n.type === "binary_expression" && /^(?:===|==|!==|!=)$/.test(n.childForFieldName("operator")?.text ?? "")) {
      for (const side of [n.childForFieldName("left"), n.childForFieldName("right")]) {
        const s = stringValue(side);
        if (s !== null && ROLE_VALUE.test(s)) hit = true;
      }
    }
    return !hit;
  });
  return hit;
}

/** Server side: a name mentioning admin / role / permission anywhere in the node. */
function mentionsRoleServer(n: SyntaxNode): boolean {
  let hit = false;
  walk(n, (c) => {
    if (hit) return false;
    if (NAME_NODES.has(c.type) && SERVER_ROLE.test(c.text)) hit = true;
    else if (c.type === "string" && ROLE_VALUE.test(stringValue(c) ?? "")) hit = true;
    return !hit;
  });
  return hit;
}

function isJsx(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  return !!u && (u.type === "jsx_element" || u.type === "jsx_self_closing_element" || u.type === "jsx_fragment");
}

function isNegated(cond: SyntaxNode): boolean {
  const u = unwrap(cond);
  if (!u) return false;
  if (u.type === "unary_expression" && u.text.trimStart().startsWith("!")) return true;
  if (u.type === "binary_expression") {
    const op = u.childForFieldName("operator")?.text ?? "";
    if (op === "!==" || op === "!=") return true;
    if (op === "||") return isNegated(u.childForFieldName("left")!) || isNegated(u.childForFieldName("right")!);
  }
  return false;
}

function exitsEarly(stmt: SyntaxNode): boolean {
  if (stmt.type === "return_statement" || stmt.type === "throw_statement") return true;
  if (stmt.type === "expression_statement") return /^(?:redirect|notFound|router\.(?:push|replace))\s*\(/.test(stmt.text.trim());
  if (stmt.type === "statement_block") {
    const last = kids(stmt).pop();
    return !!last && exitsEarly(last);
  }
  return false;
}

interface Gated {
  cond: SyntaxNode;
  subtree: SyntaxNode;
}

/** Subtrees rendered only when a role condition holds: `cond && <X/>`, `cond ? <X/> : …`, `if (cond) …`. */
export function roleGatedSubtrees(pf: ParsedFile): Gated[] {
  const out: Gated[] = [];
  walk(pf.root, (n) => {
    if (n.type === "binary_expression" && n.childForFieldName("operator")?.text === "&&") {
      const left = n.childForFieldName("left");
      const right = n.childForFieldName("right");
      if (left && right && isJsx(right) && isRoleCondition(left)) out.push({ cond: left, subtree: unwrap(right)! });
    } else if (n.type === "ternary_expression") {
      // `isAdmin ? <X/> : …` gates the consequence; `!isAdmin ? … : <X/>` gates the alternative.
      const cond = n.childForFieldName("condition");
      if (cond && isRoleCondition(cond)) {
        const b = n.childForFieldName(isNegated(cond) ? "alternative" : "consequence");
        if (b && isJsx(b)) out.push({ cond, subtree: unwrap(b)! });
      }
    } else if (n.type === "if_statement") {
      const cond = n.childForFieldName("condition");
      const cons = n.childForFieldName("consequence");
      if (cond && cons && isRoleCondition(cond)) {
        if (!isNegated(cond)) out.push({ cond, subtree: cons });
        else {
          // `if (!isAdmin) return null; …` → the rest of the block is for admins; `else { … }` likewise.
          const alt = n.childForFieldName("alternative");
          if (alt) out.push({ cond, subtree: alt });
          if (exitsEarly(cons) && n.parent) {
            let after = false;
            for (const s of kids(n.parent)) {
              if (s.id === n.id) {
                after = true;
                continue;
              }
              if (after) out.push({ cond, subtree: s });
            }
          }
        }
      }
    }
    return true;
  });
  return out;
}

// ---------------------------------------------------------------- server calls from handlers

type Target = { kind: "action"; file: string; exportName: string; node: SyntaxNode } | { kind: "http"; method: string; path: string; node: SyntaxNode };

function isUseServerFile(ctx: ProjectContext, file: string): boolean {
  const pf = ctx.parse(file);
  return !!pf && hasDirective(pf.root, "use server");
}

/** URL pattern of a fetch/axios argument: literal parts kept, dynamic parts become ":p". */
export function urlPattern(pf: ParsedFile, node: SyntaxNode | null, depth = 0): string | null {
  const u = unwrap(node);
  if (!u || depth > 6) return null;
  const s = stringValue(u);
  if (s !== null) return s;
  if (u.type === "template_string") {
    let out = "";
    for (const c of u.namedChildren) {
      if (!c) continue;
      if (c.type === "string_fragment" || c.type === "escape_sequence") out += c.text;
      else if (c.type === "template_substitution") out += urlPattern(pf, kids(c)[0] ?? null, depth + 1) ?? ":p";
    }
    return out;
  }
  if (u.type === "binary_expression" && u.childForFieldName("operator")?.text === "+") {
    return `${urlPattern(pf, u.childForFieldName("left"), depth + 1) ?? ":p"}${urlPattern(pf, u.childForFieldName("right"), depth + 1) ?? ":p"}`;
  }
  if (u.type === "identifier") {
    const v = resolveLocal(pf, u.text, u);
    if (v && v.id !== u.id) return urlPattern(pf, v, depth + 1);
  }
  return null;
}

export function normaliseUrl(url: string): string | null {
  let s = url.split(/[?#]/)[0]!;
  s = s.replace(/^https?:\/\/[^/]+/i, "");
  if (s.startsWith(":p/")) s = s.slice(2);
  if (!s.startsWith("/")) return null;
  return s;
}

function httpTarget(pf: ParsedFile, call: SyntaxNode): Target | null {
  const path = exprPath(callee(call));
  let method: string | null = null;
  let urlNode: SyntaxNode | null = null;
  if (path === "fetch" || path === "window.fetch") {
    urlNode = args(call)[0] ?? null;
    method = "GET";
    const init = unwrap(args(call)[1] ?? null);
    const m = init?.type === "object" ? objectProps(init).find((p) => p.key === "method") : undefined;
    if (m) method = (stringValue(m.value) ?? "GET").toUpperCase();
  } else {
    const m = /^axios\.(get|post|put|patch|delete)$/.exec(path);
    if (!m) return null;
    method = m[1]!.toUpperCase();
    urlNode = args(call)[0] ?? null;
  }
  const raw = urlPattern(pf, urlNode);
  const url = raw === null ? null : normaliseUrl(raw);
  return url ? { kind: "http", method, path: url, node: call } : null;
}

/** Server calls made by a handler expression (inline function, same-file function, imported helper or action). */
function targetsOf(ctx: ProjectContext, pf: ParsedFile, expr: SyntaxNode): Target[] {
  const out: Target[] = [];
  const fromIdentifier = (id: SyntaxNode, node: SyntaxNode): boolean => {
    const imp = importOf(pf, id.text);
    if (!imp) return false;
    const file = resolveJsModule(ctx, pf.file, imp.source);
    if (!file) return false;
    if (isUseServerFile(ctx, file)) {
      out.push({ kind: "action", file, exportName: imp.imported === "*" ? "default" : imp.imported, node });
      return true;
    }
    // Imported helper (one level): look for fetch/axios calls inside it.
    const tpf = ctx.parse(file);
    const fn = tpf ? exportsOf(tpf).get(imp.imported === "*" ? "default" : imp.imported) : undefined;
    if (tpf && fn && isFunction(fn)) for (const c of callsOneLevel(fn, tpf)) {
      const t = httpTarget(tpf, c);
      if (t) out.push({ ...t, node });
    }
    return true;
  };
  const visitCalls = (fn: SyntaxNode) => {
    for (const c of callsOneLevel(fn, pf)) {
      const t = httpTarget(pf, c);
      if (t) {
        out.push(t);
        continue;
      }
      const f = unwrap(callee(c));
      if (f?.type === "identifier") fromIdentifier(f, c);
      else if (f?.type === "member_expression" && f.childForFieldName("property")?.text === "bind") {
        const obj = unwrap(f.childForFieldName("object"));
        if (obj?.type === "identifier") fromIdentifier(obj, c);
      }
    }
  };
  const u = unwrap(expr);
  if (!u) return out;
  if (isFunction(u)) visitCalls(u);
  else if (u.type === "identifier") {
    const fn = resolveFunction(pf, u, u);
    if (fn) visitCalls(fn);
    else fromIdentifier(u, u);
  } else if (isCall(u)) {
    const f = unwrap(callee(u));
    if (f?.type === "member_expression" && f.childForFieldName("property")?.text === "bind") {
      const obj = unwrap(f.childForFieldName("object"));
      if (obj?.type === "identifier") fromIdentifier(obj, u);
    } else {
      const t = httpTarget(pf, u);
      if (t) out.push(t);
      else if (f?.type === "identifier") {
        const fn = resolveFunction(pf, f, u);
        if (fn) visitCalls(fn);
        else fromIdentifier(f, u);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- matching entry points

export function pathMatches(req: string, route: string): number {
  const rq = req.split("/").filter(Boolean);
  const rt = route.split("/").filter(Boolean);
  let literal = 0;
  for (let i = 0; i < rt.length; i++) {
    const r = rt[i]!;
    if (r.startsWith(":") && (r.endsWith("*") || r.endsWith("*?"))) {
      const rest = rq.length - i;
      return rest >= (r.endsWith("*?") ? 0 : 1) ? literal : -1;
    }
    const q = rq[i];
    if (q === undefined) return -1;
    const param = r.startsWith(":") || r.startsWith("{") || q.includes(":p");
    if (!param && r !== q) return -1;
    if (!param) literal++;
  }
  return rq.length === rt.length ? literal : -1;
}

function resolveEntry(ctx: ProjectContext, t: Target): InventoryEntry | null {
  if (t.kind === "action") {
    const name = `${t.file}#${t.exportName}`;
    return ctx.inventory.find((e) => e.kind === "server_action" && e.name === name) ?? null;
  }
  // At least one literal path segment must match, so fully dynamic URLs never match.
  let best: InventoryEntry | null = null;
  let bestScore = 0;
  for (const e of ctx.inventory) {
    if (e.kind !== "http_route" || e.path === undefined) continue;
    if (e.method !== "*" && e.method !== t.method) continue;
    const score = pathMatches(t.path, e.path);
    if (score > bestScore) {
      best = e;
      bestScore = score;
    }
  }
  return best;
}

const middlewareCache = new WeakMap<ProjectContext, Map<UnitInfo, ReturnType<typeof nextMiddleware>>>();

function middlewareOf(ctx: ProjectContext, unit: UnitInfo): ReturnType<typeof nextMiddleware> {
  let m = middlewareCache.get(ctx);
  if (!m) {
    m = new Map();
    middlewareCache.set(ctx, m);
  }
  if (!m.has(unit)) m.set(unit, nextMiddleware({ ctx, unit, guards: guardMatcherFor(ctx) }));
  return m.get(unit)!;
}

function hasServerRoleCheck(ctx: ProjectContext, e: InventoryEntry): boolean {
  if (e.auth.guard && SERVER_ROLE.test(e.auth.guard)) return true;
  for (const m of e.internal.middleware) if (SERVER_ROLE.test(m.name) || mentionsRoleServer(m.node)) return true;
  if (e.framework === "fastapi" && mentionsRoleServer(e.internal.registration.node)) return true;
  for (const h of e.internal.handlers) {
    if (mentionsRoleServer(h.node)) return true;
    // Same-file helpers called by the handler (one level).
    for (const c of callsOneLevel(h.node, h.pf)) if (SERVER_ROLE.test(exprPath(callee(c)).split(".").pop() ?? "")) return true;
    if (e.framework === "fastapi" && h.node.parent?.type === "decorated_definition" && mentionsRoleServer(h.node.parent)) return true;
  }
  if (e.framework === "nextjs" && e.path !== undefined) {
    const mw = middlewareOf(ctx, e.internal.unit);
    const pf = mw ? ctx.parse(mw.file) : null;
    if (mw && pf && mw.covers(e.path) && mentionsRoleServer(pf.root)) return true;
  }
  return false;
}

/** Redact, then shorten (so a cut can never expose part of a secret). */
function clip(s: string, n: number): string {
  const r = redact(s);
  return r.length <= n ? r : `${r.slice(0, n - 1)}…`;
}

function describeEntry(e: InventoryEntry): string {
  if (e.kind === "server_action") return `server action ${e.name?.split("#").pop() ?? ""}`;
  return `${e.method === "*" ? "" : `${e.method} `}${e.path ?? ""}`;
}

function clientFiles(ctx: ProjectContext, unit: UnitInfo): string[] {
  return clientGraph(ctx, unit).files.filter((f) => {
    const l = langForFile(f);
    return !!l && l !== "python";
  });
}

export const clientOnlyChecksRule = defineRule({
  id: "web/client-only-checks",
  title: "Role check only in the UI",
  pack: "web",
  maturity: "experimental",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => ctx.hasUnit("web") && (ctx.hasUnit("api") || ctx.inventory.some((e) => e.kind === "server_action")),
  check(ctx, emit) {
    const done = new Set<string>();
    const files = [...new Set(ctx.unitsOf("web").flatMap((u) => clientFiles(ctx, u)))].sort();
    for (const file of files) {
      const text = ctx.read(file);
      if (!text || !/[<]/.test(text)) continue;
      const pf = ctx.parse(file);
      if (!pf) continue;
      for (const g of roleGatedSubtrees(pf)) {
        walk(g.subtree, (n) => {
          if (n.type !== "jsx_attribute") return true;
          const name = kids(n)[0]?.text ?? "";
          if (!/^on[A-Z]\w*$|^(?:action|formAction)$/.test(name)) return true;
          const value = kids(n)[1];
          const expr = value?.type === "jsx_expression" ? (kids(value)[0] ?? null) : null;
          if (!expr) return true;
          for (const t of targetsOf(ctx, pf, expr)) {
            const entry = resolveEntry(ctx, t);
            if (!entry || hasServerRoleCheck(ctx, entry)) continue;
            const key = `${file}\u0000${n.id}\u0000${entry.id}`;
            if (done.has(key)) continue;
            done.add(key);
            const cond = collapse((unwrap(g.cond) ?? g.cond).text);
            emit({
              severity: "high",
              advisory: true,
              service: "web",
              file,
              line: n.startPosition.row + 1,
              anchor: `${cond} -> ${entry.id}`,
              evidence: `${clip(cond, 70)} … ${clip(collapse(n.text), 70)} → ${describeEntry(entry)} (${entry.file}:${entry.line})`,
              why: WHY,
              fix: { summary: "Check the user's role in the server action or route handler this element calls and return 403 when it does not match; keep the UI check only for display." },
              entryPointId: entry.id,
            });
          }
          return true;
        });
      }
    }
  },
});
