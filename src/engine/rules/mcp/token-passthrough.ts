// mcp/token-passthrough (spec section 8.5): in one function, the client's token (the incoming Authorization header
// or the verified token from authInfo) flows into the headers of an outbound fetch / axios / httpx call.

import { anchorText, args, callee, calleeName, calleePath, exprPath, isCall, isFunction, isInside, kids, kwarg, line, prop, resolveLocal, unwrap, walk } from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";
import { Taint, bindingsIn, clientTokenKey, isClientTokenSource, isIncomingHeaderSet, mcpHttpUnits, nestedFunctions, targetNames } from "./common.js";

const WHY =
  "The token the client sent to this server is forwarded to another API. That API then trusts a token that was not issued for it, which breaks audience checks and lets a stolen token reach every upstream service.";
const FIX = "Use the server's own credentials for upstream APIs; never forward the client's token.";

const QUICK_SOURCE = /authorization|authInfo|get_access_token|\.auth\.token|\b(?:req|request|incoming\w*)\.headers\b/i;
const QUICK_SINK = /\bfetch\b|axios|httpx|requests|\bgot\b|\bky\b|undici|aiohttp|\bRequest\b|defaults\.headers|\.headers\[|\.headers\.update/;

/**
 * Calls to the token's own authorization server (OIDC userinfo, RFC 7662 introspection, tokeninfo) validate the
 * token rather than pass it through (DECISIONS.md).
 */
const AUTH_SERVER_URL = /userinfo|introspect|tokeninfo|\/oauth2?\/|\.well-known\/|\/protocol\/openid-connect\//i;

const JS_FETCH = /^(?:globalThis\.|window\.|self\.)?fetch$|^undici\.(?:fetch|request)$|^(?:got|ky|ofetch|\$fetch)(?:\.\w+)?$/;
const PY_HTTP_METHOD = new Set(["get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send"]);
const PY_HTTP_CTOR = /^(?:Async)?Client$|^Session$|^ClientSession$|^Request$|^build_request$/;

export const tokenPassthroughRule = defineRule({
  id: "mcp/token-passthrough",
  title: "Client token forwarded to another API",
  pack: "mcp",
  maturity: "experimental",
  source: SOURCES.mcpSecurity,
  appliesTo: (ctx) => mcpHttpUnits(ctx).length > 0,
  check(ctx, emit) {
    const files = new Set<string>();
    for (const unit of mcpHttpUnits(ctx)) for (const f of ctx.codeFiles(unit)) files.add(f);
    for (const file of [...files].sort()) {
      const text = ctx.read(file) ?? "";
      if (!QUICK_SOURCE.test(text) || !QUICK_SINK.test(text)) continue;
      const pf = ctx.parse(file);
      if (!pf) continue;
      const hits = new Map<number, SyntaxNode>();
      visitScope(pf, pf.root, new Set(), hits);
      for (const node of [...hits.values()].sort((a, b) => a.startIndex - b.startIndex)) {
        const entryId = entryFor(ctx, file, node);
        emit({
          severity: "critical",
          service: "mcp",
          file,
          line: line(node),
          anchor: anchorText(node),
          evidence: node.text,
          why: WHY,
          fix: { summary: FIX },
          ...(entryId ? { entryPointId: entryId } : {}),
        });
      }
    }
  },
});

/**
 * Analyse one function scope (the module root first). Names tainted in an enclosing function stay tainted in nested
 * ones unless a nested declaration shadows them; outbound calls are checked in the scope that contains them.
 */
function visitScope(pf: ParsedFile, scope: SyntaxNode, inherited: ReadonlySet<string>, hits: Map<number, SyntaxNode>): void {
  const t = new Taint({ isSource: isClientTokenSource, sourceKey: clientTokenKey });
  const declared = declaredNames(scope);
  for (const n of inherited) if (!declared.has(n)) t.names.add(n);
  t.propagate(bindingsIn(scope, false));
  walk(scope, (n) => {
    if (n.id !== scope.id && isFunction(n)) return false;
    if ((isCall(n) || n.type === "new_expression") && forwardsToken(pf, n, t)) hits.set(n.startIndex, n);
    else if (mutatesClientHeaders(pf, n, t)) hits.set(n.startIndex, n);
    return true;
  });
  for (const fn of nestedFunctions(scope)) visitScope(pf, fn, t.names, hits);
}

/** Names declared in this scope (not nested functions): `const/let/var` and Python assignments. Parameters are not counted. */
function declaredNames(scope: SyntaxNode): Set<string> {
  const out = new Set<string>();
  walk(scope, (n) => {
    if (n.id !== scope.id && isFunction(n)) return false;
    if (n.type === "variable_declarator") for (const x of targetNames(n.childForFieldName("name"))) out.add(x);
    else if (n.type === "assignment") {
      const left = n.childForFieldName("left");
      if (left?.type === "identifier") out.add(left.text);
    }
    return true;
  });
  return out;
}

/** An object literal, directly or through a same-file variable. */
function objectOf(pf: ParsedFile, n: SyntaxNode | null): SyntaxNode | null {
  const u = unwrap(n);
  if (!u) return null;
  if (u.type === "object" || u.type === "dictionary") return u;
  if (u.type === "identifier") {
    const v = unwrap(resolveLocal(pf, u.text, u));
    if (v && v.id !== u.id && (v.type === "object" || v.type === "dictionary")) return v;
  }
  return null;
}

/** Do these outbound headers carry the client's token (or the whole incoming header set)? */
function headersCarryToken(pf: ParsedFile, h: SyntaxNode, t: Taint): boolean {
  if (t.has(h) || containsIncomingHeaders(h)) return true;
  // `const headers = dict(request.headers)` / `new Headers(req.headers)`, then `headers=headers`.
  const u = unwrap(h);
  if (u?.type === "identifier") {
    const v = unwrap(resolveLocal(pf, u.text, u));
    if (v && v.id !== u.id && (t.has(v) || containsIncomingHeaders(v))) return true;
  }
  return false;
}

function containsIncomingHeaders(n: SyntaxNode): boolean {
  let hit = false;
  walk(n, (c) => {
    if (hit) return false;
    if (isIncomingHeaderSet(c)) hit = true;
    return !hit;
  });
  return hit;
}

/** The call targets the token's authorization server: a URL argument (or url / base_url / baseURL) names one. */
function callsAuthServer(pf: ParsedFile, call: SyntaxNode): boolean {
  const texts: string[] = [];
  for (const a of args(call)) {
    if (a.type === "keyword_argument") {
      if (/^(?:url|base_url)$/.test(a.childForFieldName("name")?.text ?? "")) texts.push(a.childForFieldName("value")?.text ?? "");
      continue;
    }
    const obj = objectOf(pf, a);
    if (obj) for (const key of ["url", "baseURL"]) texts.push(prop(obj, key)?.text ?? "");
    else texts.push(a.text);
  }
  return texts.some((x) => AUTH_SERVER_URL.test(x));
}

/** Is `call` an outbound HTTP call whose headers carry the client's token? */
function forwardsToken(pf: ParsedFile, call: SyntaxNode, t: Taint): boolean {
  const path = calleePath(call);
  if (pf.lang === "python") {
    const h = kwarg(call, "headers");
    if (!h) return false;
    const name = calleeName(call);
    if (!/^(?:httpx|requests|aiohttp)\./.test(path) && !PY_HTTP_METHOD.has(name) && !PY_HTTP_CTOR.test(name)) return false;
    return headersCarryToken(pf, h, t) && !callsAuthServer(pf, call);
  }
  let configs: SyntaxNode[];
  if (call.type === "new_expression") {
    if (path !== "Request") return false;
    configs = args(call).slice(1);
  } else if (JS_FETCH.test(path)) configs = args(call).slice(1);
  else if (/^axios(?:\.\w+)?$/.test(path) || isAxiosInstanceCall(pf, call)) configs = args(call);
  else return false;
  for (const c of configs) {
    const obj = objectOf(pf, c);
    const h = obj ? prop(obj, "headers") : null;
    if (h && headersCarryToken(pf, h, t)) return !callsAuthServer(pf, call);
  }
  return false;
}

/** `api.get(...)` where `api = axios.create(...)`. */
function isAxiosInstanceCall(pf: ParsedFile, call: SyntaxNode): boolean {
  const fn = callee(call);
  if (fn?.type !== "member_expression") return false;
  const obj = unwrap(fn.childForFieldName("object"));
  if (obj?.type !== "identifier") return false;
  const v = unwrap(resolveLocal(pf, obj.text, call));
  return !!v && isCall(v) && calleePath(v) === "axios.create";
}

/**
 * Default headers set from the client's token: `axios.defaults.headers.common.Authorization = token`,
 * Python `client.headers["Authorization"] = token` / `client.headers.update({...})` on an httpx / requests client.
 */
function mutatesClientHeaders(pf: ParsedFile, n: SyntaxNode, t: Taint): boolean {
  if (n.type === "assignment_expression") {
    return /\.defaults\.headers\b/.test(exprPath(n.childForFieldName("left"))) && t.has(n.childForFieldName("right"));
  }
  if (pf.lang !== "python") return false;
  if (n.type === "assignment") {
    const left = n.childForFieldName("left");
    if (left?.type !== "subscript") return false;
    const base = left.childForFieldName("value");
    return isHttpClientHeaders(pf, base, n) && t.has(n.childForFieldName("right"));
  }
  if (n.type === "call" && calleeName(n) === "update") {
    const fn = callee(n);
    const base = fn?.type === "attribute" ? fn.childForFieldName("object") : null;
    return isHttpClientHeaders(pf, base, n) && args(n).some((a) => t.has(a));
  }
  return false;
}

/** `<client>.headers` where `<client>` was created by httpx.Client / AsyncClient or requests.Session. */
function isHttpClientHeaders(pf: ParsedFile, n: SyntaxNode | null, at: SyntaxNode): boolean {
  const u = unwrap(n);
  if (u?.type !== "attribute" || u.childForFieldName("attribute")?.text !== "headers") return false;
  const obj = unwrap(u.childForFieldName("object"));
  if (obj?.type !== "identifier") return false;
  const v = unwrap(resolveLocal(pf, obj.text, at));
  if (v && isCall(v)) return /^(?:httpx\.(?:Async)?Client|requests\.Session|(?:Async)?Client|Session)$/.test(calleePath(v));
  // `async with httpx.AsyncClient() as client:`
  for (let p = at.parent; p; p = p.parent) {
    if (p.type !== "with_statement") continue;
    for (const item of p.descendantsOfType("as_pattern")) {
      if (!item) continue;
      const alias = item.childForFieldName("alias");
      const value = kids(item)[0];
      if (alias?.text === obj.text && value && isCall(value) && /(?:^|\.)(?:Async)?Client$|(?:^|\.)Session$/.test(calleePath(value))) return true;
    }
  }
  return false;
}

/** The inventory entry whose handler contains the node (innermost handler). */
function entryFor(ctx: ProjectContext, file: string, node: SyntaxNode): string | null {
  let best: { id: string; size: number } | null = null;
  for (const e of ctx.inventory) {
    for (const h of e.internal.handlers) {
      if (h.file !== file || !isInside(node, h.node)) continue;
      const size = h.node.endIndex - h.node.startIndex;
      if (!best || size < best.size) best = { id: e.id, size };
    }
  }
  return best?.id ?? null;
}
