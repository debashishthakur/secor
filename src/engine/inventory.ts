// Inventory (spec section 8.1 step 4): run the framework adapters and derive auth, declaredPublic,
// callsPaidApi and writesDb for every entry point.

import type { EntryPoint } from "../types.js";
import { args, booleanValue, callee, walk, calleeName, calleePath, callsIn, exportsOf, functionName, importOf, isCall, isFunction, kwarg, prop, resolveFunction, resolveLocal, unwrap } from "./ast.js";
import { GuardMatcher, callsOneLevel, callsPaidApi, dbCallsIn, handlerRateLimited, isRateLimitExpr } from "./auth-guards.js";
import { parsePublicRoute } from "./config.js";
import type { ProjectContext } from "./context.js";
import type { UnitInfo } from "./detect.js";
import { expressAdapter } from "./adapters/express.js";
import { fastapiAdapter } from "./adapters/fastapi.js";
import { mcpPyAdapter, mcpTsAdapter } from "./adapters/mcp.js";
import { nextjsAdapter } from "./adapters/nextjs.js";
import { samePath } from "./adapters/paths.js";
import type { AdapterContext, RawEntry } from "./adapters/types.js";
import type { InventoryEntry, MiddlewareRef } from "./inventory-types.js";
import type { ParsedFile, SyntaxNode } from "./parse.js";
import { resolveJsModule } from "./resolve.js";
import { sha256Hex } from "./util/hash.js";

export function guardMatcherFor(ctx: ProjectContext): GuardMatcher {
  return new GuardMatcher({ guards: ctx.config.auth.guards, ownershipHelpers: ctx.config.auth.ownershipHelpers, rateLimitHelpers: ctx.config.rateLimit.helpers });
}

export function entryPointId(e: Pick<EntryPoint, "kind" | "framework" | "method" | "path" | "name" | "file">): string {
  return sha256Hex(`${e.kind}|${e.framework}|${e.method ?? ""}|${e.path ?? e.name ?? ""}|${e.file}`).slice(0, 12);
}

export function buildInventory(ctx: ProjectContext): InventoryEntry[] {
  const guards = guardMatcherFor(ctx);
  const out = new Map<string, InventoryEntry>();
  for (const unit of ctx.units) {
    const a: AdapterContext = { ctx, unit, guards };
    let raw: RawEntry[] = [];
    switch (unit.framework) {
      case "express":
        raw = expressAdapter(a);
        break;
      case "nextjs":
        raw = nextjsAdapter(a);
        break;
      case "fastapi":
        raw = fastapiAdapter(a);
        break;
      case "mcp-ts":
        raw = mcpTsAdapter(a);
        break;
      case "mcp-py":
        raw = mcpPyAdapter(a);
        break;
      case "vite":
        raw = [];
        break;
    }
    const serverAuth = unit.kind === "mcp" ? mcpServerAuth(ctx, unit) : null;
    for (const r of raw) {
      const e = finalize(ctx, unit, guards, r, serverAuth);
      if (!out.has(e.id)) out.set(e.id, e);
    }
  }
  return [...out.values()].sort(compareEntries);
}

export function compareEntries(a: EntryPoint, b: EntryPoint): number {
  return (
    cmp(a.file, b.file) ||
    a.line - b.line ||
    cmp(a.kind, b.kind) ||
    cmp(a.method ?? "", b.method ?? "") ||
    cmp(a.path ?? a.name ?? "", b.path ?? b.name ?? "") ||
    cmp(a.id, b.id)
  );
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function finalize(ctx: ProjectContext, unit: UnitInfo, guards: GuardMatcher, r: RawEntry, serverAuth: EntryPoint["auth"] | null): InventoryEntry {
  const id = entryPointId(r);
  const auth = r.auth ?? computeAuth(ctx, guards, r) ?? (r.service === "mcp" && serverAuth ? serverAuth : { guarded: false, via: null });
  const rateLimited =
    !!r.rateLimited ||
    r.middleware.some((m) => {
      const pf = ctx.parse(m.file);
      return pf ? isRateLimitExpr(m.node, pf, guards) : false;
    }) ||
    r.handlers.some((h) => handlerRateLimited(h.node, h.pf, guards));
  return {
    id,
    kind: r.kind,
    service: r.service,
    framework: r.framework,
    ...(r.method !== undefined ? { method: r.method } : {}),
    ...(r.path !== undefined ? { path: r.path } : {}),
    ...(r.name !== undefined ? { name: r.name } : {}),
    file: r.file,
    line: r.line,
    auth,
    declaredPublic: isDeclaredPublic(ctx, unit, r),
    callsPaidApi: r.handlers.some((h) => callsPaidApi(h.node, h.pf)),
    writesDb: r.handlers.some((h) => dbCallsIn(h.node, h.pf).some((d) => d.op === "write")),
    internal: {
      unit,
      handlers: r.handlers,
      middleware: r.middleware,
      registration: r.registration,
      inputNames: r.inputNames ?? [],
      guardParams: r.guardParams ?? [],
      middlewareCovered: !!r.middlewareCovered,
      rateLimited,
      ...(r.methodBranch ? { methodBranch: r.methodBranch } : {}),
    },
  };
}

/**
 * Guard from the middleware chain, a handler wrapper, or a call in the handler: same-file helpers one level deep
 * (section 8.3), and project helpers imported from another file one level deep (DECISIONS.md).
 */
function computeAuth(ctx: ProjectContext, guards: GuardMatcher, r: RawEntry): EntryPoint["auth"] | null {
  for (let i = 0; i < r.middleware.length; i++) {
    const g = middlewareGuard(ctx, guards, r.middleware[i]!, r.framework);
    if (g) return { guarded: true, via: r.middlewareLevels?.[i] ?? "middleware", guard: g };
  }
  for (const w of r.wrappers ?? []) if (guards.isGuardWrapper(w, r.framework)) return { guarded: true, via: "handler", guard: w };
  for (const h of r.handlers) {
    const calls = callsOneLevel(h.node, h.pf);
    for (const c of calls) {
      const g = callGuard(guards, h.pf, c, r.framework);
      if (g) return { guarded: true, via: "handler", guard: g };
    }
    if (inlineCredentialCheck(h.node, h.pf)) return { guarded: true, via: "handler", guard: "inline credential check" };
    if (h.pf.lang === "python") continue;
    for (const c of calls) {
      const target = importedFunction(ctx, h.pf, c);
      if (!target) continue;
      for (const inner of callsIn(target.node)) {
        const g = callGuard(guards, target.pf, inner, r.framework);
        if (g) return { guarded: true, via: "handler", guard: `${calleeName(c)} → ${g}` };
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------- inline credential checks

const CREDENTIAL_JS =
  /\b(?:req|request)\.(?:cookies|signedCookies|session|user|auth)\b|\b(?:req|request)\.headers\b[^;]{0,80}authori[sz]ation|\.headers\.get\(\s*["']authorization["']\)|\bcookies\(\)\s*\.get\(\s*["'][^"']*(?:token|session|sid|auth|jwt)[^"']*["']\)/i;
const CREDENTIAL_PY = /\brequest\.(?:session|cookies|user|auth)\b|\brequest\.headers\b[^\n]{0,80}authori[sz]ation/i;
const EXIT_JS = /\breturn\b|\bthrow\b|\bnext\s*\(\s*(?:new\s+\w*Error|err)|\bstatus\(\s*40[13]\s*\)|\bsendStatus\(\s*40[13]\s*\)|\bredirect\s*\(|\bunauthorized\s*\(|\bforbidden\s*\(|\bstatus:\s*40[13]\b/;
const EXIT_PY = /\braise\b|\breturn\b[^\n]*40[13]|\bRedirectResponse\(/;

/**
 * An inline guard in the handler (DECISIONS.md): a value read from a request credential (cookie, session,
 * Authorization header, req.user) is tested for absence and the handler exits early or answers 401/403.
 * `if (!req.user) return res.sendStatus(401)`; `const u = users.get(req.cookies.token); if (!u) { next(err); return }`.
 */
export function inlineCredentialCheck(fn: SyntaxNode, pf: ParsedFile): boolean {
  const py = pf.lang === "python";
  const credential = py ? CREDENTIAL_PY : CREDENTIAL_JS;
  const exit = py ? EXIT_PY : EXIT_JS;
  const credVars = new Set<string>();
  let found = false;
  walk(fn, (n) => {
    if (found) return false;
    if (n.type === "variable_declarator" || n.type === "assignment") {
      const name = n.childForFieldName(n.type === "assignment" ? "left" : "name");
      const value = n.childForFieldName(n.type === "assignment" ? "right" : "value");
      if (name && value && (credential.test(value.text) || [...credVars].some((v) => new RegExp(`(?<![\\w.])${v}(?![\\w])`).test(value.text)))) {
        for (const id of name.type === "identifier" ? [name.text] : boundNamesSafe(name)) credVars.add(id);
      }
    } else if (n.type === "if_statement") {
      const cond = n.childForFieldName("condition")?.text ?? "";
      const body = n.childForFieldName("consequence")?.text ?? "";
      const negated = py ? /\bnot\b|\bis\s+None\b|==\s*None/.test(cond) : /!|===?\s*(?:null|undefined)\b|==\s*null/.test(cond);
      const mentions = credential.test(cond) || [...credVars].some((v) => new RegExp(`(?<![\\w.])${v}(?![\\w])`).test(cond));
      const alt = n.childForFieldName("alternative")?.text ?? "";
      // `if (!user) exit` — or the inverted `if (user) {...} else exit`.
      if (mentions && ((negated && exit.test(body)) || (!negated && alt && exit.test(alt)))) found = true;
    }
    return true;
  });
  return found;
}

function boundNamesSafe(n: SyntaxNode): string[] {
  const out: string[] = [];
  walk(n, (c) => {
    if (c.type === "identifier" || c.type === "shorthand_property_identifier_pattern") out.push(c.text);
    return true;
  });
  return out;
}

/** A guard call, by its own name or by the original name of an aliased import (`import { expressjwt as jwt }`). */
export function callGuard(guards: GuardMatcher, pf: ParsedFile, call: SyntaxNode, framework: RawEntry["framework"]): string | null {
  if (optionalAuthOptions(call)) return null;
  const direct = guards.guardCall(call, framework);
  if (direct) return direct;
  const c = callee(call);
  if (c?.type === "identifier") {
    const imp = importOf(pf, c.text);
    if (imp && imp.imported !== "default" && imp.imported !== "*" && imp.imported !== c.text) {
      if (imp.imported === "expressjwt" && imp.source === "express-jwt") return "expressjwt";
      if (guards.isGuardName(imp.imported, framework)) return imp.imported;
    }
    if (imp?.source === "express-jwt" && (imp.imported === "default" || imp.imported === "*")) return "expressjwt";
  }
  return null;
}

/** `jwt({ credentialsRequired: false })` (express-jwt) lets anonymous requests through: optional auth is not a guard. */
function optionalAuthOptions(call: SyntaxNode): boolean {
  return args(call).some((a) => booleanValue(prop(a, "credentialsRequired")) === false);
}

/** The function an identifier callee refers to when it is imported from another project file. */
function importedFunction(ctx: ProjectContext, pf: ParsedFile, call: SyntaxNode): { pf: ParsedFile; node: SyntaxNode } | null {
  const c = callee(call);
  if (c?.type !== "identifier") return null;
  const imp = importOf(pf, c.text);
  if (!imp) return null;
  const file = resolveJsModule(ctx, pf.file, imp.source);
  const tpf = file ? ctx.parse(file) : null;
  if (!tpf) return null;
  const v = exportsOf(tpf).get(imp.imported === "*" ? "default" : imp.imported);
  const fn = v ? resolveFunction(tpf, v) : null;
  return fn ? { pf: tpf, node: fn } : null;
}

/**
 * Resolve a JS expression to the node that defines it: local declarations, imports from project files,
 * and `obj.prop` on object literals (`auth.required` → `jwt({...})`). Depth-limited.
 */
function resolveValue(ctx: ProjectContext, pf: ParsedFile, n: SyntaxNode | null, depth = 0): { pf: ParsedFile; node: SyntaxNode } | null {
  const u = unwrap(n);
  if (!u || depth > 4) return null;
  if (u.type === "identifier") {
    const local = unwrap(resolveLocal(pf, u.text, u));
    if (local) return resolveValue(ctx, pf, local, depth + 1) ?? { pf, node: local };
    const imp = importOf(pf, u.text);
    if (!imp) return null;
    const file = resolveJsModule(ctx, pf.file, imp.source);
    const tpf = file ? ctx.parse(file) : null;
    const v = tpf ? exportsOf(tpf).get(imp.imported === "*" ? "default" : imp.imported) : null;
    if (!tpf || !v) return null;
    return resolveValue(ctx, tpf, v, depth + 1) ?? { pf: tpf, node: v };
  }
  if (u.type === "member_expression") {
    const key = u.childForFieldName("property")?.text ?? "";
    const objNode = unwrap(u.childForFieldName("object"));
    if (objNode?.type === "identifier") {
      const imp = importOf(pf, objNode.text);
      if (imp?.imported === "*") {
        const file = resolveJsModule(ctx, pf.file, imp.source);
        const tpf = file ? ctx.parse(file) : null;
        const v = tpf ? exportsOf(tpf).get(key) : null;
        if (tpf && v) return resolveValue(ctx, tpf, v, depth + 1) ?? { pf: tpf, node: v };
      }
    }
    const obj = resolveValue(ctx, pf, objNode, depth + 1);
    if (obj && obj.node.type === "object") {
      const v = unwrap(prop(obj.node, key));
      if (v) return resolveValue(ctx, obj.pf, v, depth + 1) ?? { pf: obj.pf, node: v };
    }
    return null;
  }
  return { pf, node: u };
}

/**
 * A middleware expression is a guard by name, or resolves to a guard call: a variable initialised from one
 * (`const bearer = requireBearerAuth(...)`), an object property (`auth.required` → `expressjwt(...)`), or an import.
 */
export function middlewareGuard(ctx: ProjectContext, guards: GuardMatcher, m: MiddlewareRef, framework: RawEntry["framework"]): string | null {
  const u = unwrap(m.node);
  if (!u) return null;
  const pf = ctx.parse(m.file);
  if (pf && isCall(u)) return callGuard(guards, pf, u, framework);
  if (pf && pf.lang !== "python") {
    const resolved = resolveValue(ctx, pf, u);
    if (resolved && isCall(resolved.node)) return callGuard(guards, resolved.pf, resolved.node, framework);
    if (resolved && resolved.node.id !== u.id && isFunction(resolved.node)) {
      const name = functionName(resolved.node);
      if (name && guards.isGuardName(name, framework)) return name;
    }
  }
  return guards.guardExpr(u, framework);
}

function isDeclaredPublic(ctx: ProjectContext, unit: UnitInfo, r: RawEntry): boolean {
  for (const p of ctx.config.public) {
    if ("route" in p) {
      if (r.kind !== "http_route" || r.path === undefined) continue;
      const { method, path } = parsePublicRoute(p.route);
      if ((method === "*" || method === r.method) && samePath(path, r.path)) return true;
    } else if ("action" in p) {
      if (r.kind === "server_action" && r.name === p.action) return true;
    } else if ("mcpServer" in p) {
      if (r.service !== "mcp") continue;
      if (r.file === p.mcpServer || unit.mcp?.serverFiles.includes(p.mcpServer)) return true;
    }
  }
  return false;
}

/**
 * MCP server-level auth (used for tool entries and mcp/auth-required): TS `requireBearerAuth(` (not `mcpAuthRouter(` alone),
 * Python FastMCP/MCPServer constructed with auth=, token_verifier= or auth_server_provider=.
 */
export function mcpServerAuth(ctx: ProjectContext, unit: UnitInfo): EntryPoint["auth"] | null {
  for (const file of ctx.codeFiles(unit)) {
    const text = ctx.read(file) ?? "";
    if (unit.framework === "mcp-ts") {
      if (!/requireBearerAuth/.test(text)) continue;
      const pf = ctx.parse(file);
      if (!pf) continue;
      for (const c of callsIn(pf.root)) {
        const name = calleeName(c);
        // mcpAuthRouter only serves the OAuth endpoints; the MCP endpoint is protected by requireBearerAuth (DECISIONS.md).
        if (name === "requireBearerAuth") return { guarded: true, via: "server", guard: name };
      }
    } else if (unit.framework === "mcp-py") {
      if (!/(?:FastMCP|MCPServer)\s*\(/.test(text)) continue;
      const pf = ctx.parse(file);
      if (!pf) continue;
      for (const c of callsIn(pf.root)) {
        if (!/^(?:FastMCP|MCPServer)$/.test(calleeName(c))) continue;
        for (const k of ["auth", "token_verifier", "auth_server_provider"]) {
          const v = kwarg(c, k);
          if (v && v.type !== "none") return { guarded: true, via: "server", guard: `${calleePath(c)}(${k}=)` };
        }
      }
    }
  }
  return null;
}
