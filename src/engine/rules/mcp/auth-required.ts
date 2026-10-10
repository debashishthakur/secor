// mcp/auth-required (spec section 8.5): a remote MCP server reachable over HTTP with no authentication.

import { anchorText, calleeName, calleePath, callsIn, descendants, enclosingFunction, exprPath, imports, isFunction, kids, line, positionalArgs, resolveLocal, unwrap, walk } from "../../ast.js";
import { callsOneLevel, type GuardMatcher } from "../../auth-guards.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import type { MiddlewareRef } from "../../inventory-types.js";
import { guardMatcherFor, mcpServerAuth } from "../../inventory.js";
import { SOURCES, defineRule } from "../types.js";
import { SERVES_MCP_HTTP, type Site, TRANSPORT_HANDOFF, checksCredentials, declaredPublicServer, mcpHttpUnits, serverConstructions } from "./common.js";

const WHY = "Anyone who can reach this server over the network can list and call its tools: no authentication protects the MCP endpoint.";
const FIX_TS =
  "Add OAuth per the MCP authorization spec (for example requireBearerAuth on the MCP route), or declare the server public in secor.config.yaml with a reason if it serves no user data.";
const FIX_PY =
  "Add OAuth per the MCP authorization spec (FastMCP(..., token_verifier=..., auth=AuthSettings(...))), or declare the server public in secor.config.yaml with a reason if it serves no user data.";

/**
 * Auth middleware packages that protect the app when used, although their exports are not guard names in section 8.3
 * (`auth()` from express-oauth2-jwt-bearer, Hono `bearerAuth` / `jwt`, the Cloudflare OAuth provider...).
 */
const TS_AUTH_PACKAGES =
  /^(?:express-oauth2-jwt-bearer|express-openid-connect|express-basic-auth|@cloudflare\/workers-oauth-provider|hono\/(?:bearer-auth|jwt|basic-auth)|@fastify\/(?:bearer-auth|jwt|auth|basic-auth))$/;

/** Middleware or wrapper names that enforce auth around a mounted Python app. */
const PY_AUTH_MIDDLEWARE = /^(?:RequireAuth\w*|\w*(?:Auth|Bearer|Jwt|JWT|Token|ApiKey|APIKey)\w*Middleware)$/;

export const authRequiredRule = defineRule({
  id: "mcp/auth-required",
  title: "Remote MCP server with no auth",
  pack: "mcp",
  maturity: "experimental",
  source: SOURCES.mcpAuth,
  appliesTo: (ctx) => mcpHttpUnits(ctx, "remote").length > 0,
  check(ctx, emit) {
    const guards = guardMatcherFor(ctx);
    for (const unit of mcpHttpUnits(ctx, "remote")) {
      if (declaredPublicServer(ctx, unit)) continue;
      if (mcpServerAuth(ctx, unit)) continue;
      if (unit.framework === "mcp-ts" ? tsRouteGuarded(ctx, unit, guards) || authPackageUsed(ctx, unit) : pyAppGuarded(ctx, unit, guards)) continue;
      const site = reportedServer(ctx, unit);
      if (!site) continue;
      emit({
        severity: "critical",
        service: "mcp",
        file: site.file,
        line: line(site.node),
        anchor: anchorText(site.node),
        evidence: site.node.text,
        why: WHY,
        fix: { summary: unit.framework === "mcp-py" ? FIX_PY : FIX_TS },
      });
    }
  },
});

/** The construction to report: the first one in a file that serves HTTP, else the first one. */
function reportedServer(ctx: ProjectContext, unit: UnitInfo): Site | null {
  const sites = serverConstructions(ctx, unit);
  return sites.find((s) => SERVES_MCP_HTTP.test(s.pf.source)) ?? sites[0] ?? null;
}

/**
 * TS: a guard protects the MCP route. Routes are inventory http_route entries in the same root whose handler hands
 * the request to the transport (`transport.handleRequest(...)`); a route counts as protected when it is guarded
 * (section 8.3), has middleware that checks a credential header and refuses the request, or checks one itself.
 * Requests handed to the transport outside a known route are judged by the function that does it.
 */
function tsRouteGuarded(ctx: ProjectContext, unit: UnitInfo, guards: GuardMatcher): boolean {
  for (const e of ctx.inventory) {
    if (e.kind !== "http_route" || e.internal.unit.root !== unit.root) continue;
    if (!e.internal.handlers.some((h) => callsOneLevel(h.node, h.pf).some((c) => TRANSPORT_HANDOFF.test(calleePath(c))))) continue;
    if (e.auth.guarded) return true;
    if (e.internal.middleware.some((m) => credentialMiddleware(ctx, m))) return true;
    if (e.internal.handlers.some((h) => checksCredentials(h.node))) return true;
  }
  for (const file of ctx.codeFiles(unit, "js")) {
    const text = ctx.read(file) ?? "";
    if (!/handleRequest|handlePostMessage/.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const c of callsIn(pf.root)) {
      if (!TRANSPORT_HANDOFF.test(calleePath(c))) continue;
      const fn = enclosingFunction(c);
      if (!fn) continue;
      if (callsOneLevel(fn, pf).some((x) => guards.guardCall(x, "mcp-ts"))) return true;
      if (checksCredentials(fn)) return true;
    }
  }
  return false;
}

/** A known auth middleware package is imported and its export is used (called or passed as middleware). */
function authPackageUsed(ctx: ProjectContext, unit: UnitInfo): boolean {
  for (const file of ctx.codeFiles(unit, "js")) {
    const text = ctx.read(file) ?? "";
    if (!/oauth|jwt|auth/i.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    const locals = new Set(imports(pf).filter((b) => TS_AUTH_PACKAGES.test(b.source)).map((b) => b.local));
    if (locals.size === 0) continue;
    let used = false;
    walk(pf.root, (n) => {
      if (used || n.type === "import_statement") return false;
      if (n.type === "identifier" && locals.has(n.text) && !(n.parent?.type === "variable_declarator" && n.parent.childForFieldName("name")?.id === n.id)) used = true;
      return !used;
    });
    if (used) return true;
  }
  return false;
}

/** Inline or same-file middleware that checks a credential header and refuses the request. */
function credentialMiddleware(ctx: ProjectContext, m: MiddlewareRef): boolean {
  const u = unwrap(m.node);
  if (!u) return false;
  if (isFunction(u)) return checksCredentials(u);
  if (u.type === "identifier") {
    const pf = ctx.parse(m.file);
    const v = pf ? unwrap(resolveLocal(pf, u.text, u)) : null;
    return !!v && isFunction(v) && checksCredentials(v);
  }
  return false;
}

/**
 * Python: a guard on the mounted app. Auth middleware added to the app (`add_middleware(...)`, `Middleware(...)`),
 * an auth wrapper around the MCP app (`RequireAuthMiddleware(mcp.streamable_http_app(), ...)`), or an
 * `@app.middleware("http")` function that checks a credential header and refuses the request.
 */
function pyAppGuarded(ctx: ProjectContext, unit: UnitInfo, guards: GuardMatcher): boolean {
  const isAuthName = (name: string) => !/csrf/i.test(name) && (guards.isGuardName(name, "mcp-py") || PY_AUTH_MIDDLEWARE.test(name));
  for (const file of ctx.codeFiles(unit, "py")) {
    const text = ctx.read(file) ?? "";
    if (!/[Mm]iddleware|\.mount\(|Mount\(/.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const c of callsIn(pf.root)) {
      const name = calleeName(c);
      if (name === "add_middleware" || name === "Middleware") {
        const first = positionalArgs(c)[0];
        const mw = first ? (exprPath(first).split(".").pop() ?? "") : "";
        if (isAuthName(mw)) return true;
      } else if (isAuthName(name) && /\.(?:streamable_http_app|sse_app|http_app)\s*\(/.test(c.text)) return true;
    }
    for (const def of descendants(pf.root, "decorated_definition")) {
      const decorators = kids(def).filter((k) => k.type === "decorator");
      if (!decorators.some((d) => /^@\s*\w+\.middleware\s*\(/.test(d.text))) continue;
      const fn = def.childForFieldName("definition");
      if (!fn) continue;
      if (checksCredentials(fn) || isAuthName(fn.childForFieldName("name")?.text ?? "")) return true;
      let guarded = false;
      walk(fn, (n) => {
        if (guarded) return false;
        if (n.type === "call" && guards.guardCall(n, "mcp-py")) guarded = true;
        return !guarded;
      });
      if (guarded) return true;
    }
  }
  return false;
}

