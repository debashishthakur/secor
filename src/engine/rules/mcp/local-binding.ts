// mcp/local-binding (spec section 8.5): a local HTTP MCP server that (a) listens on all interfaces and/or
// (b) does not validate the Origin or Host header (DNS rebinding). One finding per unit listing the failing parts.

import { anchorText, args, callee, calleeName, calleePath, callsIn, collapse, exprPath, isCall, isFunction, kwarg, line, positionalArgs, prop, resolveLocal, unwrap, walk } from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { type LineEdit, unifiedDiff } from "../../patch.js";
import { SOURCES, defineRule } from "../types.js";
import { SERVES_MCP_HTTP, type Site, classifyHost, insertAfterNode, jsQuote, mcpHttpUnits, pyFlavor, replaceNode, serverConstructions, validatesOriginOrHost } from "./common.js";

const WHY =
  "A web page the developer visits can reach a local MCP server: binding to all interfaces exposes it to the network, and without Origin or Host checks a DNS-rebinding page can call its tools from the browser.";
const FIX = "Bind to 127.0.0.1 and validate the Origin header.";
const LOOPBACK = "127.0.0.1";

/** A place where the server listens on all interfaces. */
export interface AllInterfacesSite {
  file: string;
  pf: ParsedFile;
  /** Node shown as evidence and used as the anchor (the listen / run call or the host assignment). */
  node: SyntaxNode;
  /** The single edit that binds to 127.0.0.1, when the change is unambiguous. */
  edit: LineEdit | null;
}

export const localBindingRule = defineRule({
  id: "mcp/local-binding",
  title: "Local HTTP server reachable beyond this machine",
  pack: "mcp",
  maturity: "experimental",
  source: SOURCES.mcpTransports,
  appliesTo: (ctx) => mcpHttpUnits(ctx, "local").length > 0,
  check(ctx, emit) {
    for (const unit of mcpHttpUnits(ctx, "local")) {
      const py = unit.framework === "mcp-py";
      // Report a listener in a file that serves MCP first (an auxiliary server, e.g. an OAuth demo, comes later).
      const all = (py ? pyAllInterfaces(ctx, unit) : tsAllInterfaces(ctx, unit)).sort((x, y) => Number(!SERVES_MCP_HTTP.test(x.pf.source)) - Number(!SERVES_MCP_HTTP.test(y.pf.source)));
      const validated = py ? pyOriginValidated(ctx, unit) : tsOriginValidated(ctx, unit);
      if (all.length === 0 && validated) continue;
      const parts: string[] = [];
      if (all.length) parts.push("(a) listens on all interfaces");
      if (!validated) parts.push("(b) no Origin or Host validation");
      const site: Site | null = all[0] ?? transportSite(ctx, unit);
      if (!site) continue;
      const first = all[0];
      const patch = all.length === 1 && first?.edit ? patchFor(ctx, first.file, [first.edit]) : null;
      emit({
        severity: "high",
        service: "mcp",
        file: site.file,
        line: line(site.node),
        anchor: anchorText(site.node),
        evidence: `${parts.join("; ")}: ${collapse(site.node.text)}`,
        why: WHY,
        fix: { summary: FIX, ...(patch ? { patch } : {}) },
      });
    }
  },
});

function patchFor(ctx: ProjectContext, file: string, edits: LineEdit[]): string | null {
  const original = ctx.read(file);
  if (original === null) return null;
  try {
    const diff = unifiedDiff(file, original, edits);
    return diff || null;
  } catch {
    return null;
  }
}

/** Where to report when only (b) fails: the HTTP transport construction, else the server construction. */
function transportSite(ctx: ProjectContext, unit: UnitInfo): Site | null {
  for (const file of ctx.codeFiles(unit, unit.framework === "mcp-py" ? "py" : "js")) {
    const text = ctx.read(file) ?? "";
    if (!/StreamableHTTPServerTransport|SSEServerTransport|StreamableHTTPSessionManager|SseServerTransport/.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const c of callsIn(pf.root)) {
      if (/^(?:WebStandard)?StreamableHTTPServerTransport$|^SSEServerTransport$|^StreamableHTTPSessionManager$|^SseServerTransport$/.test(calleeName(c))) return { file, pf, node: c };
    }
  }
  return serverConstructions(ctx, unit)[0] ?? null;
}

// ---------------------------------------------------------------- (a) TypeScript

/** `.listen(port)` with no host, or a host of "0.0.0.0" / "::" (also through a constant or an env default). */
export function tsAllInterfaces(ctx: ProjectContext, unit: UnitInfo): AllInterfacesSite[] {
  const out: AllInterfacesSite[] = [];
  for (const file of ctx.codeFiles(unit, "js")) {
    const text = ctx.read(file) ?? "";
    if (!/\.listen\s*\(/.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const call of callsIn(pf.root)) {
      const fn = callee(call);
      if (fn?.type !== "member_expression" || fn.childForFieldName("property")?.text !== "listen") continue;
      const a = args(call);
      const first = unwrap(a[0] ?? null);
      if (!first) continue;
      if (first.type === "object") {
        const host = prop(first, "host");
        if (!host && prop(first, "port")) out.push({ file, pf, node: call, edit: null });
        else if (host) {
          const v = classifyHost(pf, host);
          if (v.kind === "all") out.push({ file, pf, node: call, edit: literalEdit(pf, v.literal) });
        }
        continue;
      }
      if (!isPortLike(first)) continue;
      const second = unwrap(a[1] ?? null);
      const secondIsCallback = !!second && (isFunction(second) || (second.type === "identifier" && isFunction(unwrap(resolveLocal(pf, second.text, second)))));
      if (!second || secondIsCallback) {
        out.push({ file, pf, node: call, edit: insertHostEdit(pf, first) });
        continue;
      }
      const v = classifyHost(pf, second);
      if (v.kind === "all") out.push({ file, pf, node: call, edit: literalEdit(pf, v.literal) });
    }
  }
  return out;
}

/** A port argument: a number, or an expression that names a port (`PORT`, `process.env.PORT ?? 3000`). */
function isPortLike(n: SyntaxNode): boolean {
  if (n.type === "number") return true;
  if (n.type === "string" || n.type === "template_string") return false;
  return /port/i.test(n.text) || /^\d+$/.test(n.text);
}

/** `.listen(port, cb)` → `.listen(port, "127.0.0.1", cb)`: insert the host right after the port argument. */
function insertHostEdit(pf: ParsedFile, port: SyntaxNode): LineEdit | null {
  if (port.startPosition.row !== port.endPosition.row) return null;
  const q = jsQuote(pf);
  return insertAfterNode(pf.source, port, `, ${q}${LOOPBACK}${q}`);
}

/** Replace the "0.0.0.0" / "::" literal with "127.0.0.1", keeping its quotes (and any string prefix). */
function literalEdit(pf: ParsedFile, literal: SyntaxNode | null): LineEdit | null {
  if (!literal) return null;
  const replaced = literal.text.replace(/0\.0\.0\.0|\[::\]|::/, LOOPBACK);
  return replaced === literal.text ? null : replaceNode(pf.source, literal, replaced);
}

// ---------------------------------------------------------------- (a) Python

const PY_HOST_CALLS = /^(?:FastMCP|MCPServer|run|Config|run_http_async|run_streamable_http_async|run_sse_async|serve)$/;

/**
 * Host "0.0.0.0" / "::" given to FastMCP / MCPServer, `uvicorn.run` / `uvicorn.Config`, `<server>.run(...)`
 * (fastmcp), or assigned to `<server>.settings.host`. A missing host keeps the SDK / uvicorn default 127.0.0.1.
 */
export function pyAllInterfaces(ctx: ProjectContext, unit: UnitInfo): AllInterfacesSite[] {
  const out: AllInterfacesSite[] = [];
  for (const file of ctx.codeFiles(unit, "py")) {
    const text = ctx.read(file) ?? "";
    if (!/\bhost\b/.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    walk(pf.root, (n) => {
      if (n.type === "call" && PY_HOST_CALLS.test(calleeName(n))) {
        const host = kwarg(n, "host");
        if (host) {
          const v = classifyHost(pf, host);
          if (v.kind === "all") out.push({ file, pf, node: n, edit: literalEdit(pf, v.literal) });
        }
      } else if (n.type === "assignment" && /(?:^|\.)settings\.host$/.test(exprPath(n.childForFieldName("left")))) {
        const v = classifyHost(pf, n.childForFieldName("right"));
        if (v.kind === "all") out.push({ file, pf, node: n, edit: literalEdit(pf, v.literal) });
      }
      return true;
    });
  }
  return out;
}

// ---------------------------------------------------------------- (b) TypeScript

/**
 * TS SDK Host/Origin validation: transport options `enableDnsRebindingProtection: true` with `allowedHosts` and/or
 * `allowedOrigins`; `createMcpExpressApp()` (loopback host by default, or `allowedHosts`); the
 * `hostHeaderValidation(...)` / `localhostHostValidation()` middleware; or a function that checks the header itself.
 */
export function tsOriginValidated(ctx: ProjectContext, unit: UnitInfo): boolean {
  for (const file of ctx.codeFiles(unit, "js")) {
    const text = ctx.read(file) ?? "";
    const pf = ctx.parse(file);
    if (!pf) continue;
    if (/enableDnsRebindingProtection|createMcpExpressApp|hostHeaderValidation|localhostHostValidation/.test(text)) {
      for (const c of callsIn(pf.root)) {
        const name = calleeName(c);
        if (/^(?:WebStandard)?StreamableHTTPServerTransport$/.test(name) && dnsProtection(pf, args(c)[0] ?? null)) return true;
        if (name === "SSEServerTransport" && dnsProtection(pf, args(c)[2] ?? null)) return true;
        if (name === "createMcpExpressApp" && expressAppValidates(pf, args(c)[0] ?? null)) return true;
        if (name === "hostHeaderValidation" || name === "localhostHostValidation") return true;
      }
    }
    if (/origin|host/i.test(text) && customValidation(pf)) return true;
  }
  return false;
}

function objectOf(pf: ParsedFile, n: SyntaxNode | null): SyntaxNode | null {
  const u = unwrap(n);
  if (!u) return null;
  if (u.type === "object") return u;
  if (u.type === "identifier") {
    const v = unwrap(resolveLocal(pf, u.text, u));
    if (v && v.type === "object") return v;
  }
  return null;
}

function dnsProtection(pf: ParsedFile, options: SyntaxNode | null): boolean {
  const o = objectOf(pf, options);
  if (!o) return false;
  const enabled = unwrap(prop(o, "enableDnsRebindingProtection"));
  return enabled?.type === "true" && (!!prop(o, "allowedHosts") || !!prop(o, "allowedOrigins"));
}

/** createMcpExpressApp validates Host unless it is told a non-loopback host without allowedHosts. */
function expressAppValidates(pf: ParsedFile, options: SyntaxNode | null): boolean {
  if (!options) return true;
  const o = objectOf(pf, options);
  if (!o) return true;
  if (prop(o, "allowedHosts")) return true;
  const host = prop(o, "host");
  if (!host) return true;
  const v = classifyHost(pf, host);
  return v.kind === "local" || v.kind === "unknown";
}

function customValidation(pf: ParsedFile): boolean {
  let found = false;
  walk(pf.root, (n) => {
    if (found) return false;
    if (isFunction(n) && validatesOriginOrHost(n)) {
      found = true;
      return false;
    }
    return true;
  });
  return found;
}

// ---------------------------------------------------------------- (b) Python

const LOCAL_HOST_DEFAULT = new Set(["mcp1", "mcp2"]);

/**
 * Python Host/Origin validation: `transport_security=TransportSecuritySettings(...)` not disabled; the official SDK's
 * FastMCP / MCPServer constructed with a loopback (or default) host and no transport_security, which enables DNS
 * rebinding protection automatically (mcp >= 1.23, verified in 1.30); `security_settings=` on a session manager or
 * SSE transport; Starlette `TrustedHostMiddleware`; or a function that checks the header itself.
 */
export function pyOriginValidated(ctx: ProjectContext, unit: UnitInfo): boolean {
  for (const file of ctx.codeFiles(unit, "py")) {
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const c of callsIn(pf.root)) {
      const name = calleeName(c);
      if (name === "FastMCP" || name === "MCPServer") {
        const ts = kwarg(c, "transport_security");
        if (ts && ts.type !== "none") {
          if (securitySettingsEnabled(pf, ts)) return true;
          continue;
        }
        if (!LOCAL_HOST_DEFAULT.has(pyFlavor(pf, c))) continue;
        const host = kwarg(c, "host");
        if (!host || classifyHost(pf, host).kind === "local") return true;
      } else if (/^(?:StreamableHTTPSessionManager|SseServerTransport|StreamableHTTPServerTransport)$/.test(name)) {
        const s = kwarg(c, "security_settings");
        if (s && s.type !== "none" && securitySettingsEnabled(pf, s)) return true;
      } else if (name === "add_middleware" || name === "Middleware") {
        const first = positionalArgs(c)[0];
        if (first && /(?:^|\.)TrustedHostMiddleware$/.test(exprPath(first))) return true;
      } else if (name === "TrustedHostMiddleware") return true;
    }
    if (/origin|host/i.test(pf.source) && customValidation(pf)) return true;
  }
  return false;
}

/** TransportSecuritySettings(...) unless `enable_dns_rebinding_protection=False`; unresolvable values count as enabled. */
function securitySettingsEnabled(pf: ParsedFile, n: SyntaxNode): boolean {
  let u = unwrap(n);
  if (u?.type === "identifier") {
    const v = unwrap(resolveLocal(pf, u.text, u));
    if (v && v.id !== u.id) u = v;
  }
  if (!u || !isCall(u)) return true;
  if (!/TransportSecuritySettings$/.test(calleePath(u))) return true;
  const flag = kwarg(u, "enable_dns_rebinding_protection");
  return !flag || flag.type !== "false";
}
