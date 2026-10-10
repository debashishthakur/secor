// Dashboard HTTP server (spec section 12.1): binds to 127.0.0.1 on a random free port, read-only, two routes.
//
// Every request must carry the right Host (127.0.0.1:<port> or localhost:<port>; DNS-rebinding defence) and, when it
// has an Origin header, a local origin for the same port. Requests from other sites (other local ports included) may
// only be top-level navigations (Fetch Metadata). Then the request must present the token, either as ?t=<token>
// (which sets the secor_t cookie) or as that cookie; both are compared in constant time. Only GET is served, and only
// "/" and "/api/summary". The server closes itself after `idleMs` without an accepted request.

import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type OutgoingHttpHeaders, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { redact, redactDeep } from "../engine/redact.js";
import type { DashboardSummary } from "../types.js";
import { renderPage } from "./page.js";
import { buildDashboardSummary } from "./summary.js";

export const DEFAULT_IDLE_MS = 30 * 60_000;
export const COOKIE_NAME = "secor_t";
const TOKEN_RE = /^[0-9a-f]{64}$/;

export interface DashboardServerOptions {
  /** Project root whose results the dashboard shows. */
  root: string;
  /** Close after this long without an accepted request (default 30 minutes). */
  idleMs?: number;
  /** Fixed token (tests); default 32 random bytes, hex. */
  token?: string;
  /** Summary source (tests); default buildDashboardSummary(root). */
  summary?: () => DashboardSummary;
}

export interface DashboardServer {
  root: string;
  port: number;
  token: string;
  /** http://127.0.0.1:<port>/?t=<token> */
  url: string;
  startedAt: string;
  isClosed(): boolean;
  close(): Promise<void>;
  /** Resolves once the server has closed (idle timeout or close()). */
  closed: Promise<void>;
}

export function newToken(): string {
  return randomBytes(32).toString("hex");
}

export function dashboardUrl(port: number, token: string): string {
  return `http://127.0.0.1:${port}/?t=${token}`;
}

/** Constant-time comparison of a presented token with the server's token. */
export function tokenMatches(presented: string | null | undefined, token: string): boolean {
  if (typeof presented !== "string") return false;
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(token, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Every value of one cookie in a Cookie header ("a=1; secor_t=..."). Cookies are not isolated by port, so another
 * local app can set a decoy secor_t for 127.0.0.1; checking every value keeps that from locking the user out.
 */
export function cookieValues(header: string | undefined, name: string): string[] {
  const out: string[] = [];
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) out.push(part.slice(eq + 1).trim());
  }
  return out;
}

/**
 * Fetch Metadata resource isolation: requests from other sites (which include other ports on 127.0.0.1) may only be
 * top-level GET navigations; they cannot embed, script-load or fetch dashboard routes. Browsers that send no
 * Sec-Fetch-Site header (and non-browser clients) rely on the Host, Origin and token checks alone.
 */
export function allowedByFetchMetadata(method: string | undefined, site: string | undefined, mode: string | undefined, dest: string | undefined): boolean {
  if (!site || site === "same-origin" || site === "none") return true;
  return mode === "navigate" && method === "GET" && dest !== "object" && dest !== "embed";
}

function one(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

function securityHeaders(nonce?: string): OutgoingHttpHeaders {
  const csp = nonce
    ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
    : "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
  return {
    "Content-Security-Policy": csp,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
  };
}

function send(res: ServerResponse, status: number, body: string, contentType: string, extra: OutgoingHttpHeaders = {}, nonce?: string): void {
  const data = Buffer.from(body, "utf8");
  res.writeHead(status, { ...securityHeaders(nonce), "Content-Type": contentType, "Content-Length": data.length, ...extra });
  res.end(res.req.method === "HEAD" ? undefined : data);
}

function text(res: ServerResponse, status: number, body: string, extra: OutgoingHttpHeaders = {}): void {
  send(res, status, `${body}\n`, "text/plain; charset=utf-8", extra);
}

export async function startDashboardServer(opts: DashboardServerOptions): Promise<DashboardServer> {
  const root = resolve(opts.root);
  const token = opts.token ?? newToken();
  if (!TOKEN_RE.test(token)) throw new Error("dashboard token must be 64 hex characters");
  const idleMs = opts.idleMs ?? DEFAULT_IDLE_MS;
  const summary = opts.summary ?? (() => buildDashboardSummary(root));
  let port = 0;
  let closed = false;
  let idleTimer: NodeJS.Timeout | undefined;
  let resolveClosed!: () => void;
  const closedPromise = new Promise<void>((r) => {
    resolveClosed = r;
  });

  // requireHostHeader: false lets the Host check below answer a missing Host with 403 like any other wrong Host.
  const server: Server = createServer({ requireHostHeader: false }, (req, res) => {
    try {
      handle(req, res);
    } catch {
      if (!res.headersSent) text(res, 500, "Internal error.");
      else res.destroy();
    }
  });

  const close = (): Promise<void> => {
    if (!closed) {
      closed = true;
      if (idleTimer) clearTimeout(idleTimer);
      server.close(() => resolveClosed());
      server.closeAllConnections();
    }
    return closedPromise;
  };

  const touch = (): void => {
    if (closed) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => void close(), idleMs);
    idleTimer.unref();
  };

  function handle(req: IncomingMessage, res: ServerResponse): void {
    // 1. Host: only the loopback names for this port (blocks DNS rebinding).
    const host = (req.headers.host ?? "").toLowerCase();
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return text(res, 403, "Forbidden: unexpected Host header.");
    // 2. Origin, when present: only this dashboard's own origin.
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== `http://127.0.0.1:${port}` && origin !== `http://localhost:${port}`) return text(res, 403, "Forbidden: unexpected Origin header.");
    // 3. Fetch metadata: other sites may navigate here, nothing else.
    if (!allowedByFetchMetadata(req.method, one(req.headers["sec-fetch-site"]), one(req.headers["sec-fetch-mode"]), one(req.headers["sec-fetch-dest"]))) {
      return text(res, 403, "Forbidden: cross-site request.");
    }
    let url: URL;
    try {
      url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
    } catch {
      return text(res, 400, "Bad request.");
    }
    // 4. Token: ?t=<token> (sets the cookie) or the secor_t cookie.
    const viaQuery = tokenMatches(url.searchParams.get("t"), token);
    const viaCookie = cookieValues(req.headers.cookie, COOKIE_NAME).some((v) => tokenMatches(v, token));
    if (!viaQuery && !viaCookie) return text(res, 401, "Unauthorized: open the dashboard with the link that secor dashboard prints.");
    touch();
    const cookie: OutgoingHttpHeaders = viaQuery ? { "Set-Cookie": `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/` } : {};
    // 5. Read-only: GET only.
    if (req.method !== "GET") return text(res, 405, "Method not allowed: the dashboard is read-only.", { Allow: "GET", ...cookie });
    // 6. Routes.
    if (url.pathname === "/") {
      const nonce = randomBytes(16).toString("base64");
      return send(res, 200, renderPage(nonce), "text/html; charset=utf-8", cookie, nonce);
    }
    if (url.pathname === "/api/summary") {
      let body: string;
      try {
        body = JSON.stringify(redactDeep(summary()));
      } catch (e) {
        return text(res, 500, redact(`Could not build the summary: ${e instanceof Error ? e.message : String(e)}`), cookie);
      }
      return send(res, 200, body, "application/json; charset=utf-8", cookie);
    }
    return text(res, 404, "Not found.", cookie);
  }

  server.on("clientError", (_err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    else socket.destroy();
  });

  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", fail);
      ok();
    });
  });
  port = (server.address() as AddressInfo).port;
  touch();

  return {
    root,
    port,
    token,
    url: dashboardUrl(port, token),
    startedAt: new Date().toISOString(),
    isClosed: () => closed,
    close,
    closed: closedPromise,
  };
}
