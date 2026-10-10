// The Probe checks (spec 9A.5). Each is read-only (GET / OPTIONS only) and maps to the static rule it
// confirms. Nothing here writes to disk; response bodies are redacted by makeFinding before they reach a
// Finding and discarded when the run ends.

import type { EntryPoint, ServiceKind } from "../types.js";
import { accountHeaders, type TestAccounts } from "./accounts.js";
import { type ProbeClient, type ProbeMethod, rawRequest, type RawResponse } from "./http.js";
import { reResolvePin, type Resolver } from "./scope-guard.js";
import type { ProbeCheckId, ProbeFinding, VerifiedTarget } from "./types.js";

const CORS_PROBE_ORIGIN = "https://secor-probe.example";
const SESSION_COOKIE = /(?:^|[-_])(session|sess|sid|token|auth|jwt|refresh)(?:$|[-_])|^(session|sid|token|jwt|auth)$/i;
const ARTIFACT_PATHS = ["/.env", "/.git/HEAD", "/.git/config", "/config.json", "/.ds_store"];

function header(res: RawResponse, name: string): string | undefined {
  const v = res.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

function is2xx(status: number): boolean {
  return status >= 200 && status < 300;
}

/** A 2xx body that looks like data: a non-empty JSON object/array that is not purely an error shape. */
export function looksLikeData(body: string): boolean {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return false;
  }
  if (Array.isArray(json)) return json.length > 0;
  if (json && typeof json === "object") {
    const keys = Object.keys(json);
    if (keys.length === 0) return false;
    const errorOnly = keys.every((k) => /^(error|errors|message|detail|statusCode|code)$/i.test(k));
    return !errorOnly;
  }
  return false;
}

function dataShape(body: string): string {
  try {
    const json = JSON.parse(body);
    if (Array.isArray(json)) return `JSON array (${json.length} item${json.length === 1 ? "" : "s"})`;
    return `JSON object (${Object.keys(json as object).length} field${Object.keys(json as object).length === 1 ? "" : "s"})`;
  } catch {
    return "a body";
  }
}

/** Replace :param and :param* path segments with a concrete value so the route can be requested. */
export function concreteRequestPath(path: string | undefined): string {
  if (!path) return "/";
  const noQuery = path.split("?")[0]!;
  const out = noQuery
    .split("/")
    .map((seg) => (seg.startsWith(":") ? "1" : seg))
    .join("/");
  return out.startsWith("/") ? out : `/${out}`;
}

export interface Probed {
  findings: ProbeFinding[];
  responses: RawResponse[];
}

const mk = (f: ProbeFinding): ProbeFinding => f;

// --------------------------------------------------------------------------- unauthenticated checks

/** probe/open-endpoint: GET each non-public API entry point with no session. Confirms api/missing-auth. */
export async function checkOpenEndpoint(client: ProbeClient, inventory: EntryPoint[]): Promise<Probed> {
  const findings: ProbeFinding[] = [];
  const responses: RawResponse[] = [];
  const targets = inventory.filter((e) => e.service === "api" && e.kind === "http_route" && !e.declaredPublic && (e.method === "GET" || e.method === "*" || e.method === undefined));
  // Fire concurrently; the client's semaphore + rate gate enforce the <=4 concurrent / <=5 req/s caps.
  const probed = await Promise.all(
    targets.map(async (e) => {
      const path = concreteRequestPath(e.path);
      try {
        return { e, path, res: await client.request("GET", path) };
      } catch {
        return null; // connection error: nothing proven for this endpoint
      }
    }),
  );
  for (const item of probed) {
    if (!item) continue;
    const { e, path, res } = item;
    responses.push(res);
    if (is2xx(res.status) && looksLikeData(res.body)) {
      const proof = `GET ${path} with no session returned ${res.status} and ${dataShape(res.body)}`;
      findings.push(
        mk({
          check: "open-endpoint",
          ruleId: "probe/open-endpoint",
          severity: "critical",
          service: "api",
          file: e.file,
          line: e.line,
          anchor: `open-endpoint ${e.method ?? "GET"} ${path}`,
          evidence: `${proof}: ${res.body}`,
          why: "An unauthenticated request to this endpoint returned data, confirming it has no effective login check.",
          proof,
          entryPointId: e.id,
        }),
      );
    }
  }
  return { findings, responses };
}

/** probe/security-headers: confirm the web/security-headers checks on the live root response. */
export function checkSecurityHeaders(rootRes: RawResponse, path = "/"): ProbeFinding[] {
  const findings: ProbeFinding[] = [];
  const add = (name: string, label: string) =>
    findings.push(
      mk({
        check: "security-headers",
        ruleId: "probe/security-headers",
        severity: "low",
        service: "web",
        file: path,
        line: 1,
        anchor: `security-headers ${name}`,
        evidence: `the live response from ${path} is missing ${label}`,
        why: `The live response is missing the ${label} header.`,
        proof: `live response is missing ${label}`,
        matchKey: name,
      }),
    );
  const csp = header(rootRes, "content-security-policy");
  if (!csp) add("content-security-policy", "Content-Security-Policy");
  if (!header(rootRes, "strict-transport-security")) add("strict-transport-security", "Strict-Transport-Security");
  if (!header(rootRes, "x-content-type-options")) add("x-content-type-options", "X-Content-Type-Options");
  if (!header(rootRes, "x-frame-options") && !(csp && /frame-ancestors/i.test(csp))) add("frame-protection", "frame protection (X-Frame-Options or CSP frame-ancestors)");
  if (csp) {
    const directive = /script-src[^;]*/i.exec(csp)?.[0] ?? /default-src[^;]*/i.exec(csp)?.[0] ?? "";
    if (/'unsafe-inline'/i.test(directive) && /'unsafe-eval'/i.test(directive)) {
      findings.push(
        mk({
          check: "security-headers",
          ruleId: "probe/security-headers",
          severity: "low",
          advisory: true,
          service: "web",
          file: path,
          line: 1,
          anchor: `security-headers csp-unsafe`,
          evidence: `the live CSP allows both 'unsafe-inline' and 'unsafe-eval'`,
          why: "The live CSP allows both 'unsafe-inline' and 'unsafe-eval', which defeats much of its protection.",
          proof: "live CSP allows 'unsafe-inline' and 'unsafe-eval'",
          matchKey: "csp-unsafe",
        }),
      );
    }
  }
  return findings;
}

/** probe/tls-redirect: GET http://<host> and fire when it does not redirect to HTTPS (public targets only). */
export async function checkTlsRedirect(target: VerifiedTarget, resolver: Resolver): Promise<ProbeFinding[]> {
  const pin = await reResolvePin(target, resolver);
  let res: RawResponse;
  try {
    res = await rawRequest({ method: "GET", protocol: "http:", host: target.host, pinnedIp: pin.ip, family: pin.family, port: 80, path: "/" });
  } catch {
    return [];
  }
  const loc = res.location ?? "";
  const redirects = res.status >= 300 && res.status < 400 && /^https:\/\//i.test(loc);
  if (redirects) return [];
  return [
    mk({
      check: "tls-redirect",
      ruleId: "probe/tls-redirect",
      severity: "medium",
      service: "web",
      file: `http://${target.host}/`,
      line: 1,
      anchor: `tls-redirect ${target.host}`,
      evidence: `http://${target.host}/ returned ${res.status}${loc ? ` -> ${loc}` : ""} and did not redirect to HTTPS`,
      why: "The site is reachable over plain HTTP and does not redirect to HTTPS, so requests can be sent unencrypted.",
      proof: `http://${target.host}/ did not redirect to HTTPS (status ${res.status})`,
    }),
  ];
}

interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: boolean;
}

export function parseSetCookie(value: string): ParsedCookie {
  const [pair, ...attrs] = value.split(";");
  const name = (pair ?? "").split("=")[0]!.trim();
  const lower = attrs.map((a) => a.trim().toLowerCase());
  return {
    name,
    secure: lower.includes("secure"),
    httpOnly: lower.includes("httponly"),
    sameSite: lower.some((a) => a.startsWith("samesite")),
  };
}

/** probe/cookie-flags: inspect Set-Cookie on responses already received. Confirms web/cookie-flags. */
export function checkCookieFlags(responses: RawResponse[], path = "/"): ProbeFinding[] {
  const findings: ProbeFinding[] = [];
  const seen = new Set<string>();
  for (const res of responses) {
    for (const raw of res.setCookie) {
      const c = parseSetCookie(raw);
      if (!c.name || !SESSION_COOKIE.test(c.name) || seen.has(c.name)) continue;
      const missing = [!c.httpOnly && "HttpOnly", !c.secure && "Secure", !c.sameSite && "SameSite"].filter(Boolean) as string[];
      if (missing.length === 0) continue;
      seen.add(c.name);
      findings.push(
        mk({
          check: "cookie-flags",
          ruleId: "probe/cookie-flags",
          severity: "medium",
          service: "web",
          file: path,
          line: 1,
          anchor: `cookie-flags ${c.name}`,
          evidence: `the live Set-Cookie for "${c.name}" is missing ${missing.join(", ")}`,
          why: `The session cookie "${c.name}" is set without ${missing.join(", ")}.`,
          proof: `live cookie "${c.name}" missing ${missing.join(", ")}`,
          matchKey: c.name,
        }),
      );
    }
  }
  return findings;
}

/** probe/cors-reflection: a GET and a credentialed preflight with a foreign Origin. Confirms api/cors-credentials. */
export async function checkCorsReflection(client: ProbeClient): Promise<Probed> {
  const responses: RawResponse[] = [];
  const reflects = (res: RawResponse): boolean => {
    const acao = header(res, "access-control-allow-origin");
    const acac = header(res, "access-control-allow-credentials");
    return acao === CORS_PROBE_ORIGIN && (acac ?? "").toLowerCase() === "true";
  };
  let fired: RawResponse | null = null;
  try {
    const get = await client.request("GET", "/", { headers: { origin: CORS_PROBE_ORIGIN } });
    responses.push(get);
    if (reflects(get)) fired = get;
    const preflight = await client.request("OPTIONS", "/", { headers: { origin: CORS_PROBE_ORIGIN, "access-control-request-method": "GET", "access-control-request-headers": "authorization" } });
    responses.push(preflight);
    if (!fired && reflects(preflight)) fired = preflight;
  } catch {
    return { findings: [], responses };
  }
  if (!fired) return { findings: [], responses };
  return {
    responses,
    findings: [
      mk({
        check: "cors-reflection",
        ruleId: "probe/cors-reflection",
        severity: "high",
        service: "api",
        file: "/",
        line: 1,
        anchor: `cors-reflection`,
        evidence: `the live response reflects Origin ${CORS_PROBE_ORIGIN} with Access-Control-Allow-Credentials: true`,
        why: "The server reflects an arbitrary Origin together with credentials, letting any site make authenticated cross-origin requests.",
        proof: `reflected Origin ${CORS_PROBE_ORIGIN} with credentials`,
      }),
    ],
  };
}

function artifactMatch(path: string, res: RawResponse): string | null {
  if (!is2xx(res.status)) return null;
  const body = res.body;
  if (path === "/.env") return /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(body) ? "a dotenv file" : null;
  if (path === "/.git/HEAD") return /^(ref:\s*refs\/|[0-9a-f]{40})/m.test(body.trim()) ? "a git HEAD ref" : null;
  if (path === "/.git/config") return /\[core\]/i.test(body) ? "a git config" : null;
  if (path === "/config.json") {
    try {
      const j = JSON.parse(body);
      return j && typeof j === "object" ? "a JSON config" : null;
    } catch {
      return null;
    }
  }
  if (path === "/.ds_store") return /Bud1/.test(body) ? "a .DS_Store file" : null;
  return body.includes('"version":3') || body.includes('"mappings"') ? "a source map" : null;
}

/** Source-map URLs referenced by the served HTML (sourceMappingURL comments and .js script tags). */
export function sourceMapUrls(html: string): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(/sourceMappingURL=([^\s"'*]+)/g)) {
    const u = m[1]!;
    if (!/^https?:\/\//.test(u)) out.add(u.startsWith("/") ? u : `/${u}`);
  }
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+\.js)["']/gi)) {
    const src = m[1]!;
    if (!/^https?:\/\//.test(src)) out.add(`${src.startsWith("/") ? src : `/${src}`}.map`);
  }
  return [...out].slice(0, 10);
}

/** probe/exposed-artifact: GET a fixed short list plus HTML-referenced source maps; fire on matching content. */
export async function checkExposedArtifact(client: ProbeClient, rootHtml: string): Promise<Probed> {
  const responses: RawResponse[] = [];
  const findings: ProbeFinding[] = [];
  const paths = [...ARTIFACT_PATHS, ...sourceMapUrls(rootHtml)];
  for (const path of paths) {
    let res: RawResponse;
    try {
      res = await client.request("GET", path);
    } catch {
      continue;
    }
    responses.push(res);
    const kind = artifactMatch(ARTIFACT_PATHS.includes(path) ? path : "sourcemap", res);
    if (!kind) continue;
    const severity = path === "/.env" || path.startsWith("/.git") ? "critical" : "high";
    findings.push(
      mk({
        check: "exposed-artifact",
        ruleId: "probe/exposed-artifact",
        severity,
        service: "web",
        file: path,
        line: 1,
        anchor: `exposed-artifact ${path}`,
        evidence: `GET ${path} returned ${res.status} with ${kind}: ${res.body}`,
        why: `${path} is served to anyone and returned ${kind}, exposing project internals.`,
        proof: `GET ${path} returned ${res.status} with ${kind}`,
      }),
    );
  }
  return { findings, responses };
}

/** probe/anon-table-read: GET /rest/v1/<table>?select=*&limit=1 with the public anon key. Confirms web/database-rules. */
export async function checkAnonTableRead(supaClient: ProbeClient, tables: string[], anonKey: string): Promise<Probed> {
  const findings: ProbeFinding[] = [];
  const responses: RawResponse[] = [];
  for (const table of tables) {
    let res: RawResponse;
    try {
      res = await supaClient.request("GET", `/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, { headers: { apikey: anonKey, authorization: `Bearer ${anonKey}` } });
    } catch {
      continue;
    }
    responses.push(res);
    if (!is2xx(res.status)) continue;
    let rows = 0;
    try {
      const j = JSON.parse(res.body);
      if (Array.isArray(j)) rows = j.length;
      else continue;
    } catch {
      continue;
    }
    if (rows === 0) continue; // reachable but empty is not proof of readable data
    findings.push(
      mk({
        check: "anon-table-read",
        ruleId: "probe/anon-table-read",
        severity: "critical",
        service: "web",
        file: `supabase/migrations#${table}`,
        line: 1,
        anchor: `anon-table-read ${table}`,
        evidence: `table "${table}" returned ${rows} row(s) to the public anon key`,
        why: `The public anon key read rows from table "${table}", so its row-level security does not protect it.`,
        proof: `anon key read ${rows} row(s) from "${table}"`,
        matchKey: table,
      }),
    );
  }
  return { findings, responses };
}

// --------------------------------------------------------------------------- authenticated checks

function guardedByAdmin(e: EntryPoint): boolean {
  const guard = (e.auth.guard ?? "").toLowerCase();
  const path = (e.path ?? "").toLowerCase();
  return /admin|role|permission/.test(guard) || /(^|\/)admin(\/|$)/.test(path);
}

/** probe/idor: as A learn an ID shape, then as B request A's record URLs. Confirms api/missing-ownership. */
export async function checkIdor(client: ProbeClient, accounts: TestAccounts, inventory: EntryPoint[]): Promise<Probed> {
  const findings: ProbeFinding[] = [];
  const responses: RawResponse[] = [];
  const headersA = accountHeaders(accounts.a);
  const headersB = accountHeaders(accounts.b);
  const itemRoutes = inventory.filter((e) => e.service === "api" && e.kind === "http_route" && (e.method === "GET" || e.method === "*" || e.method === undefined) && /:[A-Za-z_]/.test(e.path ?? ""));
  for (const e of itemRoutes) {
    // Learn an ID from account A: GET the collection (the path with its last :param segment removed).
    const collectionPath = concreteRequestPath((e.path ?? "").replace(/\/:[A-Za-z_][\w]*\*?$/, ""));
    let ids: string[] = [];
    try {
      const listRes = await client.request("GET", collectionPath, { headers: headersA });
      responses.push(listRes);
      ids = extractIds(listRes.body);
    } catch {
      // fall through to notChecked below
    }
    if (ids.length === 0) continue;
    const itemPath = concreteRequestPath(e.path).replace(/\/1(\/|$)/, `/${ids[0]}$1`);
    try {
      const bRes = await client.request("GET", itemPath, { headers: headersB });
      responses.push(bRes);
      if (is2xx(bRes.status) && looksLikeData(bRes.body)) {
        const proof = `account B fetched ${itemPath} (an ID owned by account A) and received ${bRes.status} with data`;
        findings.push(
          mk({
            check: "idor",
            ruleId: "probe/idor",
            severity: "high",
            service: "api",
            file: e.file,
            line: e.line,
            anchor: `idor ${e.method ?? "GET"} ${e.path}`,
            evidence: proof,
            why: "A second account read a record created by the first, confirming the endpoint does not check record ownership.",
            proof,
            entryPointId: e.id,
          }),
        );
      }
    } catch {
      // connection error: nothing proven
    }
  }
  return { findings, responses };
}

function extractIds(body: string): string[] {
  try {
    const json = JSON.parse(body);
    const arr = Array.isArray(json) ? json : Array.isArray((json as { data?: unknown }).data) ? ((json as { data: unknown[] }).data) : [];
    const ids: string[] = [];
    for (const row of arr) {
      if (row && typeof row === "object") {
        const id = (row as Record<string, unknown>).id ?? (row as Record<string, unknown>)._id;
        if (typeof id === "string" || typeof id === "number") ids.push(String(id));
      }
    }
    return ids;
  } catch {
    return [];
  }
}

/** probe/privilege-field: as non-admin account A, GET admin-gated endpoints. Confirms web/client-only-checks. */
export async function checkPrivilegeField(client: ProbeClient, accounts: TestAccounts, inventory: EntryPoint[]): Promise<Probed> {
  const findings: ProbeFinding[] = [];
  const responses: RawResponse[] = [];
  const headersA = accountHeaders(accounts.a);
  const adminRoutes = inventory.filter((e) => e.service === "api" && e.kind === "http_route" && (e.method === "GET" || e.method === "*" || e.method === undefined) && guardedByAdmin(e));
  for (const e of adminRoutes) {
    const path = concreteRequestPath(e.path);
    try {
      const res = await client.request("GET", path, { headers: headersA });
      responses.push(res);
      if (is2xx(res.status) && looksLikeData(res.body)) {
        const proof = `non-admin account A fetched admin-gated ${path} and received ${res.status} with data`;
        findings.push(
          mk({
            check: "privilege-field",
            ruleId: "probe/privilege-field",
            severity: "high",
            service: "web",
            file: e.file,
            line: e.line,
            anchor: `privilege-field ${e.method ?? "GET"} ${path}`,
            evidence: proof,
            why: "A non-admin account received admin-gated data, confirming the role check is not enforced on the server.",
            proof,
            entryPointId: e.id,
          }),
        );
      }
    } catch {
      // connection error
    }
  }
  return { findings, responses };
}

export const CHECK_SERVICE: Record<ProbeCheckId, ServiceKind> = {
  "open-endpoint": "api",
  "security-headers": "web",
  "tls-redirect": "web",
  "cookie-flags": "web",
  "cors-reflection": "api",
  "exposed-artifact": "web",
  "anon-table-read": "web",
  idor: "api",
  "privilege-field": "web",
};

export type { ProbeMethod };
