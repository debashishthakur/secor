// Dashboard server (spec 12.1 request checks, M4 acceptance): Host and Origin checks, token and cookie, routes,
// read-only methods, security headers, page content rules (12.2), redaction of /api/summary, idle shutdown.

import { request } from "node:http";
import { afterAll, describe, expect, it } from "vitest";
import { type DashboardServer, allowedByFetchMetadata, cookieValues, startDashboardServer, tokenMatches } from "../../src/dashboard/server.js";
import type { DashboardSummary } from "../../src/types.js";
import { PLANTED, PLANTED_EMAIL, fake, leaked, tempProject } from "../mcp/synthetic.js";

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function get(port: number, path: string, opts: { method?: string; headers?: Record<string, string>; host?: string | null; connectHost?: string } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (opts.host !== null) headers.Host = opts.host ?? `127.0.0.1:${port}`;
    const req = request({ host: opts.connectHost ?? "127.0.0.1", port, path, method: opts.method ?? "GET", headers, setHost: false }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c: string) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function summaryWith(over: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    project: "demo",
    lastCheck: "2026-10-10T12:00:00.000Z",
    rulesVersion: "1.0.0",
    scoringVersion: 1,
    overall: { score: 79, band: "needs-work", delta: 4 },
    ship: { score: 79, api: 79, mcp: null, web: null },
    connect: { score: null, serverCount: 0, hooks: "off" },
    coverage: { percent: 90, incomplete: false },
    findings: { critical: 0, high: 1, medium: 0, low: 0, ignored: 0, advisory: 0 },
    fixNext: [{ severity: "high", title: "Route without an auth check", file: "src/app.ts", line: 3 }],
    servers: [],
    history: [],
    notChecked: ["Running deployment (SECOR v1 reads files only)"],
    ...over,
  };
}

const servers: DashboardServer[] = [];
async function start(opts: { idleMs?: number; summary?: () => DashboardSummary } = {}): Promise<DashboardServer> {
  const s = await startDashboardServer({ root: tempProject(), summary: opts.summary ?? (() => summaryWith()), ...(opts.idleMs ? { idleMs: opts.idleMs } : {}) });
  servers.push(s);
  return s;
}
afterAll(async () => {
  await Promise.all(servers.map((s) => s.close()));
});

describe("request checks (spec 12.1)", async () => {
  const s = await start();
  const cookie = { Cookie: `secor_t=${s.token}` };

  it("URL is http://127.0.0.1:<port>/?t=<64 hex>", () => {
    expect(s.url).toBe(`http://127.0.0.1:${s.port}/?t=${s.token}`);
    expect(s.token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("listens on 127.0.0.1 only (not on ::1)", async () => {
    await expect(get(s.port, `/?t=${s.token}`, { connectHost: "::1", host: `localhost:${s.port}` })).rejects.toThrow();
  });

  it("rejects a Host other than 127.0.0.1:<port> or localhost:<port> with 403", async () => {
    for (const host of ["evil.example.com", `evil.example.com:${s.port}`, `127.0.0.1:${s.port + 1}`, "127.0.0.1", `0.0.0.0:${s.port}`, `[::1]:${s.port}`]) {
      const r = await get(s.port, `/?t=${s.token}`, { host });
      expect(r.status, host).toBe(403);
    }
    expect((await get(s.port, `/?t=${s.token}`, { host: null })).status).toBe(403);
  });

  it("accepts Host localhost:<port>", async () => {
    expect((await get(s.port, "/", { host: `localhost:${s.port}`, headers: cookie })).status).toBe(200);
  });

  it("rejects an Origin other than this dashboard's with 403, even with a valid token", async () => {
    for (const origin of ["http://evil.example", "null", `http://127.0.0.1:${s.port + 1}`, `https://127.0.0.1:${s.port}`, "http://localhost"]) {
      const r = await get(s.port, "/api/summary", { headers: { ...cookie, Origin: origin } });
      expect(r.status, origin).toBe(403);
    }
    expect((await get(s.port, "/api/summary", { headers: { ...cookie, Origin: `http://127.0.0.1:${s.port}` } })).status).toBe(200);
    expect((await get(s.port, "/api/summary", { headers: { ...cookie, Origin: `http://localhost:${s.port}` } })).status).toBe(200);
  });

  it("rejects requests without the token, or with a wrong one, with 401", async () => {
    expect((await get(s.port, "/")).status).toBe(401);
    expect((await get(s.port, "/api/summary")).status).toBe(401);
    expect((await get(s.port, `/?t=${"0".repeat(64)}`)).status).toBe(401);
    expect((await get(s.port, "/?t=short")).status).toBe(401);
    expect((await get(s.port, "/", { headers: { Cookie: `secor_t=${"a".repeat(64)}` } })).status).toBe(401);
    expect((await get(s.port, "/", { headers: { Cookie: `other=${s.token}` } })).status).toBe(401);
  });

  it("?t=<token> answers 200 and sets the secor_t cookie with HttpOnly, SameSite=Strict, Path=/", async () => {
    const r = await get(s.port, `/?t=${s.token}`);
    expect(r.status).toBe(200);
    const setCookie = r.headers["set-cookie"];
    expect(setCookie).toEqual([`secor_t=${s.token}; HttpOnly; SameSite=Strict; Path=/`]);
  });

  it("later requests are accepted with the cookie alone", async () => {
    const page = await get(s.port, "/", { headers: { Cookie: `theme=dark; secor_t=${s.token}` } });
    expect(page.status).toBe(200);
    expect(page.headers["set-cookie"]).toBeUndefined();
    const api = await get(s.port, "/api/summary", { headers: cookie });
    expect(api.status).toBe(200);
    expect(api.headers["content-type"]).toBe("application/json; charset=utf-8");
    expect(JSON.parse(api.body)).toEqual(summaryWith());
  });

  it("accepts the right secor_t even when another local app planted a decoy cookie of the same name", async () => {
    const r = await get(s.port, "/api/summary", { headers: { Cookie: `secor_t=${"0".repeat(64)}; secor_t=${s.token}` } });
    expect(r.status).toBe(200);
  });

  it("other sites (other local ports included) may only navigate here, never embed or fetch (Fetch Metadata)", async () => {
    const meta = (site: string, mode: string, dest: string) => ({ ...cookie, "Sec-Fetch-Site": site, "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest });
    for (const [site, mode, dest] of [
      ["same-site", "no-cors", "script"],
      ["same-site", "cors", "empty"],
      ["cross-site", "no-cors", "image"],
      ["cross-site", "navigate", "object"],
      ["same-site", "navigate", "embed"],
    ]) {
      expect((await get(s.port, "/api/summary", { headers: meta(site!, mode!, dest!) })).status, `${site} ${mode} ${dest}`).toBe(403);
    }
    expect((await get(s.port, "/", { headers: meta("same-origin", "cors", "empty") })).status).toBe(200);
    expect((await get(s.port, "/", { headers: meta("none", "navigate", "document") })).status).toBe(200);
    expect((await get(s.port, `/?t=${s.token}`, { headers: { "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document" } })).status).toBe(200);
  });

  it("everything else is 404", async () => {
    for (const path of ["/index.html", "/api", "/api/summary/x", "/favicon.ico", "/api/../etc/passwd", "/.secor/latest.json"]) {
      expect((await get(s.port, path, { headers: cookie })).status, path).toBe(404);
    }
  });

  it("is read-only: other methods get 405 (401 without the token)", async () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      for (const path of ["/", "/api/summary"]) {
        const r = await get(s.port, path, { method, headers: cookie });
        expect(r.status, `${method} ${path}`).toBe(405);
        expect(r.headers.allow).toBe("GET");
      }
    }
    expect((await get(s.port, "/api/summary", { method: "POST" })).status).toBe(401);
  });

  it("sends the security headers on every response", async () => {
    for (const r of [await get(s.port, "/", { headers: cookie }), await get(s.port, "/api/summary", { headers: cookie }), await get(s.port, "/nope", { headers: cookie }), await get(s.port, "/")]) {
      expect(r.headers["x-content-type-options"]).toBe("nosniff");
      expect(r.headers["x-frame-options"]).toBe("DENY");
      expect(r.headers["referrer-policy"]).toBe("no-referrer");
      expect(r.headers["cache-control"]).toBe("no-store");
      expect(String(r.headers["content-security-policy"])).toMatch(/^default-src 'none'/);
      expect(String(r.headers["content-security-policy"])).toContain("frame-ancestors 'none'");
    }
  });
});

describe("the page (spec 12.2)", async () => {
  const s = await start();
  const cookie = { Cookie: `secor_t=${s.token}` };
  const page = await get(s.port, "/", { headers: cookie });
  const html = page.body;

  it("is one HTML document whose inline style and script carry the CSP nonce", () => {
    expect(page.headers["content-type"]).toBe("text/html; charset=utf-8");
    const csp = String(page.headers["content-security-policy"]);
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain(`style-src 'nonce-${nonce}'`);
    expect(csp).toContain("connect-src 'self'");
    expect(csp).not.toContain("unsafe-eval");
    expect(html).toContain(`<script nonce="${nonce}">`);
    expect(html).toContain(`<style nonce="${nonce}">`);
    expect(html.match(/<script/g)).toHaveLength(1);
    expect(html.match(/<style/g)).toHaveLength(1);
  });

  it("uses a fresh nonce per response", async () => {
    const again = await get(s.port, "/", { headers: cookie });
    expect(again.headers["content-security-policy"]).not.toBe(page.headers["content-security-policy"]);
  });

  it("makes no external requests of any kind", () => {
    expect(html).not.toMatch(/https?:\/\//i);
    expect(html).not.toMatch(/\bsrc\s*=|\bhref\s*=|@import|url\(|<link|<img|<iframe|<object|<embed/i);
    expect(html).not.toMatch(/["'(]\/\/[a-z0-9]/i);
    // The only request the page makes is to its own summary route.
    expect(html.match(/fetch\(/g)).toHaveLength(1);
    expect(html).toContain('fetch("/api/summary"');
  });

  it("never contains the word secure, and never writes markup from data", () => {
    expect(html).not.toMatch(/secure/i);
    expect(html).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  });

  it("shows the panels in the fixed order with their labels, empty states and the score notice", () => {
    const order = ["OVERALL", "Ship", "Connect", "Coverage", "OPEN FINDINGS", "FIX NEXT", "CONNECTED SERVERS", "HISTORY", "NOT CHECKED"];
    let at = -1;
    for (const label of order) {
      const i = html.indexOf(`>${label}<`, at + 1);
      expect(i, label).toBeGreaterThan(at);
      at = i;
    }
    expect(html).toContain("This score counts known issues in the checks SECOR ran. It does not measure how hard your system is to attack.");
    for (const t of ["Not run yet.", '"secor ship"', "Not set up.", '"secor connect add <server>"', "No counted findings.", "Fewer than 2 checks so far."]) expect(html).toContain(t);
    for (const t of ["server", "vetted", "scope", "sandbox", "changed", "sent 7d", "blocked 7d", "score"]) expect(html).toContain(`<th scope="col"${t === "sent 7d" || t === "blocked 7d" || t === "score" ? ' class="num"' : ""}>${t}</th>`);
    expect(html).toContain("▁▂▃▄▅▆▇█");
    for (const t of ["Fix before deploy", "Needs work", "No critical or high issues known", "since last check", "each with a reason", "(not scored)", "% of applicable checks", "API ", "MCP server ", "Website "]) expect(html).toContain(t);
  });

  it("is one column of at most 760 px, system UI font, tabular numbers, light and dark themes, phone width", () => {
    expect(html).toContain("max-width: 760px");
    expect(html).toContain("font: 15px/1.5 system-ui");
    expect(html).toContain("font-variant-numeric: tabular-nums");
    expect(html).toContain("@media (prefers-color-scheme: dark)");
    expect(html).toContain('<meta name="viewport" content="width=device-width, initial-scale=1">');
    expect(html).toContain("@media (max-width: 600px)");
    expect(html).toContain("overflow-wrap: anywhere");
  });

  it("polls /api/summary every 5 seconds and drops the token from the address bar", () => {
    expect(html).toContain("setTimeout(loop, 5000)");
    expect(html).toContain('history.replaceState(null, "", location.pathname)');
  });
});

describe("/api/summary redaction (invariant 4)", async () => {
  const github = fake("GITHUB");
  const stripe = fake("STRIPE_LIVE");
  const s = await start({
    summary: () =>
      summaryWith({
        project: `demo ${stripe}`,
        fixNext: [{ severity: "critical", title: `Hard-coded key ${fake("OPENAI")}`, file: `src/${github}.ts`, line: 1 }],
        servers: [{ name: `srv-${fake("SLACK")}`, vetted: false, scoped: false, sandbox: "no", changed: false, sent7d: 1, blocked7d: 0, score: 25 }],
        notChecked: [`Area ${PLANTED_EMAIL} (${fake("ANTHROPIC")})`, ...PLANTED.map((p) => `x ${p}`)],
      }),
  });

  it("returns no planted secret or personal data, only redacted forms", async () => {
    const r = await get(s.port, "/api/summary", { headers: { Cookie: `secor_t=${s.token}` } });
    expect(r.status).toBe(200);
    expect(leaked(r.body)).toEqual([]);
    expect(r.body).toContain(`ghp_…${github.slice(-4)}`);
    expect(r.body).toContain(`sk_live_…${stripe.slice(-4)}`);
    expect(r.body).toContain("j***@acme-corp.io");
  });

  it("a summary that throws gives a redacted 500, not a crash", async () => {
    const bad = await start({
      summary: () => {
        throw new Error(`cannot read ${fake("GITHUB")}`);
      },
    });
    const r = await get(bad.port, "/api/summary", { headers: { Cookie: `secor_t=${bad.token}` } });
    expect(r.status).toBe(500);
    expect(leaked(r.body)).toEqual([]);
    expect((await get(bad.port, "/", { headers: { Cookie: `secor_t=${bad.token}` } })).status).toBe(200);
  });
});

describe("idle shutdown (spec 12.1)", () => {
  it("closes after idleMs without requests and stops answering", async () => {
    const s = await start({ idleMs: 150 });
    const t0 = Date.now();
    await s.closed;
    expect(Date.now() - t0).toBeGreaterThanOrEqual(100);
    expect(s.isClosed()).toBe(true);
    await expect(get(s.port, "/", { headers: { Cookie: `secor_t=${s.token}` } })).rejects.toThrow();
  });

  it("each accepted request restarts the idle timer", async () => {
    const s = await start({ idleMs: 600 });
    const cookie = { Cookie: `secor_t=${s.token}` };
    const t0 = Date.now();
    for (let i = 0; i < 12; i++) {
      expect((await get(s.port, "/api/summary", { headers: cookie })).status).toBe(200);
      await sleep(100);
    }
    expect(Date.now() - t0).toBeGreaterThan(600);
    expect(s.isClosed()).toBe(false);
    await s.closed;
    expect(s.isClosed()).toBe(true);
  });

  it("rejected requests do not keep it alive", async () => {
    const s = await start({ idleMs: 250 });
    const t0 = Date.now();
    const spam = (async () => {
      while (!s.isClosed() && Date.now() - t0 < 3000) {
        await get(s.port, "/", { host: "evil.example.com" }).catch(() => undefined);
        await sleep(40);
      }
    })();
    await s.closed;
    expect(Date.now() - t0).toBeLessThan(2000);
    await spam;
  });
});

describe("helpers", () => {
  it("tokenMatches compares exactly", () => {
    const t = "ab".repeat(32);
    expect(tokenMatches(t, t)).toBe(true);
    expect(tokenMatches(`${t}0`, t)).toBe(false);
    expect(tokenMatches(t.toUpperCase(), t)).toBe(false);
    expect(tokenMatches(null, t)).toBe(false);
    expect(tokenMatches("", t)).toBe(false);
  });

  it("cookieValues finds every value of one cookie", () => {
    expect(cookieValues("a=1; secor_t=xyz; b=2", "secor_t")).toEqual(["xyz"]);
    expect(cookieValues("secor_t=1; secor_t=2", "secor_t")).toEqual(["1", "2"]);
    expect(cookieValues("secor_tt=1", "secor_t")).toEqual([]);
    expect(cookieValues(undefined, "secor_t")).toEqual([]);
  });

  it("allowedByFetchMetadata follows the resource isolation policy", () => {
    expect(allowedByFetchMetadata("GET", undefined, undefined, undefined)).toBe(true);
    expect(allowedByFetchMetadata("GET", "same-origin", "cors", "empty")).toBe(true);
    expect(allowedByFetchMetadata("GET", "none", "navigate", "document")).toBe(true);
    expect(allowedByFetchMetadata("GET", "cross-site", "navigate", "document")).toBe(true);
    expect(allowedByFetchMetadata("POST", "cross-site", "navigate", "document")).toBe(false);
    expect(allowedByFetchMetadata("GET", "cross-site", "navigate", "embed")).toBe(false);
    expect(allowedByFetchMetadata("GET", "same-site", "no-cors", "script")).toBe(false);
  });
});
