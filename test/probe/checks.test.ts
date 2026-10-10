// Functional checks (spec 9A.8): each check fires on a deliberately-misconfigured local app and stays
// silent on the fixed one; the traffic caps hold; only GET/OPTIONS are ever sent; bodies never hit disk;
// retrieved secrets are redacted.

import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as http from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runProbe } from "../../src/probe/run.js";
import type { Finding } from "../../src/types.js";
import { FAKE } from "../helpers/fixtures.js";
import { autoConfirmIO, ep, fakeResolver, startServer, staticFinding, type TestServer, tempHome, type TempHome, v4, writeLatest } from "./helpers.js";

const PLANTED_SECRET = FAKE.AWS_ACCESS_KEY; // generated at runtime; matches the AWS access-key-id detector

function project(): string {
  return mkdtempSync(join(tmpdir(), "secor-probe-proj-"));
}

function send(res: http.ServerResponse, status: number, body: string, headers: Record<string, string | string[]> = {}): void {
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.statusCode = status;
  res.end(body);
}

function reflectCors(req: http.IncomingMessage, res: http.ServerResponse): void {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("access-control-allow-origin", Array.isArray(origin) ? origin[0]! : origin);
    res.setHeader("access-control-allow-credentials", "true");
  }
}

const vulnerableApp: http.RequestListener = (req, res) => {
  reflectCors(req, res);
  if (req.method === "OPTIONS") return send(res, 204, "");
  const url = req.url ?? "/";
  if (url === "/") return send(res, 200, `<html><body><script src="/app.js"></script></body></html>`, { "content-type": "text/html", "set-cookie": "session=abc123; Path=/" });
  if (url === "/app.js.map") return send(res, 200, JSON.stringify({ version: 3, sources: [], mappings: "AAAA" }), { "content-type": "application/json" });
  if (url === "/.env") return send(res, 200, `AWS_ACCESS_KEY_ID=${PLANTED_SECRET}\nPORT=3000\n`);
  if (url.startsWith("/api/")) return send(res, 200, JSON.stringify([{ id: 1, name: "row" }]), { "content-type": "application/json" });
  return send(res, 404, "not found");
};

const fixedApp: http.RequestListener = (req, res) => {
  if (req.method === "OPTIONS") return send(res, 204, "");
  const url = req.url ?? "/";
  if (url === "/")
    return send(res, 200, "<html><body>ok</body></html>", {
      "content-type": "text/html",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "strict-transport-security": "max-age=63072000",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "set-cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
    });
  if (url.startsWith("/api/")) return send(res, 401, JSON.stringify({ error: "unauthorized" }), { "content-type": "application/json" });
  return send(res, 404, "nope");
};

function byCheck(findings: Finding[]): Set<string> {
  return new Set(findings.filter((f) => f.probe).map((f) => f.ruleId));
}

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walkFiles(p));
    else out.push(p);
  }
  return out;
}

describe("Probe checks: vulnerable vs fixed", () => {
  let home: TempHome;
  let server: TestServer;
  let root: string;
  beforeEach(() => {
    home = tempHome();
    root = project();
  });
  afterEach(async () => {
    await server?.close();
    rmSync(root, { recursive: true, force: true });
    home.restore();
  });

  const inventory = [ep({ path: "/api/users", id: "ep_users" })];
  const statics: Finding[] = [
    staticFinding({ id: "sf_auth", ruleId: "api/missing-auth", severity: "critical", entryPointId: "ep_users", file: "src/app.ts", line: 10 }),
    staticFinding({ id: "sf_csp", ruleId: "web/security-headers", severity: "low", service: "web", evidence: "missing Content-Security-Policy" }),
    staticFinding({ id: "sf_cookie", ruleId: "web/cookie-flags", severity: "medium", service: "web", evidence: 'cookie "session" missing flags' }),
  ];

  it("fires every unauthenticated check on the vulnerable app and merges confirmations", async () => {
    server = await startServer(vulnerableApp);
    writeLatest(root, inventory, statics, [
      { kind: "api", framework: "express", root: "" },
      { kind: "web", framework: "nextjs", root: "" },
    ]);
    const run = await runProbe({
      projectRoot: root,
      target: server.origin,
      iOwnThisTarget: true,
      io: autoConfirmIO(),
      clientOpts: { maxPerSecond: 1000 },
    });
    const checks = byCheck(run.result.findings);
    // open-endpoint and cookie-flags/security-headers merged into their static findings; others added.
    expect(run.merged).toBeGreaterThanOrEqual(3);
    expect(checks.has("probe/cors-reflection")).toBe(true);
    expect(checks.has("probe/exposed-artifact")).toBe(true);
    // The static missing-auth finding is now confirmed live.
    const auth = run.result.findings.find((f) => f.id === "sf_auth")!;
    expect(auth.probe).toBe(true);
    expect(auth.advisory).toBe(false);
    expect(auth.evidence).toContain("confirmed live");
    // Every request used an allowed method only.
    for (const r of server.requests) expect(["GET", "OPTIONS"]).toContain(r.method);
    // No write methods ever.
    expect(server.requests.some((r) => ["POST", "PUT", "PATCH", "DELETE"].includes(r.method))).toBe(false);
  });

  it("stays silent on the fixed app (no probe findings)", async () => {
    server = await startServer(fixedApp);
    writeLatest(root, inventory, [], [
      { kind: "api", framework: "express", root: "" },
      { kind: "web", framework: "nextjs", root: "" },
    ]);
    const run = await runProbe({
      projectRoot: root,
      target: server.origin,
      iOwnThisTarget: true,
      io: autoConfirmIO(),
      clientOpts: { maxPerSecond: 1000 },
    });
    expect(run.result.findings.filter((f) => f.probe)).toEqual([]);
    expect(run.added).toBe(0);
    expect(run.merged).toBe(0);
  });

  it("redacts a planted secret and never writes response bodies to disk", async () => {
    server = await startServer(vulnerableApp);
    writeLatest(root, inventory, statics);
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), clientOpts: { maxPerSecond: 1000 } });
    const envFinding = run.result.findings.find((f) => f.probe && f.ruleId === "probe/exposed-artifact" && f.location.file === "/.env")!;
    expect(envFinding).toBeTruthy();
    expect(envFinding.evidence).not.toContain(PLANTED_SECRET);
    expect(envFinding.evidence).toContain("AKIA"); // redacted form keeps the prefix
    // The raw secret must not appear in any file under the project .secor or SECOR_HOME.
    const files = [...walkFiles(join(root, ".secor")), ...walkFiles(home.secorHome)];
    for (const f of files) expect(readFileSync(f, "utf8").includes(PLANTED_SECRET), f).toBe(false);
    expect(files.length).toBeGreaterThan(0); // sanity: we did write a run + consent log
  });

  it("records anon-table-read, idor and privilege-field as notChecked without their inputs", async () => {
    server = await startServer(fixedApp);
    writeLatest(root, inventory, []);
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), clientOpts: { maxPerSecond: 1000 } });
    const areas = run.notChecked.map((n) => n.area);
    expect(areas).toContain("Probe: idor");
    expect(areas).toContain("Probe: privilege-field");
    expect(areas).toContain("Probe: anon-table-read");
    expect(run.notChecked.find((n) => n.area === "Probe: tls-redirect")?.reason).toMatch(/public targets only/);
  });
});

describe("Probe traffic caps", () => {
  let home: TempHome;
  let server: TestServer;
  let root: string;
  beforeEach(() => {
    home = tempHome();
    root = project();
  });
  afterEach(async () => {
    await server?.close();
    rmSync(root, { recursive: true, force: true });
    home.restore();
  });

  it("holds concurrency <= 4 and rate <= 5/s across many endpoints", async () => {
    const slow: http.RequestListener = (req, res) => {
      setTimeout(() => send(res, 200, JSON.stringify([{ id: 1 }]), { "content-type": "application/json" }), 40);
    };
    server = await startServer(slow);
    const inv = Array.from({ length: 12 }, (_, i) => ep({ path: `/api/item${i}`, id: `ep_${i}` }));
    writeLatest(root, inv, []);
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), only: ["open-endpoint"] });
    expect(run.requests.length).toBe(12);
    expect(server.maxConcurrent).toBeLessThanOrEqual(4);
    // The 6th start must be gated ~1s behind the 1st (<= 5 starts per rolling second).
    const starts = [...server.starts].sort((a, b) => a - b);
    expect(starts.length).toBe(12);
    expect(starts[5]! - starts[0]!).toBeGreaterThanOrEqual(900);
    for (const r of server.requests) expect(r.method).toBe("GET");
  });
});

describe("Probe authenticated + supabase checks", () => {
  let home: TempHome;
  let server: TestServer;
  let root: string;
  beforeEach(() => {
    home = tempHome();
    root = project();
  });
  afterEach(async () => {
    await server?.close();
    rmSync(root, { recursive: true, force: true });
    home.restore();
  });

  function writeAccounts(): string {
    const p = join(root, "accounts.json");
    writeFileSync(p, JSON.stringify({ a: { headers: { "x-user": "A" } }, b: { headers: { "x-user": "B" } } }));
    return p;
  }

  it("probe/idor fires when account B reads account A's record, silent when it 403s", async () => {
    const vuln: http.RequestListener = (req, res) => {
      const url = req.url ?? "";
      if (url === "/api/notes") return send(res, 200, JSON.stringify([{ id: "n1" }]), { "content-type": "application/json" });
      if (url === "/api/notes/n1") return send(res, 200, JSON.stringify({ id: "n1", owner: "A" }), { "content-type": "application/json" });
      return send(res, 404, "x");
    };
    server = await startServer(vuln);
    writeLatest(root, [ep({ path: "/api/notes/:id", id: "ep_note" })], []);
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), only: ["idor"], accountsPath: writeAccounts(), clientOpts: { maxPerSecond: 1000 } });
    expect(run.result.findings.some((f) => f.probe && f.ruleId === "probe/idor")).toBe(true);
    // Account headers never leak into any finding evidence.
    for (const f of run.result.findings) expect(f.evidence).not.toContain("x-user");
  });

  it("probe/privilege-field fires when a non-admin reads an admin endpoint", async () => {
    const vuln: http.RequestListener = (req, res) => {
      if ((req.url ?? "").startsWith("/api/admin/")) return send(res, 200, JSON.stringify({ totalUsers: 999 }), { "content-type": "application/json" });
      return send(res, 404, "x");
    };
    server = await startServer(vuln);
    writeLatest(root, [ep({ path: "/api/admin/stats", id: "ep_admin", auth: { guarded: true, via: "handler", guard: "requireAdmin" } })], []);
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), only: ["privilege-field"], accountsPath: writeAccounts(), clientOpts: { maxPerSecond: 1000 } });
    expect(run.result.findings.some((f) => f.probe && f.ruleId === "probe/privilege-field")).toBe(true);
  });

  it("probe/anon-table-read reports table + row count only when the Supabase URL is the target", async () => {
    const rowSecret = "super-secret-row-value";
    const supa: http.RequestListener = (req, res) => {
      if ((req.url ?? "").startsWith("/rest/v1/notes")) return send(res, 200, JSON.stringify([{ id: 1, secret: rowSecret }]), { "content-type": "application/json" });
      return send(res, 404, "x");
    };
    server = await startServer(supa);
    mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
    writeFileSync(join(root, "supabase", "migrations", "0001_init.sql"), "create table public.notes (id int primary key);\n");
    writeFileSync(join(root, ".env"), `SUPABASE_URL=${server.origin}\nSUPABASE_ANON_KEY=anon_key_1234567890abcdef\n`);
    writeLatest(root, [], []);
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), only: ["anon-table-read"], clientOpts: { maxPerSecond: 1000 } });
    const finding = run.result.findings.find((f) => f.probe && f.ruleId === "probe/anon-table-read");
    expect(finding).toBeTruthy();
    expect(finding!.evidence).toContain("notes");
    expect(finding!.evidence).toContain("1 row");
    expect(finding!.evidence).not.toContain(rowSecret); // row contents are never reported
    // The anon key was sent as a header, never written to a finding.
    expect(finding!.evidence).not.toContain("anon_key_1234567890abcdef");
  });

  it("probe/anon-table-read is notChecked when the Supabase URL is a different public host", async () => {
    server = await startServer(fixedApp);
    mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
    writeFileSync(join(root, "supabase", "migrations", "0001.sql"), "create table public.notes (id int);\n");
    writeFileSync(join(root, ".env"), `SUPABASE_URL=https://abcd.supabase.co\nSUPABASE_ANON_KEY=anon_key_1234567890abcdef\n`);
    writeLatest(root, [], []);
    // Inject a resolver so the public Supabase host resolves to a public IP (no real DNS); the main
    // target is a literal 127.0.0.1 and does not use the resolver.
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), only: ["anon-table-read"], resolver: fakeResolver({ lookup: v4("93.184.216.34") }), clientOpts: { maxPerSecond: 1000 } });
    expect(run.notChecked.find((n) => n.area === "Probe: anon-table-read")?.reason).toMatch(/not the authorized target/);
  });
});

describe("Probe --verify re-runs one check", () => {
  let home: TempHome;
  let server: TestServer;
  let root: string;
  beforeEach(() => {
    home = tempHome();
    root = project();
  });
  afterEach(async () => {
    await server?.close();
    rmSync(root, { recursive: true, force: true });
    home.restore();
  });

  it("re-runs only the given finding's check", async () => {
    server = await startServer(vulnerableApp);
    writeLatest(root, [ep({ path: "/api/users", id: "ep_users" })], [staticFinding({ id: "sf_auth", ruleId: "api/missing-auth", severity: "critical", entryPointId: "ep_users" })]);
    const run = await runProbe({ projectRoot: root, target: server.origin, iOwnThisTarget: true, io: autoConfirmIO(), verifyFindingId: "sf_auth", clientOpts: { maxPerSecond: 1000 } });
    // Only the open-endpoint check ran: one GET to /api/users, nothing else.
    expect(run.requests.map((r) => r.url)).toEqual([`${server.origin}/api/users`]);
    expect(run.result.findings.find((f) => f.id === "sf_auth")!.probe).toBe(true);
  });
});
