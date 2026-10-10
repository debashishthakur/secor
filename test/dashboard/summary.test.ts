// DashboardSummary builder (spec 12.2 counting rules, 12.3 shape): synthetic runs, history, posture and ledger.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ConnectPosture, ServerPosture } from "../../src/connect/posture.js";
import { buildDashboardSummary, previousRun, summarize, usableRun } from "../../src/dashboard/summary.js";
import type { HistoryLine } from "../../src/engine/report.js";
import { finding, ledgerEntry, runResult, type TempHome, tempProject, useTempHome, writeLedger, writeRawRun } from "../mcp/synthetic.js";

const NOW = new Date("2026-10-10T12:00:00.000Z");
const NO_SERVERS: ConnectPosture = { servers: [], hooks: "off", score: null };

function server(p: Partial<ServerPosture> & { name: string; score: number }): ServerPosture {
  return {
    source: `claude-code:project:/p/.mcp.json`,
    managed: true,
    transport: "stdio",
    sandbox: "no",
    vetted: true,
    vetVerdict: "ok",
    scoped: true,
    changed: false,
    ...p,
  };
}

function hist(runId: string, overall: number | null, finishedAt = `${runId.slice(0, 4)}-${runId.slice(4, 6)}-${runId.slice(6, 8)}T00:00:00.000Z`): HistoryLine {
  return { runId, finishedAt, overall, ship: overall, connect: null, coverage: 90 };
}

describe("summarize: empty states", () => {
  it("no run, no servers, no ledger", () => {
    expect(summarize({ projectName: "demo", latest: null, history: [], posture: NO_SERVERS, ledger: [], now: NOW })).toEqual({
      project: "demo",
      lastCheck: null,
      rulesVersion: "1.0.0",
      scoringVersion: 1,
      overall: { score: null, band: null, delta: null },
      ship: { score: null, api: null, mcp: null, web: null },
      connect: { score: null, serverCount: 0, hooks: "off" },
      coverage: { percent: 0, incomplete: true },
      findings: { critical: 0, high: 0, medium: 0, low: 0, ignored: 0, advisory: 0 },
      fixNext: [],
      servers: [],
      history: [],
      notChecked: [],
    });
  });

  it("Connect alone gives an overall score when Ship has not run", () => {
    const posture: ConnectPosture = { servers: [server({ name: "github", score: 55 })], hooks: "on", score: 55 };
    const s = summarize({ projectName: "demo", latest: null, history: [], posture, ledger: [], now: NOW });
    expect(s.overall).toEqual({ score: 55, band: "needs-work", delta: null });
    expect(s.ship.score).toBeNull();
    expect(s.connect).toEqual({ score: 55, serverCount: 1, hooks: "on" });
  });
});

describe("summarize: findings panel (spec 12.2 counting rules)", () => {
  const latest = runResult({
    findings: [
      finding({ severity: "critical", location: { file: "src/b.ts", line: 5 }, title: "B critical" }),
      finding({ severity: "critical", location: { file: "src/a.ts", line: 9 }, title: "A critical" }),
      finding({ severity: "high", location: { file: "src/a.ts", line: 2 }, title: "A high" }),
      finding({ severity: "medium", location: { file: "src/a.ts", line: 1 } }),
      finding({ severity: "low", location: { file: "src/c.ts", line: 1 } }),
      finding({ severity: "critical", advisory: true, location: { file: "src/0.ts", line: 1 } }),
      finding({ severity: "high", maturity: "experimental", location: { file: "src/0.ts", line: 2 } }),
      finding({ severity: "critical", status: "ignored", ignoreReason: "behind VPN", location: { file: "src/0.ts", line: 3 } }),
      finding({ severity: "low", status: "ignored", advisory: true, ignoreReason: "ok", location: { file: "src/0.ts", line: 4 } }),
    ],
  });
  const s = summarize({ projectName: "demo", latest, history: [], posture: NO_SERVERS, ledger: [], now: NOW });

  it("counts only counted findings by severity; advisory and experimental go to Advisory; ignored only to Ignored", () => {
    expect(s.findings).toEqual({ critical: 2, high: 1, medium: 1, low: 1, ignored: 2, advisory: 2 });
  });

  it("FIX NEXT: up to 3 counted findings by severity, then file, then line", () => {
    expect(s.fixNext).toEqual([
      { severity: "critical", title: "A critical", file: "src/a.ts", line: 9 },
      { severity: "critical", title: "B critical", file: "src/b.ts", line: 5 },
      { severity: "high", title: "A high", file: "src/a.ts", line: 2 },
    ]);
  });

  it("no counted findings gives an empty FIX NEXT", () => {
    const only = runResult({ findings: [finding({ advisory: true }), finding({ maturity: "experimental" })] });
    expect(summarize({ projectName: "d", latest: only, history: [], posture: NO_SERVERS, ledger: [], now: NOW }).fixNext).toEqual([]);
  });

  it("run metadata: lastCheck, versions, coverage, notChecked as '<area> (<reason>)'", () => {
    expect(s.lastCheck).toBe(latest.finishedAt);
    expect(s.rulesVersion).toBe("1.0.0");
    expect(s.scoringVersion).toBe(1);
    expect(s.coverage).toEqual({ percent: 90, incomplete: false });
    expect(s.notChecked).toEqual(["Running deployment (SECOR v1 reads files only)", "Containers (not supported in v1)"]);
  });
});

describe("summarize: overall, delta and history", () => {
  const latest = runResult({
    runId: "20261009T000000Z",
    finishedAt: "2026-10-09T00:00:00.000Z",
    score: { scoringVersion: 1, overall: 72, band: "needs-work", ship: 72, shipByKind: { api: 72, mcp: 90, web: null }, connect: null, incomplete: false },
  });
  const history = [
    hist("20261001T000000Z", 10),
    hist("20261002T000000Z", 20),
    hist("20261003T000000Z", 30),
    hist("20261004T000000Z", null),
    hist("20261005T000000Z", 50),
    hist("20261006T000000Z", 60),
    hist("20261007T000000Z", 70),
    hist("20261008T000000Z", 50),
    hist("20261009T000000Z", 72),
  ];

  it("overall = min(Ship score of the latest run, live Connect score), with its band", () => {
    const posture: ConnectPosture = { servers: [server({ name: "x", score: 65 })], hooks: "on", score: 65 };
    const s = summarize({ projectName: "d", latest, history, posture, ledger: [], now: NOW });
    expect(s.ship).toEqual({ score: 72, api: 72, mcp: 90, web: null });
    expect(s.overall.score).toBe(65);
    expect(s.overall.band).toBe("needs-work");
    expect(s.overall.delta).toBe(65 - 50);
  });

  it("delta = overall minus the previous run's overall", () => {
    const s = summarize({ projectName: "d", latest, history, posture: NO_SERVERS, ledger: [], now: NOW });
    expect(s.overall).toEqual({ score: 72, band: "needs-work", delta: 22 });
  });

  it("delta is null with a single run, or when the previous run had no overall score", () => {
    expect(summarize({ projectName: "d", latest, history: [hist("20261009T000000Z", 72)], posture: NO_SERVERS, ledger: [], now: NOW }).overall.delta).toBeNull();
    const prevNull = [hist("20261008T000000Z", null), hist("20261009T000000Z", 72)];
    expect(summarize({ projectName: "d", latest, history: prevNull, posture: NO_SERVERS, ledger: [], now: NOW }).overall.delta).toBeNull();
  });

  it("previousRun falls back to the newest older line when latest is missing from history", () => {
    const h = [hist("20261001T000000Z", 10), hist("20261002T000000Z", 20)];
    expect(previousRun(h, latest)?.runId).toBe("20261002T000000Z");
    expect(previousRun(h, null)).toBeNull();
  });

  it("history: the last 7 runs, oldest first, as {runId, at, overall}", () => {
    const s = summarize({ projectName: "d", latest, history, posture: NO_SERVERS, ledger: [], now: NOW });
    expect(s.history.map((h) => h.runId)).toEqual(history.slice(-7).map((h) => h.runId));
    expect(s.history[0]).toEqual({ runId: "20261003T000000Z", at: "2026-10-03T00:00:00.000Z", overall: 30 });
    expect(s.history[1]?.overall).toBeNull();
  });
});

describe("summarize: connected servers", () => {
  const posture: ConnectPosture = {
    servers: [
      server({ name: "notion", score: 80 }),
      server({ name: "github", score: 80, sandbox: "yes" }),
      server({ name: "random.tool", score: 25, managed: false, vetted: false, scoped: false, vetVerdict: null }),
      server({ name: "remote", score: 70, transport: "http", sandbox: "n/a", changed: true }),
    ],
    hooks: "degraded",
    score: 25,
  };
  const ledger = [
    ledgerEntry({ server: "github", decision: "pass", ts: "2026-10-09T10:00:00.000Z" }),
    ledgerEntry({ server: "github", decision: "block", ts: "2026-10-09T11:00:00.000Z" }),
    ledgerEntry({ server: "github", decision: "ask", ts: "2026-10-04T12:00:01.000Z" }),
    ledgerEntry({ server: "github", decision: "error", ts: "2026-10-09T12:00:00.000Z" }),
    ledgerEntry({ server: "github", decision: "warn", phase: "post", ts: "2026-10-09T12:00:00.000Z" }),
    ledgerEntry({ server: "github", decision: "block", ts: "2026-10-02T12:00:00.000Z" }),
    // Claude Code tool names replace "." with "_": the hook records "random_tool".
    ledgerEntry({ server: "random_tool", decision: "block", ts: "2026-10-10T09:00:00.000Z" }),
    ledgerEntry({ server: "notion", decision: "ask", ts: "2026-10-10T11:59:59.000Z" }),
  ];
  const s = summarize({ projectName: "d", latest: null, history: [], posture, ledger, now: NOW });

  it("rows sorted by score ascending, then name", () => {
    expect(s.servers.map((x) => x.name)).toEqual(["random.tool", "remote", "github", "notion"]);
  });

  it("sent7d counts pre entries of the last 7 days except error; blocked7d the blocks among them", () => {
    const by = Object.fromEntries(s.servers.map((x) => [x.name, x]));
    expect(by.github).toMatchObject({ sent7d: 3, blocked7d: 1, sandbox: "yes", vetted: true, scoped: true, changed: false, score: 80 });
    expect(by["random.tool"]).toMatchObject({ sent7d: 1, blocked7d: 1, vetted: false, scoped: false });
    expect(by.notion).toMatchObject({ sent7d: 1, blocked7d: 0 });
    expect(by.remote).toMatchObject({ sent7d: 0, blocked7d: 0, sandbox: "n/a", changed: true });
  });

  it("connect panel: live score, server count and hooks status", () => {
    expect(s.connect).toEqual({ score: 25, serverCount: 4, hooks: "degraded" });
    expect(s.overall).toMatchObject({ score: 25, band: "fix-before-deploy" });
  });

  it("each row has exactly the 12.3 fields", () => {
    for (const row of s.servers) expect(Object.keys(row).sort()).toEqual(["blocked7d", "changed", "name", "sandbox", "scoped", "score", "sent7d", "vetted"]);
  });
});

describe("usableRun", () => {
  it("rejects files without the fields the dashboard reads", () => {
    expect(usableRun(null)).toBeNull();
    expect(usableRun({ runId: "x" })).toBeNull();
    expect(usableRun({ ...runResult(), findings: "nope" })).toBeNull();
    expect(usableRun(runResult())).not.toBeNull();
  });
});

describe("buildDashboardSummary from disk", () => {
  let env: TempHome;
  beforeAll(() => {
    env = useTempHome();
  });
  afterAll(() => env.restore());

  it("no .secor yet: project name from package.json, empty panels, discovered servers still listed", () => {
    const root = tempProject();
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "shop-api" }));
    writeFileSync(join(root, ".mcp.json"), JSON.stringify({ mcpServers: { github: { command: "npx", args: ["-y", "gh-mcp"] }, secor: { command: "secor", args: ["mcp"] } } }));
    const s = buildDashboardSummary(root, NOW);
    expect(s.project).toBe("shop-api");
    expect(s.lastCheck).toBeNull();
    expect(s.fixNext).toEqual([]);
    // SECOR's own server is not a third-party server; github is unmanaged, unvetted, unscoped, unsandboxed: 100-30-20-25.
    expect(s.servers.map((x) => x.name)).toEqual(["github"]);
    expect(s.servers[0]).toMatchObject({ vetted: false, scoped: false, sandbox: "no", changed: false, score: 25 });
    expect(s.connect).toEqual({ score: 25, serverCount: 1, hooks: "off" });
  });

  it("reads latest.json, history.jsonl and the ledger", () => {
    const root = tempProject();
    writeFileSync(join(root, ".mcp.json"), JSON.stringify({ mcpServers: { github: { command: "npx", args: ["gh-mcp"] } } }));
    const first = runResult({ runId: "20261008T000000Z", finishedAt: "2026-10-08T00:00:00.000Z", score: { scoringVersion: 1, overall: 40, band: "fix-before-deploy", ship: 40, shipByKind: { api: 40, mcp: null, web: null }, connect: null, incomplete: false } });
    const second = runResult({
      runId: "20261009T000000Z",
      finishedAt: "2026-10-09T00:00:00.000Z",
      project: { name: "from-run", root },
      findings: [finding({ severity: "high" })],
    });
    writeRawRun(root, first);
    writeRawRun(root, second);
    mkdirSync(env.secorHome, { recursive: true });
    writeLedger(env.secorHome, [ledgerEntry({ server: "github", ts: "2026-10-10T10:00:00.000Z", decision: "block" })]);
    const s = buildDashboardSummary(root, NOW);
    expect(s.project).toBe("from-run");
    expect(s.lastCheck).toBe("2026-10-09T00:00:00.000Z");
    expect(s.findings.high).toBe(1);
    expect(s.history.map((h) => h.overall)).toEqual([40, 79]);
    // A ledger entry for github means hooks count as configured (on): connect = 25, overall = min(79, 25).
    expect(s.connect.hooks).toBe("on");
    expect(s.servers[0]).toMatchObject({ name: "github", sent7d: 1, blocked7d: 1 });
    expect(s.overall).toEqual({ score: 25, band: "fix-before-deploy", delta: 25 - 40 });
  });

  it("a corrupt latest.json shows as not run instead of failing", () => {
    const root = tempProject();
    mkdirSync(join(root, ".secor"), { recursive: true });
    writeFileSync(join(root, ".secor", "latest.json"), "{ not json");
    expect(buildDashboardSummary(root, NOW).lastCheck).toBeNull();
  });
});
