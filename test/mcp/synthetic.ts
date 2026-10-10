// Synthetic runs, findings, ledger lines and an isolated HOME for the MCP and dashboard tests.
// writeRawRun() writes a run to .secor/ WITHOUT redaction, so tests can prove that the MCP and dashboard layers
// redact on their own (invariant 4), whatever is on disk.

import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, LedgerEntry, RunResult } from "../../src/types.js";
import { FAKE } from "../helpers/fixtures.js";

/** A fake value by name, failing loudly if the shared FAKE table does not have it. */
export function fake(name: string): string {
  const v = (FAKE as Record<string, string | undefined>)[name];
  if (!v) throw new Error(`FAKE.${name} is not defined`);
  return v;
}

/** Fake secrets that redact() recognises anywhere in free text. */
export const PLANTED = ["STRIPE_LIVE", "GITHUB", "OPENAI", "ANTHROPIC", "AWS_ACCESS_KEY", "SLACK", "SUPABASE_SECRET", "SENDGRID", "SERVICE_ROLE_JWT"].map(fake);
export const PLANTED_EMAIL = "jane.doe.planted@acme-corp.io";

/** Every planted value, for "nothing leaked" assertions. */
export function leaked(text: string): string[] {
  return [...PLANTED, PLANTED_EMAIL].filter((v) => text.includes(v));
}

let seq = 0;

export function findingId(ruleId: string, n: number): string {
  return `${ruleId.replace(/\//g, "-")}-${n.toString(16).padStart(12, "0")}`;
}

export function finding(p: Partial<Finding> = {}): Finding {
  const ruleId = p.ruleId ?? "api/missing-auth";
  return {
    id: p.id ?? findingId(ruleId, ++seq),
    ruleId,
    title: p.title ?? "Route without an auth check",
    severity: p.severity ?? "high",
    advisory: p.advisory ?? false,
    maturity: p.maturity ?? "stable",
    service: p.service ?? "api",
    location: p.location ?? { file: "src/app.ts", line: 10 },
    ...(p.entryPointId ? { entryPointId: p.entryPointId } : {}),
    evidence: p.evidence ?? 'app.get("/api/users", handler)',
    why: p.why ?? "Anyone can call this route.",
    fix: p.fix ?? { summary: "Add an auth guard." },
    ...(p.source ? { source: p.source } : {}),
    status: p.status ?? "open",
    ...(p.ignoreReason ? { ignoreReason: p.ignoreReason } : {}),
    ...(p.probe ? { probe: true } : {}),
  };
}

export function runResult(p: Partial<RunResult> = {}): RunResult {
  return {
    runId: p.runId ?? "20261010T120000Z",
    startedAt: p.startedAt ?? "2026-10-10T12:00:00.000Z",
    finishedAt: p.finishedAt ?? "2026-10-10T12:00:05.000Z",
    secorVersion: "1.0.0",
    rulesVersion: p.rulesVersion ?? "1.0.0",
    project: p.project ?? { name: "demo", root: "/tmp/demo" },
    units: p.units ?? [{ kind: "api", framework: "express", root: "" }],
    inventory: p.inventory ?? [],
    findings: p.findings ?? [],
    coverage: p.coverage ?? {
      applicable: 10,
      ran: 9,
      percent: 90,
      notChecked: [
        { area: "Running deployment", reason: "SECOR v1 reads files only" },
        { area: "Containers", reason: "not supported in v1" },
      ],
    },
    score: p.score ?? { scoringVersion: 1, overall: 79, band: "needs-work", ship: 79, shipByKind: { api: 79, mcp: null, web: null }, connect: null, incomplete: false },
  };
}

/** Write a run under <root>/.secor exactly as given: runs/<id>.json, optionally latest.json and a history line. */
export function writeRawRun(root: string, run: RunResult, opts: { latest?: boolean; history?: boolean } = {}): void {
  const dir = join(root, ".secor");
  mkdirSync(join(dir, "runs"), { recursive: true });
  const text = `${JSON.stringify(run, null, 2)}\n`;
  writeFileSync(join(dir, "runs", `${run.runId}.json`), text);
  if (opts.latest !== false) writeFileSync(join(dir, "latest.json"), text);
  if (opts.history !== false) {
    const line = { runId: run.runId, finishedAt: run.finishedAt, overall: run.score.overall, ship: run.score.ship, connect: run.score.connect, coverage: run.coverage.percent };
    appendFileSync(join(dir, "history.jsonl"), `${JSON.stringify(line)}\n`);
  }
}

export function ledgerEntry(p: Partial<LedgerEntry> = {}): LedgerEntry {
  return {
    ts: p.ts ?? "2026-10-10T11:00:00.000Z",
    sessionId: p.sessionId ?? "session-1",
    editor: "claude-code",
    server: p.server ?? "github",
    tool: p.tool ?? "search_code",
    phase: p.phase ?? "pre",
    decision: p.decision ?? "pass",
    reasons: p.reasons ?? [],
    ...(p.argChars !== undefined ? { argChars: p.argChars } : {}),
    ...(p.classes ? { classes: p.classes } : {}),
    ...(p.flows ? { flows: p.flows } : {}),
  };
}

/** Append ledger lines to <secorHome>/ledger/<UTC date of ts>.jsonl (raw, like a hook would). */
export function writeLedger(secorHome: string, entries: (LedgerEntry | Record<string, unknown>)[]): void {
  const dir = join(secorHome, "ledger");
  mkdirSync(dir, { recursive: true });
  for (const e of entries) appendFileSync(join(dir, `${String(e.ts).slice(0, 10)}.jsonl`), `${JSON.stringify(e)}\n`);
}

export interface TempHome {
  home: string;
  secorHome: string;
  restore(): void;
}

/** Point HOME and SECOR_HOME at fresh temp dirs (every SECOR path derives from them). */
export function useTempHome(): TempHome {
  const saved = { HOME: process.env.HOME, SECOR_HOME: process.env.SECOR_HOME, CLAUDE_PROJECT_DIR: process.env.CLAUDE_PROJECT_DIR };
  const home = mkdtempSync(join(tmpdir(), "secor-home-"));
  const secorHome = join(home, ".secor");
  process.env.HOME = home;
  process.env.SECOR_HOME = secorHome;
  delete process.env.CLAUDE_PROJECT_DIR;
  return {
    home,
    secorHome,
    restore() {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      rmSync(home, { recursive: true, force: true });
    },
  };
}

export function tempProject(prefix = "secor-proj-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}
