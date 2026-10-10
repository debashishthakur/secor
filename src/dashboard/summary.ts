// DashboardSummary (spec section 12.3), built from the latest run, the run history, the live Connect posture and
// the ledger. `summarize` is pure; `buildDashboardSummary` reads the inputs from disk.
//
// Ship numbers come from the latest run. Connect numbers (servers, hooks, score) are read live, so the overall score
// is recomputed with the spec 10 formula from the run's Ship score and the live Connect score. The delta compares
// that overall score with the run before the latest one.

import { basename, resolve } from "node:path";
import { readLedger } from "../connect/ledger.js";
import { type ConnectPosture, connectPosture } from "../connect/posture.js";
import { loadProjectConfig, projectName } from "../engine/config.js";
import { counted } from "../engine/finding.js";
import { type HistoryLine, readHistory, readLatest } from "../engine/report.js";
import { band } from "../engine/score.js";
import { type DashboardSummary, type Finding, type LedgerEntry, RULES_VERSION, type RunResult, SEVERITY_RANK } from "../types.js";

const DAY = 86_400_000;
const HISTORY_RUNS = 7;
const FIX_NEXT = 3;

export interface SummaryInputs {
  projectName: string;
  latest: RunResult | null;
  /** history.jsonl lines, oldest first. */
  history: HistoryLine[];
  posture: ConnectPosture;
  /** Ledger entries; only `pre` entries of the 7 days before `now` are used. */
  ledger: LedgerEntry[];
  now: Date;
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function bySeverityFileLine(a: Finding, b: Finding): number {
  return (
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    cmp(a.location.file, b.location.file) ||
    a.location.line - b.location.line ||
    cmp(a.ruleId, b.ruleId) ||
    cmp(a.id, b.id)
  );
}

/** Claude Code names MCP tools mcp__<server>__<tool> with characters outside [A-Za-z0-9_-] replaced by "_". */
function toolNameForm(server: string): string {
  return server.replace(/[^A-Za-z0-9_-]/g, "_");
}

/** The run before `latest` in history order (history is appended as runs complete). */
export function previousRun(history: readonly HistoryLine[], latest: RunResult | null): HistoryLine | null {
  if (!latest) return null;
  let idx = -1;
  for (let i = history.length - 1; i >= 0; i--) {
    if (history[i]!.runId === latest.runId) {
      idx = i;
      break;
    }
  }
  if (idx >= 0) return idx > 0 ? history[idx - 1]! : null;
  const older = history.filter((h) => h.finishedAt < latest.finishedAt);
  return older.length ? older[older.length - 1]! : null;
}

export function summarize(i: SummaryInputs): DashboardSummary {
  const { latest, posture, now } = i;
  const ship = latest ? latest.score.ship : null;
  const shipByKind = latest ? latest.score.shipByKind : { api: null, mcp: null, web: null };
  const parts = [ship, posture.score].filter((v): v is number => typeof v === "number");
  const overall = parts.length ? Math.min(...parts) : null;
  const prev = previousRun(i.history, latest);
  const delta = overall !== null && prev !== null && typeof prev.overall === "number" ? overall - prev.overall : null;

  const findings = { critical: 0, high: 0, medium: 0, low: 0, ignored: 0, advisory: 0 };
  for (const f of latest?.findings ?? []) {
    if (f.status === "ignored") findings.ignored++;
    else if (counted(f)) findings[f.severity]++;
    else findings.advisory++; // open, and advisory or from an experimental rule
  }
  const fixNext = (latest?.findings ?? [])
    .filter(counted)
    .sort(bySeverityFileLine)
    .slice(0, FIX_NEXT)
    .map((f) => ({ severity: f.severity, title: f.title, file: f.location.file, line: f.location.line }));

  const since = new Date(now.getTime() - 7 * DAY).toISOString();
  const until = now.toISOString();
  const sent = i.ledger.filter((e) => e.phase === "pre" && e.decision !== "error" && typeof e.ts === "string" && e.ts >= since && e.ts <= until);
  const servers = posture.servers
    .map((s) => {
      const mine = sent.filter((e) => toolNameForm(String(e.server)) === toolNameForm(s.name));
      return {
        name: s.name,
        vetted: s.vetted,
        scoped: s.scoped,
        sandbox: s.sandbox,
        changed: s.changed,
        sent7d: mine.length,
        blocked7d: mine.filter((e) => e.decision === "block").length,
        score: s.score,
      };
    })
    .sort((a, b) => a.score - b.score || cmp(a.name, b.name));

  return {
    project: i.projectName,
    lastCheck: latest ? latest.finishedAt : null,
    rulesVersion: latest ? latest.rulesVersion : RULES_VERSION,
    scoringVersion: 1,
    overall: { score: overall, band: band(overall), delta },
    ship: { score: ship, api: shipByKind.api, mcp: shipByKind.mcp, web: shipByKind.web },
    connect: { score: posture.score, serverCount: posture.servers.length, hooks: posture.hooks },
    coverage: latest ? { percent: latest.coverage.percent, incomplete: latest.score.incomplete } : { percent: 0, incomplete: true },
    findings,
    fixNext,
    servers,
    history: i.history.slice(-HISTORY_RUNS).map((h) => ({ runId: h.runId, at: h.finishedAt, overall: h.overall })),
    notChecked: latest ? latest.coverage.notChecked.map((n) => `${n.area} (${n.reason})`) : [],
  };
}

// ---------------------------------------------------------------- inputs from disk

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

const numOrNull = (v: unknown): boolean => v === null || typeof v === "number";

/** latest.json is used only when it has the shape the dashboard reads; otherwise the dashboard shows "not run". */
export function usableRun(v: unknown): RunResult | null {
  if (!isObj(v) || typeof v.runId !== "string" || typeof v.finishedAt !== "string" || typeof v.rulesVersion !== "string") return null;
  if (!isObj(v.project) || typeof v.project.name !== "string") return null;
  if (!Array.isArray(v.findings) || !v.findings.every((f) => isObj(f) && isObj(f.location) && typeof f.severity === "string" && typeof f.status === "string")) return null;
  if (!isObj(v.coverage) || typeof v.coverage.percent !== "number" || !Array.isArray(v.coverage.notChecked)) return null;
  if (!isObj(v.score) || !numOrNull(v.score.ship) || !isObj(v.score.shipByKind) || typeof v.score.incomplete !== "boolean") return null;
  return v as unknown as RunResult;
}

export function usableHistory(lines: unknown[]): HistoryLine[] {
  return lines.filter((h): h is HistoryLine => isObj(h) && typeof h.runId === "string" && typeof h.finishedAt === "string" && numOrNull(h.overall));
}

function projectNameOf(root: string): string {
  try {
    return projectName(root, loadProjectConfig(root));
  } catch {
    return basename(root);
  }
}

export function buildDashboardSummary(root: string, now = new Date()): DashboardSummary {
  const r = resolve(root);
  const latest = usableRun(readLatest(r));
  return summarize({
    projectName: latest ? latest.project.name : projectNameOf(r),
    latest,
    history: usableHistory(readHistory(r)),
    posture: connectPosture(r, now),
    ledger: readLedger(7 * DAY, now),
    now,
  });
}
