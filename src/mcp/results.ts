// Result shapes for the MCP tools (spec section 11.2). Objects read from disk (runs, the ledger) or returned by
// another module are copied field by field onto the normative shapes, so a tampered or newer file cannot add
// unexpected keys to a tool result. Every result is also deep-redacted by the server before it is returned.

import { counted } from "../engine/finding.js";
import {
  type Coverage,
  EVIDENCE_NOTICE,
  type Finding,
  type LedgerDecision,
  type LedgerEntry,
  type RunResult,
  type ScoreBreakdown,
  SEVERITIES,
  type Severity,
  type VetReport,
} from "../types.js";

export { EVIDENCE_NOTICE };

export const RUN_ID_RE = /^\d{8}T\d{6}Z(?:-\d+)?$/;
export const FINDING_ID_RE = /^[a-z0-9-]+-[0-9a-f]{12}$/;

export const PAGE_SIZE_DEFAULT = 20;
export const PAGE_SIZE_MAX = 50;

export interface FindingSummary {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  advisory: boolean;
  maturity: "experimental" | "stable";
  location: { file: string; line: number; endLine?: number };
}

export interface RunSummary {
  score: ScoreBreakdown;
  counts: Record<Severity, number>;
  ignored: number;
  advisory: number;
  coverage: Coverage;
}

export interface ShipResultsPage {
  status: "done";
  summary: RunSummary;
  findings: FindingSummary[];
  page: number;
  totalPages: number;
}

/** Not counted because it needs human judgment or comes from an experimental rule (spec 12.2 "Advisory"). */
export function isAdvisoryOrExperimental(f: Finding): boolean {
  return f.advisory || f.maturity !== "stable";
}

function location(l: Finding["location"]): FindingSummary["location"] {
  return { file: l.file, line: l.line, ...(typeof l.endLine === "number" ? { endLine: l.endLine } : {}) };
}

export function pickScore(s: ScoreBreakdown): ScoreBreakdown {
  return {
    scoringVersion: s.scoringVersion,
    overall: s.overall,
    band: s.band,
    ship: s.ship,
    shipByKind: { api: s.shipByKind.api, mcp: s.shipByKind.mcp, web: s.shipByKind.web },
    connect: s.connect,
    incomplete: s.incomplete,
  };
}

export function pickCoverage(c: Coverage): Coverage {
  return {
    applicable: c.applicable,
    ran: c.ran,
    percent: c.percent,
    notChecked: c.notChecked.map((n) => ({ area: n.area, reason: n.reason })),
  };
}

/**
 * Summary counts follow the dashboard rules (spec 12.2): `counts` holds counted findings only (open, not advisory,
 * stable rule); `advisory` holds open findings that are advisory or from an experimental rule; `ignored` holds
 * ignored findings.
 */
export function summarizeRun(run: RunResult): RunSummary {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  let ignored = 0;
  let advisory = 0;
  for (const f of run.findings) {
    if (f.status === "ignored") ignored++;
    else if (counted(f)) counts[f.severity]++;
    else if (isAdvisoryOrExperimental(f)) advisory++;
  }
  return { score: pickScore(run.score), counts, ignored, advisory, coverage: pickCoverage(run.coverage) };
}

export function findingSummary(f: Finding): FindingSummary {
  return { id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, advisory: f.advisory, maturity: f.maturity, location: location(f.location) };
}

export interface PageQuery {
  severity?: Severity[];
  includeAdvisory?: boolean;
  page?: number;
  pageSize?: number;
}

/**
 * One page of a run's open findings, in run order (severity, file, line, rule). Ignored findings are left out (they
 * appear only in `summary.ignored`). `includeAdvisory: false` keeps only counted findings, so the list then matches
 * `summary.counts`. `totalPages` is at least 1; a page past the end has no findings.
 */
export function resultsPage(run: RunResult, q: PageQuery): ShipResultsPage {
  const pageSize = q.pageSize ?? PAGE_SIZE_DEFAULT;
  const page = q.page ?? 1;
  const severities = q.severity && q.severity.length ? new Set(q.severity) : null;
  const list = run.findings.filter(
    (f) => f.status === "open" && (q.includeAdvisory !== false || !isAdvisoryOrExperimental(f)) && (!severities || severities.has(f.severity)),
  );
  const totalPages = Math.max(1, Math.ceil(list.length / pageSize));
  const findings = list.slice((page - 1) * pageSize, page * pageSize).map(findingSummary);
  return { status: "done", summary: summarizeRun(run), findings, page, totalPages };
}

/** A Finding copied onto its normative fields (spec 7), plus the evidence notice (spec 11.2). */
export function findingResult(f: Finding): Finding & { notice: string } {
  const fix: Finding["fix"] = { summary: f.fix.summary };
  if (typeof f.fix.patch === "string") fix.patch = f.fix.patch;
  if (typeof f.fix.humanAction === "string") fix.humanAction = f.fix.humanAction;
  if (typeof f.fix.testTemplate === "string") fix.testTemplate = f.fix.testTemplate;
  return {
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    advisory: f.advisory,
    maturity: f.maturity,
    service: f.service,
    location: location(f.location),
    ...(typeof f.entryPointId === "string" ? { entryPointId: f.entryPointId } : {}),
    evidence: f.evidence,
    why: f.why,
    fix,
    ...(f.source ? { source: { name: f.source.name, url: f.source.url } } : {}),
    status: f.status,
    ...(typeof f.ignoreReason === "string" ? { ignoreReason: f.ignoreReason } : {}),
    ...(f.probe === true ? { probe: true } : {}),
    notice: EVIDENCE_NOTICE,
  };
}

/** A VetReport copied onto its normative fields (spec 7), plus the evidence notice. */
export function vetResult(r: VetReport): VetReport & { notice: string } {
  return {
    server: r.server,
    source: r.source,
    transport: r.transport,
    sandboxed: r.sandboxed,
    toolCount: r.toolCount,
    verdict: r.verdict,
    findings: (r.findings ?? []).map((f) => ({
      checkId: f.checkId,
      severity: f.severity,
      ...(typeof f.tool === "string" ? { tool: f.tool } : {}),
      evidence: f.evidence,
    })),
    ...(typeof r.incompleteReason === "string" ? { incompleteReason: r.incompleteReason } : {}),
    notice: EVIDENCE_NOTICE,
  };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** A ledger line with the fields the summary relies on (ledger files are read back from disk). */
export function isLedgerEntry(v: unknown): v is LedgerEntry {
  return (
    isRecord(v) &&
    typeof v.ts === "string" &&
    typeof v.server === "string" &&
    typeof v.tool === "string" &&
    (v.phase === "pre" || v.phase === "post") &&
    typeof v.decision === "string" &&
    (DECISIONS as readonly string[]).includes(v.decision)
  );
}

export function ledgerEntryResult(e: LedgerEntry): LedgerEntry {
  const reasons = (Array.isArray(e.reasons) ? e.reasons : []).filter(isRecord).map((r) => ({ code: String(r.code), detail: String(r.detail) }));
  return {
    ts: e.ts,
    sessionId: String(e.sessionId),
    editor: e.editor,
    server: e.server,
    tool: e.tool,
    phase: e.phase,
    decision: e.decision,
    reasons,
    ...(typeof e.argChars === "number" ? { argChars: e.argChars } : {}),
    ...(Array.isArray(e.classes) ? { classes: e.classes.filter((c) => typeof c === "string") } : {}),
    ...(Array.isArray(e.flows) ? { flows: e.flows.filter(isRecord).map((f) => ({ source: String(f.source), matches: Number(f.matches) })) } : {}),
  };
}

export type DecisionTotals = Record<LedgerDecision, number>;

export interface LedgerSummary {
  totals: DecisionTotals;
  perServer: ({ server: string } & DecisionTotals)[];
  recent: LedgerEntry[];
}

const DECISIONS: readonly LedgerDecision[] = ["pass", "ask", "block", "warn", "error"];

function zeroTotals(): DecisionTotals {
  return { pass: 0, ask: 0, block: 0, warn: 0, error: 0 };
}

/**
 * Totals per decision and per server (sorted by server name), and the 20 most recent ask / block / warn entries,
 * newest first (spec 9.6 and 11.2). `entries` must be oldest first.
 */
export function summarizeLedger(all: readonly unknown[], max = 20): LedgerSummary {
  const entries = all.filter(isLedgerEntry);
  const totals = zeroTotals();
  const per = new Map<string, DecisionTotals>();
  for (const e of entries) {
    totals[e.decision]++;
    const t = per.get(e.server) ?? zeroTotals();
    t[e.decision]++;
    per.set(e.server, t);
  }
  const perServer = [...per.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([server, t]) => ({ server, ...t }));
  const recent = entries
    .filter((e) => e.decision === "ask" || e.decision === "block" || e.decision === "warn")
    .slice(-max)
    .reverse()
    .map(ledgerEntryResult);
  return { totals, perServer, recent };
}
