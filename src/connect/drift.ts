// Drift (spec section 9.7): re-list every managed server's tools with the vet mechanics and compare tool hashes with
// the approved ones. Drift records `changed`, `changes`, the latest vet result and `lastDriftCheck`; it never touches
// the approval state (`toolHashes`, `approvedAt`), which only `secor connect approve` (a human) changes.
// `changed` stays true until a human approves, even if a later check sees the approved definitions again.

import { isDeepStrictEqual } from "node:util";
import type { VetFinding, VetReport } from "../types.js";
import { serverFromSource } from "./discover.js";
import { type ManagedServer, type ToolChange, loadServers, managedServer, otherManagedTools, updateServers } from "./servers.js";
import { displayName } from "./text.js";
import { listServer, reportFor } from "./vet.js";

export function diffToolHashes(approved: Record<string, string>, current: Record<string, string>): ToolChange[] {
  const names = [...new Set([...Object.keys(approved), ...Object.keys(current)])].sort();
  const out: ToolChange[] = [];
  for (const tool of names) {
    const a = Object.hasOwn(approved, tool) ? approved[tool] : undefined;
    const c = Object.hasOwn(current, tool) ? current[tool] : undefined;
    if (a !== undefined && c === undefined) out.push({ tool, change: "removed" });
    else if (a === undefined && c !== undefined) out.push({ tool, change: "added" });
    else if (a !== c) out.push({ tool, change: "changed" });
  }
  return out;
}

export interface DriftResult {
  server: string;
  status: "unchanged" | "changed" | "incomplete" | "not-found";
  /** Differences found by this check. */
  changes: ToolChange[];
  /** Vet findings on the added or changed tools. */
  findings: VetFinding[];
  verdict?: VetReport["verdict"];
  incompleteReason?: string;
  /** servers.json still says changed (this check or an earlier one), waiting for `secor connect approve`. */
  awaitingApproval: boolean;
}

export interface DriftOptions {
  /** CLI only, an explicit human choice; the dashboard never sets it. */
  allowUnsandboxed?: boolean;
  /** Only servers whose lastDriftCheck is older than this many hours (or missing). */
  onlyStaleHours?: number;
  names?: string[];
  timeoutMs?: number;
  concurrency?: number;
  now?: () => Date;
}

async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

async function checkOne(name: string, m: ManagedServer, opts: DriftOptions, now: () => Date): Promise<DriftResult> {
  const def = serverFromSource(name, m.source);
  if (!def) return { server: name, status: "not-found", changes: [], findings: [], awaitingApproval: m.changed === true };
  const listing = await listServer(def, { allowUnsandboxed: opts.allowUnsandboxed === true, timeoutMs: opts.timeoutMs });
  if (listing.incompleteReason !== undefined) {
    return { server: name, status: "incomplete", changes: [], findings: [], incompleteReason: listing.incompleteReason, awaitingApproval: m.changed === true };
  }
  let others = new Map<string, string[]>();
  try {
    others = otherManagedTools(loadServers(), name);
  } catch {
    // keep empty
  }
  const outcome = reportFor(def, listing, others);
  const changes = diffToolHashes(m.toolHashes ?? {}, outcome.toolHashes);
  const touched = new Set(changes.filter((c) => c.change !== "removed").map((c) => displayName(c.tool)));
  const findings = outcome.report.findings.filter((f) => f.tool !== undefined && touched.has(f.tool));
  const at = now().toISOString();
  let awaiting = changes.length > 0 || m.changed === true;
  updateServers((file) => {
    const cur = managedServer(file, name);
    // Removed or re-approved while we were listing: leave it alone.
    if (!cur || cur.approvedAt !== m.approvedAt || !isDeepStrictEqual(cur.toolHashes, m.toolHashes)) return;
    cur.lastDriftCheck = at;
    cur.vet = { at, verdict: outcome.report.verdict, findings: outcome.report.findings };
    cur.sandbox = def.sandbox;
    if (changes.length) {
      cur.changed = true;
      cur.changes = changes;
    }
    awaiting = cur.changed === true;
  });
  return { server: name, status: changes.length ? "changed" : "unchanged", changes, findings, verdict: outcome.report.verdict, awaitingApproval: awaiting };
}

/** Check managed servers for drift and record the results in servers.json. */
export async function runDrift(opts: DriftOptions = {}): Promise<DriftResult[]> {
  const now = opts.now ?? (() => new Date());
  const file = loadServers();
  let names = Object.keys(file.servers).sort();
  if (opts.names) names = names.filter((n) => opts.names!.includes(n));
  if (opts.onlyStaleHours !== undefined) {
    const cutoff = now().getTime() - opts.onlyStaleHours * 3_600_000;
    names = names.filter((n) => {
      const last = file.servers[n]?.lastDriftCheck;
      const t = typeof last === "string" ? Date.parse(last) : Number.NaN;
      return !(t >= cutoff);
    });
  }
  return mapLimit(names, opts.concurrency ?? 3, (name) => checkOne(name, file.servers[name]!, opts, now));
}

/**
 * Background drift check for the dashboard (spec 9.7): never runs a server unsandboxed, never throws.
 * Pass onlyStaleHours: 24 to check only servers whose lastDriftCheck is older than 24 hours.
 */
export async function driftCheckAll(opts?: { onlyStaleHours?: number }): Promise<void> {
  try {
    await runDrift({ onlyStaleHours: opts?.onlyStaleHours, allowUnsandboxed: false });
  } catch {
    // background work: failures show up as a stale lastDriftCheck
  }
}
