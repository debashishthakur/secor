// Ledger (spec section 9.6): one JSON line per hook decision, metadata only, kept 90 days.

import { existsSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import type { LedgerEntry } from "../types.js";
import { appendLine, readJsonLines } from "../engine/util/fsx.js";
import { secorHome } from "../engine/util/paths.js";

const RETENTION_DAYS = 90;

export function ledgerDir(): string {
  return join(secorHome(), "ledger");
}

export function utcDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Append one entry. When this creates a new day's file, files older than 90 days are deleted. */
export function appendLedger(entry: LedgerEntry, now = new Date()): void {
  const dir = ledgerDir();
  const file = join(dir, `${utcDate(now)}.jsonl`);
  const isNew = !existsSync(file);
  appendLine(file, JSON.stringify(entry));
  if (isNew) pruneLedger(now);
}

export function pruneLedger(now = new Date()): void {
  const cutoff = utcDate(new Date(now.getTime() - RETENTION_DAYS * 86_400_000));
  let names: string[] = [];
  try {
    names = readdirSync(ledgerDir());
  } catch {
    return;
  }
  for (const n of names) {
    const m = /^(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(n);
    if (m && m[1]! < cutoff) {
      try {
        unlinkSync(join(ledgerDir(), n));
      } catch {
        // ignore
      }
    }
  }
}

export interface LedgerTotals {
  pass: number;
  ask: number;
  block: number;
  warn: number;
  error: number;
}

export interface LedgerSummary {
  sinceDays: number;
  server?: string;
  totals: LedgerTotals;
  /** Sorted by server name. */
  perServer: ({ server: string } & LedgerTotals)[];
  /** The 20 most recent ask / block / warn entries, newest first. */
  recent: LedgerEntry[];
}

const DECISIONS = ["pass", "ask", "block", "warn", "error"] as const;

function zeroTotals(): LedgerTotals {
  return { pass: 0, ask: 0, block: 0, warn: 0, error: 0 };
}

/** Section 9.6: totals per server and the 20 most recent ask / block / warn entries. */
export function ledgerSummary(opts: { server?: string; sinceDays?: number; now?: Date } = {}): LedgerSummary {
  const sinceDays = opts.sinceDays ?? 7;
  const entries = readLedger(sinceDays * 86_400_000, opts.now ?? new Date()).filter((e) => opts.server === undefined || e.server === opts.server);
  const totals = zeroTotals();
  const per = new Map<string, LedgerTotals>();
  for (const e of entries) {
    if (!(DECISIONS as readonly string[]).includes(e.decision)) continue;
    totals[e.decision]++;
    const key = typeof e.server === "string" ? e.server : "";
    let t = per.get(key);
    if (!t) per.set(key, (t = zeroTotals()));
    t[e.decision]++;
  }
  const recent = entries
    .filter((e) => e.decision === "ask" || e.decision === "block" || e.decision === "warn")
    .reverse()
    .slice(0, 20);
  const perServer = [...per.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([server, t]) => ({ server, ...t }));
  const out: LedgerSummary = { sinceDays, totals, perServer, recent };
  if (opts.server !== undefined) out.server = opts.server;
  return out;
}

/** Entries with ts within the last `sinceMs` milliseconds, oldest first. */
export function readLedger(sinceMs: number, now = new Date()): LedgerEntry[] {
  const since = new Date(now.getTime() - sinceMs);
  const fromDay = utcDate(since);
  let names: string[] = [];
  try {
    names = readdirSync(ledgerDir()).filter((n) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(n) && n.slice(0, 10) >= fromDay);
  } catch {
    return [];
  }
  const out: LedgerEntry[] = [];
  for (const n of names.sort()) {
    for (const e of readJsonLines<LedgerEntry>(join(ledgerDir(), n))) {
      if (typeof e.ts === "string" && e.ts >= since.toISOString()) out.push(e);
    }
  }
  return out.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
}
