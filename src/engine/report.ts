// Run results on disk (spec sections 5.4 and 8.1 step 8): .secor/runs/<runId>.json, .secor/latest.json,
// .secor/history.jsonl, and .secor/.gitignore.

import { existsSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { RunResult } from "../types.js";
import { redactDeep } from "./redact.js";
import { appendLine, ensureDir, readJsonFile, readJsonLines, writeFileAtomic } from "./util/fsx.js";

export interface HistoryLine {
  runId: string;
  finishedAt: string;
  overall: number | null;
  ship: number | null;
  connect: number | null;
  coverage: number;
}

export const SECOR_GITIGNORE = "runs/\nlatest.json\nhistory.jsonl\n";

export function secorDir(root: string): string {
  return join(root, ".secor");
}

const reserved = new Set<string>();

/** UTC timestamp YYYYMMDDTHHMMSSZ, plus -2, -3, ... if it collides with an existing or reserved run. */
export function newRunId(root: string, at: Date): string {
  const base = at.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const runsDir = join(secorDir(root), "runs");
  const taken = (id: string) => reserved.has(`${root}\u0000${id}`) || existsSync(join(runsDir, `${id}.json`));
  let id = base;
  for (let n = 2; taken(id); n++) id = `${base}-${n}`;
  reserved.add(`${root}\u0000${id}`);
  return id;
}

export function ensureSecorDir(root: string): void {
  const dir = secorDir(root);
  ensureDir(join(dir, "runs"), 0o755);
  const gi = join(dir, ".gitignore");
  if (!existsSync(gi)) writeFileSync(gi, SECOR_GITIGNORE, { mode: 0o644 });
}

/** Write a completed run. The result is deep-redacted first (invariant 4). */
export function writeRun(root: string, result: RunResult): RunResult {
  const safe = redactDeep(result);
  ensureSecorDir(root);
  const text = `${JSON.stringify(safe, null, 2)}\n`;
  writeFileAtomic(join(secorDir(root), "runs", `${safe.runId}.json`), text, 0o644);
  writeFileAtomic(join(secorDir(root), "latest.json"), text, 0o644);
  const line: HistoryLine = {
    runId: safe.runId,
    finishedAt: safe.finishedAt,
    overall: safe.score.overall,
    ship: safe.score.ship,
    connect: safe.score.connect,
    coverage: safe.coverage.percent,
  };
  appendLine(join(secorDir(root), "history.jsonl"), JSON.stringify(line), 0o644);
  return safe;
}

export function readLatest(root: string): RunResult | null {
  try {
    return readJsonFile<RunResult>(join(secorDir(root), "latest.json"));
  } catch {
    return null;
  }
}

export function readRun(root: string, runId: string): RunResult | null {
  if (!/^\d{8}T\d{6}Z(?:-\d+)?$/.test(runId)) return null;
  try {
    return readJsonFile<RunResult>(join(secorDir(root), "runs", `${runId}.json`));
  } catch {
    return null;
  }
}

export function readHistory(root: string): HistoryLine[] {
  return readJsonLines<HistoryLine>(join(secorDir(root), "history.jsonl"));
}

export function listRunIds(root: string): string[] {
  try {
    return readdirSync(join(secorDir(root), "runs"))
      .filter((n) => n.endsWith(".json"))
      .map((n) => n.slice(0, -5))
      .sort();
  } catch {
    return [];
  }
}
