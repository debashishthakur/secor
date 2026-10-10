// Session fingerprint store (spec section 9.5.6): ~/.secor/fingerprints/<sessionId>.jsonl, one line
// {source, fps: [hex…]} per added text. Holds hashes only, never text. Capped at 50,000 fingerprints per session
// (oldest lines dropped first); session files older than 24 hours are deleted at most once per hour.

import { appendFileSync, readdirSync, readFileSync, statSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureDir, writeFileAtomic } from "../engine/util/fsx.js";
import { sha256Hex } from "../engine/util/hash.js";
import { secorHome } from "../engine/util/paths.js";

export const FP_CAP = 50_000;
const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const CLEANUP_STAMP = ".last-cleanup";

export interface FpLine {
  source: string;
  fps: string[];
}

export function fingerprintsDir(): string {
  return join(secorHome(), "fingerprints");
}

/** File name for a session id: the id itself when it is a plain token, else a hash (never a path). */
export function sessionFileName(sessionId: string): string {
  return /^[A-Za-z0-9_-]{1,128}$/.test(sessionId) ? `${sessionId}.jsonl` : `s-${sha256Hex(sessionId).slice(0, 32)}.jsonl`;
}

export function sessionFile(sessionId: string): string {
  return join(fingerprintsDir(), sessionFileName(sessionId));
}

function parseLines(text: string): FpLine[] {
  const out: FpLine[] = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    try {
      const v = JSON.parse(line) as Partial<FpLine>;
      if (typeof v.source === "string" && Array.isArray(v.fps)) out.push({ source: v.source, fps: v.fps.filter((f): f is string => typeof f === "string") });
    } catch {
      // a partial last line from a crashed writer
    }
  }
  return out;
}

export function readStore(sessionId: string): FpLine[] {
  let text: string;
  try {
    text = readFileSync(sessionFile(sessionId), "utf8");
  } catch {
    return [];
  }
  return parseLines(text);
}

/** Fingerprints per source for this session. */
export function storeBySource(sessionId: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const line of readStore(sessionId)) {
    let set = out.get(line.source);
    if (!set) out.set(line.source, (set = new Set()));
    for (const f of line.fps) set.add(f);
  }
  return out;
}

/** Add one text's fingerprints under `source`, enforcing the per-session cap. */
export function addToStore(sessionId: string, source: string, fps: readonly string[], now = new Date()): void {
  if (fps.length === 0) return;
  const dir = fingerprintsDir();
  ensureDir(dir);
  cleanupStore(now);
  const file = sessionFile(sessionId);
  const fresh: FpLine = { source, fps: fps.slice(0, FP_CAP) };
  const existing = readStore(sessionId);
  let total = fresh.fps.length;
  for (const l of existing) total += l.fps.length;
  if (total <= FP_CAP) {
    appendFileSync(file, `${JSON.stringify(fresh)}\n`, { mode: 0o600 });
    return;
  }
  // Drop the oldest lines until the newest ones (plus this text) fit.
  const kept: FpLine[] = [];
  let count = fresh.fps.length;
  for (let i = existing.length - 1; i >= 0; i--) {
    const l = existing[i]!;
    if (count + l.fps.length > FP_CAP) break;
    kept.unshift(l);
    count += l.fps.length;
  }
  kept.push(fresh);
  writeFileAtomic(file, `${kept.map((l) => JSON.stringify(l)).join("\n")}\n`, 0o600);
}

/** Delete session files older than 24 hours, at most once per hour (tracked by a timestamp file). */
export function cleanupStore(now = new Date()): void {
  const dir = fingerprintsDir();
  const stamp = join(dir, CLEANUP_STAMP);
  let last = 0;
  try {
    last = statSync(stamp).mtimeMs;
  } catch {
    last = 0;
  }
  const t = now.getTime();
  if (last && t - last < HOUR_MS && last <= t) return;
  let names: string[] = [];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const n of names) {
    if (!n.endsWith(".jsonl")) continue;
    const p = join(dir, n);
    try {
      if (t - statSync(p).mtimeMs > DAY_MS) unlinkSync(p);
    } catch {
      // raced with another hook
    }
  }
  try {
    writeFileSync(stamp, `${now.toISOString()}\n`, { mode: 0o600 });
    utimesSync(stamp, now, now);
  } catch {
    // best effort
  }
}
