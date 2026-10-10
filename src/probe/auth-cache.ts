// Verification cache (spec 9A.2): ~/.secor/probe-auth.json, mode 0600, 24h, keyed by origin + method.
// A valid entry lets a run skip re-doing the ownership proof; the re-resolve/pin guard still runs at
// connection time.

import { join } from "node:path";
import { readJsonFile, writeFileAtomic } from "../engine/util/fsx.js";
import { secorHome } from "../engine/util/paths.js";
import type { VerifyMethod } from "./types.js";

export const AUTH_TTL_MS = 24 * 60 * 60 * 1000;

interface AuthEntry {
  origin: string;
  method: VerifyMethod;
  verifiedAt: number;
}

interface AuthFile {
  version: 1;
  entries: AuthEntry[];
}

function authPath(): string {
  return join(secorHome(), "probe-auth.json");
}

function load(): AuthFile {
  const f = readJsonFile<AuthFile>(authPath());
  return f && Array.isArray(f.entries) ? f : { version: 1, entries: [] };
}

function key(origin: string, method: VerifyMethod): string {
  return `${origin}\u0000${method}`;
}

/** A still-valid cached verification for this origin+method, if any. */
export function getCachedAuth(origin: string, method: VerifyMethod, now = Date.now()): AuthEntry | null {
  const entry = load().entries.find((e) => key(e.origin, e.method) === key(origin, method));
  if (!entry) return null;
  return now - entry.verifiedAt < AUTH_TTL_MS ? entry : null;
}

/** Any still-valid cached verification for this origin, regardless of method (for a run without --verify-method). */
export function getAnyCachedAuth(origin: string, now = Date.now()): AuthEntry | null {
  const valid = load().entries.filter((e) => e.origin === origin && now - e.verifiedAt < AUTH_TTL_MS);
  return valid.sort((a, b) => b.verifiedAt - a.verifiedAt)[0] ?? null;
}

export function cacheAuth(origin: string, method: VerifyMethod, now = Date.now()): void {
  const file = load();
  file.entries = file.entries.filter((e) => key(e.origin, e.method) !== key(origin, method) && now - e.verifiedAt < AUTH_TTL_MS);
  file.entries.push({ origin, method, verifiedAt: now });
  writeFileAtomic(authPath(), `${JSON.stringify(file, null, 2)}\n`, 0o600);
}
