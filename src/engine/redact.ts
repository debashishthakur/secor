// Redaction (spec section 8.6). Every output path (CLI text, JSON, MCP results, ledger, dashboard)
// passes through this module. Redact first, then flatten to one line, then truncate.

import type { DetectorMatch } from "./detectors/common.js";
import { detectCredentials } from "./detectors/credentials.js";
import { detectPersonalData } from "./detectors/personal-data.js";
import { detectSecrets } from "./detectors/secrets.js";

export const EVIDENCE_MAX = 200;

export function redactSecretValue(value: string, prefix?: string): string {
  if (value.length < 12) return "[REDACTED]";
  const head = prefix && value.startsWith(prefix) ? prefix : value.slice(0, 2);
  return `${head}…${value.slice(-4)}`;
}

function redactedForm(m: DetectorMatch): string {
  switch (m.class) {
    case "secret":
      return redactSecretValue(m.value, m.prefix);
    case "credential":
      return "[REDACTED]";
    case "personal_data": {
      const digits = m.value.replace(/\D/g, "");
      if (m.kind === "email") {
        const at = m.value.indexOf("@");
        return `${m.value[0]}***@${m.value.slice(at + 1)}`;
      }
      if (m.kind === "phone") return `[PHONE …${digits.slice(-2)}]`;
      if (m.kind === "card") return `[CARD …${digits.slice(-4)}]`;
      if (m.kind === "iban") return `[IBAN …${m.value.slice(-4)}]`;
      return "[REDACTED]";
    }
    case "confidential":
      return "[CONFIDENTIAL]";
  }
}

/**
 * Replace every secret, credential and personal-data value in `text` with its redacted form.
 * Two passes: secrets and credentials (plus caller-supplied matches on the original text) first, then personal
 * data on the result, so a DB password followed by "@host.tld" is redacted as a password, never shown in email form.
 */
export function redact(text: string, extra: DetectorMatch[] = []): string {
  if (!text) return text;
  const opts = { configLike: true };
  const first = applySpans(text, [...detectSecrets(text, opts), ...detectCredentials(text, opts), ...extra]);
  return applySpans(first, detectPersonalData(first));
}

/** Replace the value part of each match, right to left. Overlapping spans merge into the earlier-listed (stronger) one. */
function applySpans(text: string, matches: DetectorMatch[]): string {
  if (matches.length === 0) return text;
  const spans = matches.map((m, i) => ({ start: m.start + m.valueStart, end: m.start + m.valueStart + m.value.length, repl: redactedForm(m), order: i }));
  const kept: typeof spans = [];
  for (const s of spans.sort((a, b) => a.order - b.order)) {
    const hit = kept.find((k) => s.start < k.end && k.start < s.end);
    if (hit) {
      if (s.start < hit.start) hit.start = s.start;
      if (s.end > hit.end) hit.end = s.end;
      continue;
    }
    kept.push({ ...s });
  }
  kept.sort((a, b) => a.start - b.start);
  let out = text;
  for (let i = kept.length - 1; i >= 0; i--) {
    const s = kept[i]!;
    out = out.slice(0, s.start) + s.repl + out.slice(s.end);
  }
  return out;
}

/** One-line, redacted, truncated evidence (≤ 200 chars). */
export function evidence(text: string, max = EVIDENCE_MAX): string {
  const oneLine = redact(text).replace(/\r\n|\r|\n/g, "⏎");
  const chars = [...oneLine];
  if (chars.length <= max) return oneLine;
  return `${chars.slice(0, max - 1).join("")}…`;
}

/** Deep-redact every string in a JSON-like value. The final safety net on every output path. */
export function redactDeep<T>(value: T): T {
  if (typeof value === "string") return redact(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    // defineProperty keeps a "__proto__" key from untrusted JSON as an ordinary own property.
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) Object.defineProperty(out, k, { value: redactDeep(v), enumerable: true, writable: true, configurable: true });
    return out as T;
  }
  return value;
}
