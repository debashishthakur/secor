import type { DataClass, Severity } from "../../types.js";

export interface DetectorMatch {
  class: DataClass;
  /** Detector kind, e.g. "openai-key", "email", "db-url". */
  kind: string;
  /** Human label for messages, e.g. "OpenAI key". Never contains the value. */
  label: string;
  start: number;
  end: number;
  /** The sensitive value itself (used for anchors and redaction, never printed). */
  value: string;
  /** Offset of `value` inside the match span (for keyed matches the span covers the key too). */
  valueStart: number;
  severity?: Severity;
  /** Known prefix kept by redaction (section 8.6). */
  prefix?: string;
}

export interface DetectOptions {
  /** Allow unquoted `KEY=value` / `key: value` lines (dotenv, YAML, INI). Code files require quotes. */
  configLike?: boolean;
}

/** Placeholders, never findings (section 9.5.1). */
// Beyond the spec's list: `env(NAME)` (Supabase config.toml) and elided values ("abc...", "abc…") — DECISIONS.md.
const PLACEHOLDER = /your|example|changeme|xxx|dummy|<[^>]*>|\$\{[^}]*\}|process\.env|os\.environ|import\.meta\.env|\benv\(|\.\.\.|…/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value);
}

export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const len = [...value].length;
  let h = 0;
  for (const n of counts.values()) {
    const p = n / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Quoted `key = "value"` / `key: 'value'` / `"key": "value"` assignments. Starts only at token boundaries (linear time). */
export const KEYED_QUOTED =
  /(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,128})["']?[ \t]*[:=][ \t]*(?:"((?:[^"\\\n]|\\.){1,1000})"|'((?:[^'\\\n]|\\.){1,1000})'|`([^`\n]{1,1000})`)/g;

/** Unquoted `KEY=value` / `key: value` lines in config-like files. */
export const KEYED_LINE = /^[ \t]*(?:export[ \t]+)?([A-Za-z0-9_.-]{1,128})[ \t]*[:=][ \t]*([^\s"'`#][^\s#]{0,1000})[ \t]*(?:#.*)?$/gm;

export interface KeyedValue {
  key: string;
  value: string;
  start: number;
  end: number;
  valueStart: number;
}

export function* keyedValues(text: string, opts: DetectOptions): Generator<KeyedValue> {
  KEYED_QUOTED.lastIndex = 0;
  for (let m = KEYED_QUOTED.exec(text); m; m = KEYED_QUOTED.exec(text)) {
    const value = m[2] ?? m[3] ?? m[4] ?? "";
    const valueStart = m.index + m[0].lastIndexOf(value);
    yield { key: m[1]!, value, start: m.index, end: m.index + m[0].length, valueStart: valueStart - m.index };
  }
  if (opts.configLike) {
    KEYED_LINE.lastIndex = 0;
    for (let m = KEYED_LINE.exec(text); m; m = KEYED_LINE.exec(text)) {
      const value = m[2]!;
      const valueStart = m.index + m[0].indexOf(value, m[0].indexOf(m[1]!) + m[1]!.length);
      yield { key: m[1]!, value, start: m.index, end: m.index + m[0].length, valueStart: valueStart - m.index };
    }
  }
}

export function looksLikeUrlOrPath(value: string): boolean {
  return /^(?:[a-z][a-z0-9+.-]*:\/\/|\/|\.\.?\/|~\/)/i.test(value) || value.includes("://");
}

/** Remove overlapping matches, keeping the earliest-listed detector's match (callers list in priority order). */
export function dropOverlaps(matches: DetectorMatch[]): DetectorMatch[] {
  const kept: DetectorMatch[] = [];
  for (const m of matches) {
    if (kept.some((k) => m.start < k.end && k.start < m.end)) continue;
    kept.push(m);
  }
  return kept.sort((a, b) => a.start - b.start || a.end - b.end);
}
