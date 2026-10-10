// Credentials (class `credential`), spec section 9.5.2.

import { type DetectOptions, type DetectorMatch, dropOverlaps, isPlaceholder, keyedValues, looksLikeUrlOrPath } from "./common.js";

const PASSWORD_KEY = /password|passwd|pwd|passphrase/i;
const DB_URL = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\/([^:\s/@]{1,256}):([^@\s]{1,512})@([^\s/:?#"'`,;)]{1,253})/g;

function isLocalHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || !h.includes(".");
}

export function detectCredentials(text: string, opts: DetectOptions = {}): DetectorMatch[] {
  const found: DetectorMatch[] = [];
  DB_URL.lastIndex = 0;
  for (let m = DB_URL.exec(text); m; m = DB_URL.exec(text)) {
    const password = m[2]!;
    const host = m[3]!;
    if (isLocalHost(host) || isPlaceholder(password)) continue;
    const valueStart = m[0].indexOf(`:${password}@`) + 1;
    found.push({
      class: "credential",
      kind: "db-url",
      label: "Database URL with a password",
      start: m.index,
      end: m.index + m[0].length,
      value: password,
      valueStart,
    });
  }
  for (const kv of keyedValues(text, opts)) {
    if (!PASSWORD_KEY.test(kv.key)) continue;
    const v = kv.value;
    if (v.length < 8 || isPlaceholder(v) || looksLikeUrlOrPath(v)) continue;
    const start = kv.start + kv.valueStart;
    found.push({
      class: "credential",
      kind: "password-literal",
      label: `Password assigned to "${kv.key}"`,
      start,
      end: start + v.length,
      value: v,
      valueStart: 0,
    });
  }
  return dropOverlaps(found);
}
