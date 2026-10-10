// Fingerprints for the hook hot path (spec 9.5.6), bit-identical to src/engine/fingerprint.ts `fingerprints()`:
// NFKC + lowercase + whitespace collapse + trim; 32-code-point k-grams hashed with 64-bit FNV-1a over UTF-8;
// winnowing with a window of 16, rightmost minimum on ties, deduplicated in first-seen order.
//
// The engine version allocates a byte array per character and a hex string per k-gram; this one encodes the text
// once and compares hashes as numbers, which keeps the hooks inside the 50 ms p99 budget. A test asserts both
// functions return the same fingerprints.

import { normaliseForFingerprint } from "../engine/fingerprint.js";

const K = 32;
const WINDOW = 16;
const encoder = new TextEncoder();

function hex8(n: number): string {
  return n.toString(16).padStart(8, "0");
}

export function fingerprintsFast(text: string): string[] {
  const norm = normaliseForFingerprint(text);
  // Byte offset of each code point in the UTF-8 encoding (TextEncoder writes a lone surrogate as 3 bytes, U+FFFD).
  const offsets: number[] = [];
  let off = 0;
  for (let i = 0; i < norm.length; ) {
    const cp = norm.codePointAt(i)!;
    offsets.push(off);
    off += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    i += cp > 0xffff ? 2 : 1;
  }
  const count = offsets.length;
  if (count < K) return [];
  offsets.push(off);
  const bytes = encoder.encode(norm);
  const n = count - K + 1;
  const his = new Uint32Array(n);
  const los = new Uint32Array(n);
  for (let s = 0; s < n; s++) {
    let hi = 0xcbf29ce4;
    let lo = 0x84222325;
    const end = offsets[s + K]!;
    for (let b = offsets[s]!; b < end; b++) {
      lo = (lo ^ bytes[b]!) >>> 0;
      const t = lo * 0x1b3;
      const carry = Math.floor(t / 0x100000000);
      const newHi = (Math.imul(hi, 0x1b3) + carry + (lo << 8)) >>> 0;
      lo = t >>> 0;
      hi = newHi;
    }
    his[s] = hi;
    los[s] = lo;
  }
  // a <= b on (hi, lo), i.e. the engine's comparison of fixed-width hex strings.
  const le = (a: number, b: number) => his[a]! < his[b]! || (his[a] === his[b] && los[a]! <= los[b]!);
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (i: number) => {
    const h = hex8(his[i]!) + hex8(los[i]!);
    if (!seen.has(h)) {
      seen.add(h);
      out.push(h);
    }
  };
  if (n <= WINDOW) {
    let min = 0;
    for (let i = 0; i < n; i++) if (le(i, min)) min = i;
    add(min);
    return out;
  }
  let last = -1;
  for (let start = 0; start + WINDOW <= n; start++) {
    let min = start;
    for (let i = start; i < start + WINDOW; i++) if (le(i, min)) min = i;
    // The same position as the previous window's minimum is the same hash: already added.
    if (min !== last) add(min);
    last = min;
  }
  return out;
}
