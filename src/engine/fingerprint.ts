// Fingerprints (spec section 9.5.6): NFKC + lowercase + whitespace collapse, 32-character k-grams
// hashed with 64-bit FNV-1a over UTF-8, winnowed with a window of 16 (rightmost minimum on ties).

export const K = 32;
export const WINDOW = 16;

export function normaliseForFingerprint(text: string): string {
  return text.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
}

const encoder = new TextEncoder();

function hex(n: number): string {
  return n.toString(16).padStart(8, "0");
}

export function fingerprints(text: string): string[] {
  const norm = normaliseForFingerprint(text);
  const chars = Array.from(norm);
  if (chars.length < K) return [];
  const bytes = chars.map((c) => encoder.encode(c));
  const hashes: string[] = [];
  for (let i = 0; i + K <= chars.length; i++) hashes.push(fnv64(bytes, i, K));
  return winnow(hashes);
}

/**
 * 64-bit FNV-1a over the UTF-8 bytes of characters [start, start+len), as 16 hex digits.
 * Uses two 32-bit halves instead of BigInt: (hi:lo) * 0x100000001b3 mod 2^64 = (hi:lo) * 0x1b3 + (lo << 40).
 */
export function fnv64(bytes: Uint8Array[], start: number, len: number): string {
  let hi = 0xcbf29ce4;
  let lo = 0x84222325;
  for (let c = start; c < start + len; c++) {
    const arr = bytes[c]!;
    for (let i = 0; i < arr.length; i++) {
      lo = (lo ^ arr[i]!) >>> 0;
      const t = lo * 0x1b3;
      const carry = Math.floor(t / 0x100000000);
      const newHi = (Math.imul(hi, 0x1b3) + carry + (lo << 8)) >>> 0;
      lo = t >>> 0;
      hi = newHi;
    }
  }
  return hex(hi) + hex(lo);
}

export function fnv1a64Hex(text: string): string {
  return fnv64([encoder.encode(text)], 0, 1);
}

/** Winnowing: minimum of each window of WINDOW hashes, rightmost on ties, deduplicated (first-seen order). */
export function winnow(hashes: string[]): string[] {
  if (hashes.length === 0) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (h: string) => {
    if (!seen.has(h)) {
      seen.add(h);
      out.push(h);
    }
  };
  if (hashes.length <= WINDOW) {
    let min = 0;
    for (let i = 0; i < hashes.length; i++) if (hashes[i]! <= hashes[min]!) min = i;
    add(hashes[min]!);
    return out;
  }
  for (let start = 0; start + WINDOW <= hashes.length; start++) {
    let min = start;
    for (let i = start; i < start + WINDOW; i++) if (hashes[i]! <= hashes[min]!) min = i;
    add(hashes[min]!);
  }
  return out;
}

/** Number of fingerprints shared between two sets. */
export function sharedCount(a: readonly string[], b: ReadonlySet<string>): number {
  let n = 0;
  for (const h of new Set(a)) if (b.has(h)) n++;
  return n;
}
