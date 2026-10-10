// Fingerprints (spec 9.5.6).

import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../src/engine/util/hash.js";
import { K, WINDOW, fingerprints, fnv1a64Hex, normaliseForFingerprint, sharedCount, winnow } from "../../src/engine/fingerprint.js";

describe("FNV-1a 64", () => {
  it("matches the reference test vectors", () => {
    expect(fnv1a64Hex("")).toBe("cbf29ce484222325");
    expect(fnv1a64Hex("a")).toBe("af63dc4c8601ec8c");
    expect(fnv1a64Hex("foobar")).toBe("85944171f73967e8");
  });

  it("hashes UTF-8 bytes (multi-byte characters)", () => {
    // reference computed with BigInt
    const ref = (s: string) => {
      let h = 0xcbf29ce484222325n;
      for (const b of new TextEncoder().encode(s)) {
        h ^= BigInt(b);
        h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
      }
      return h.toString(16).padStart(16, "0");
    };
    for (const s of ["é", "naïve café", "日本語テキスト", "🙂 emoji", "x".repeat(100)]) expect(fnv1a64Hex(s), s).toBe(ref(s));
  });
});

describe("normalisation and winnowing", () => {
  it("NFKC, lowercase, collapses whitespace, trims", () => {
    expect(normaliseForFingerprint("  Ｈello\n\tWORLD  ")).toBe("hello world");
  });

  it("text under 32 characters gets no fingerprints", () => {
    expect(fingerprints("x".repeat(K - 1))).toEqual([]);
    expect(fingerprints("x".repeat(K)).length).toBe(1);
  });

  it("keeps the rightmost minimum per window, deduplicated", () => {
    const hashes = ["05", "03", "07", "03", "09", "08", "07", "06", "05", "04", "03", "02", "06", "07", "08", "09", "10"].map((h) => h.padStart(16, "0"));
    expect(hashes.length).toBe(WINDOW + 1);
    // window 1 (0..15): min "02" at 11; window 2 (1..16): min "02" at 11 → one fingerprint
    expect(winnow(hashes)).toEqual(["0000000000000002"]);
    expect(winnow(["0000000000000001"])).toEqual(["0000000000000001"]);
  });

  it("is deterministic and insensitive to case and spacing", () => {
    const a = fingerprints("The quick brown fox jumps over the lazy dog, again and again and again.");
    const b = fingerprints("the  QUICK brown fox jumps over the lazy dog,\nagain and again and again.");
    expect(a).toEqual(b);
  });
});

describe("flow detection thresholds", () => {
  const secretDoc = "Quarterly revenue forecast for the falcon project: 12.4M in Q3, 15.1M in Q4, hiring freeze until March, do not share outside the leadership group.";

  it("a verbatim copy shares many fingerprints", () => {
    const src = new Set(fingerprints(secretDoc));
    const outgoing = canonicalJson({ body: `FYI: ${secretDoc}` });
    expect(sharedCount(fingerprints(outgoing), src)).toBeGreaterThanOrEqual(3);
  });

  it("unrelated text shares none", () => {
    const src = new Set(fingerprints(secretDoc));
    expect(sharedCount(fingerprints("Please create an issue titled 'Fix login redirect on Safari' with label bug."), src)).toBe(0);
  });

  it("a partial quote (one sentence) still shares at least one", () => {
    const src = new Set(fingerprints(secretDoc));
    expect(sharedCount(fingerprints("12.4M in Q3, 15.1M in Q4, hiring freeze until March"), src)).toBeGreaterThanOrEqual(1);
  });
});
