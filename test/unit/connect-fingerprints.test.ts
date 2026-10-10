// Fingerprints on the hook path (spec 9.5.6): the fast implementation equals the engine's, and the session store
// enforces its cap, its 24-hour retention (checked at most once per hour) and safe file names.

import { existsSync, mkdirSync, readdirSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fingerprintsFast } from "../../src/connect/fingerprint-fast.js";
import { addToStore, cleanupStore, FP_CAP, fingerprintsDir, readStore, sessionFileName, storeBySource } from "../../src/connect/fpstore.js";
import { fingerprints } from "../../src/engine/fingerprint.js";
import { type TempEnv, tempEnv } from "../connect/helpers.js";

function prng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 4294967296;
  };
}

const ALPHABETS = [
  "abcdefghijklmnopqrstuvwxyz     ",
  "ABCDEFabcdef0123456789 \n\t.,;-",
  "éèàçßÆØåñü İıǅ ﬁ ① ｆｕｌｌ ",
  "日本語のテキスト 中文 한국어 ",
  "😀🚀👍🏽 a b c 𝔘𝔫𝔦𝔠𝔬𝔡𝔢",
  "\uD800x\uDC00y ​z w",
];

function randomText(r: () => number, len: number): string {
  const alpha = Array.from(ALPHABETS[Math.floor(r() * ALPHABETS.length)]!);
  let out = "";
  while (out.length < len) out += alpha[Math.floor(r() * alpha.length)];
  return out;
}

describe("fingerprintsFast", () => {
  it("returns exactly the engine's fingerprints", () => {
    const r = prng(42);
    const lengths = [0, 10, 31, 32, 33, 40, 47, 48, 49, 64, 100, 257, 1000, 5000];
    for (let i = 0; i < 400; i++) {
      const len = i < lengths.length * 6 ? lengths[i % lengths.length]! : Math.floor(r() * 3000);
      const text = randomText(r, len);
      expect(fingerprintsFast(text), JSON.stringify(text.slice(0, 40))).toEqual(fingerprints(text));
    }
  });

  it("is much faster on 20,000 characters", () => {
    const text = randomText(prng(7), 20_000);
    const time = (f: () => unknown) => {
      const t0 = performance.now();
      for (let i = 0; i < 5; i++) f();
      return (performance.now() - t0) / 5;
    };
    time(() => fingerprintsFast(text));
    const fast = time(() => fingerprintsFast(text));
    const slow = time(() => fingerprints(text));
    console.log(`fingerprints of 20k chars: fast ${fast.toFixed(2)} ms, engine ${slow.toFixed(2)} ms`);
    expect(fast).toBeLessThan(slow);
  });
});

let env: TempEnv;
beforeEach(() => {
  env = tempEnv();
});
afterEach(() => env.restore());

describe("session fingerprint store", () => {
  it("uses plain session ids as file names and hashes anything else", () => {
    expect(sessionFileName("4f6c2a1e-1234-abcd")).toBe("4f6c2a1e-1234-abcd.jsonl");
    for (const bad of ["../../etc/passwd", "a/b", "x".repeat(129), "", "sess.1", "nul\u0000"]) {
      const name = sessionFileName(bad);
      expect(name, bad).toMatch(/^s-[0-9a-f]{32}\.jsonl$/);
    }
    expect(sessionFileName("a/b")).not.toBe(sessionFileName("a_b"));
  });

  it("stores {source, fps} lines and merges them by source", () => {
    addToStore("s1", "github", ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"]);
    addToStore("s1", "file:/x", ["cccccccccccccccc"]);
    addToStore("s1", "github", ["dddddddddddddddd"]);
    addToStore("s1", "github", []);
    expect(readStore("s1")).toEqual([
      { source: "github", fps: ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"] },
      { source: "file:/x", fps: ["cccccccccccccccc"] },
      { source: "github", fps: ["dddddddddddddddd"] },
    ]);
    const by = storeBySource("s1");
    expect([...by.get("github")!]).toEqual(["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "dddddddddddddddd"]);
    expect(readStore("other")).toEqual([]);
  });

  it(`caps a session at ${FP_CAP} fingerprints, dropping the oldest lines first`, () => {
    const batch = (tag: string, n: number) => Array.from({ length: n }, (_, i) => `${tag}${String(i).padStart(15, "0")}`.slice(0, 16));
    addToStore("cap", "one", batch("a", 20_000));
    addToStore("cap", "two", batch("b", 20_000));
    addToStore("cap", "three", batch("c", 20_000));
    const lines = readStore("cap");
    expect(lines.map((l) => l.source)).toEqual(["two", "three"]);
    expect(lines.reduce((n, l) => n + l.fps.length, 0)).toBeLessThanOrEqual(FP_CAP);
    addToStore("cap", "huge", batch("d", 60_000));
    const after = readStore("cap");
    expect(after.map((l) => l.source)).toEqual(["huge"]);
    expect(after[0]!.fps).toHaveLength(FP_CAP);
  });

  it("deletes session files older than 24 hours, at most once per hour", () => {
    const dir = fingerprintsDir();
    mkdirSync(dir, { recursive: true });
    const now = new Date("2026-10-10T12:00:00Z");
    const old = new Date(now.getTime() - 25 * 3_600_000);
    const fresh = new Date(now.getTime() - 2 * 3_600_000);
    writeFileSync(join(dir, "old.jsonl"), "");
    writeFileSync(join(dir, "fresh.jsonl"), "");
    utimesSync(join(dir, "old.jsonl"), old, old);
    utimesSync(join(dir, "fresh.jsonl"), fresh, fresh);
    cleanupStore(now);
    expect(readdirSync(dir).sort()).toEqual([".last-cleanup", "fresh.jsonl"]);
    writeFileSync(join(dir, "old2.jsonl"), "");
    utimesSync(join(dir, "old2.jsonl"), old, old);
    cleanupStore(new Date(now.getTime() + 30 * 60_000)); // within the hour: skipped
    expect(existsSync(join(dir, "old2.jsonl"))).toBe(true);
    cleanupStore(new Date(now.getTime() + 61 * 60_000));
    expect(existsSync(join(dir, "old2.jsonl"))).toBe(false);
    expect(readFileSync(join(dir, ".last-cleanup"), "utf8")).toMatch(/^2026-10-10T13:01:00/);
  });
});
