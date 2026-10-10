// Version ordering used by core/vulnerable-dependency: semver (npm) and PEP 440 (PyPI).

import { describe, expect, it } from "vitest";
import { comparePep440, compareSemver, compareVersions, highest, isValidVersion, lowestAbove, parsePep440, parseSemver } from "../../src/engine/versions.js";

function expectAscending(cmp: (a: string, b: string) => number | null, list: string[]): void {
  for (let i = 0; i < list.length; i++) {
    for (let j = 0; j < list.length; j++) {
      const want = i < j ? -1 : i > j ? 1 : 0;
      expect(Math.sign(cmp(list[i]!, list[j]!) ?? Number.NaN), `${list[i]} vs ${list[j]}`).toBe(want);
    }
  }
}

describe("semver", () => {
  it("orders versions as the semver 2.0.0 specification does", () => {
    expectAscending(compareSemver, [
      "0.0.0",
      "0.9.9",
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.1",
      "1.2.0",
      "1.10.0",
      "2.0.0",
      "10.0.0",
    ]);
  });

  it("ignores build metadata and accepts a leading v", () => {
    expect(compareSemver("1.0.0+build.1", "1.0.0+build.2")).toBe(0);
    expect(compareSemver("v1.2.3", "1.2.3")).toBe(0);
  });

  it("returns null for anything that is not semver", () => {
    for (const v of ["1.2", "latest", "^1.2.3", "1.2.3.4", "01.2.3", "git+https://x", "", "1.2.3-01"]) expect(parseSemver(v), v).toBeNull();
    expect(compareSemver("1.2", "1.2.0")).toBeNull();
  });
});

describe("PEP 440", () => {
  it("orders versions as packaging does", () => {
    expectAscending(comparePep440, [
      "1.0.dev456",
      "1.0a1",
      "1.0a2.dev456",
      "1.0a12.dev456",
      "1.0a12",
      "1.0b1.dev456",
      "1.0b2",
      "1.0b2.post345.dev456",
      "1.0b2.post345",
      "1.0rc1.dev456",
      "1.0rc1",
      "1.0",
      "1.0+abc.5",
      "1.0+abc.7",
      "1.0+5",
      "1.0.post456.dev34",
      "1.0.post456",
      "1.0.15",
      "1.1.dev1",
      "2!0.1",
    ]);
  });

  it("normalises equivalent spellings", () => {
    const same: [string, string][] = [
      ["1.0", "1.0.0"],
      ["1.0", "1"],
      ["1.0a1", "1.0.alpha1"],
      ["1.0a1", "1.0-a-1"],
      ["1.0b2", "1.0beta2"],
      ["1.0rc1", "1.0c1"],
      ["1.0rc1", "1.0.pre1"],
      ["1.0.post1", "1.0-1"],
      ["1.0.post1", "1.0.rev1"],
      ["1.0.post0", "1.0.post"],
      ["1.0.dev0", "1.0.dev"],
      ["v1.0", "1.0"],
      ["1.0RC1", "1.0rc1"],
      ["2024.8.30", "2024.08.30"],
    ];
    for (const [a, b] of same) expect(comparePep440(a, b), `${a} == ${b}`).toBe(0);
  });

  it("rejects invalid versions", () => {
    for (const v of ["", "abc", "1..0", "1.0+", "==1.0", "1.0-"]) expect(parsePep440(v), v).toBeNull();
  });
});

describe("helpers", () => {
  it("lowestAbove picks the lowest candidate strictly above the current version", () => {
    expect(lowestAbove("npm", "2.0.5", ["1.2.5", "2.1.3", "3.0.0"])).toBe("2.1.3");
    expect(lowestAbove("npm", "1.1.0", ["2.1.3", "1.2.5"])).toBe("1.2.5");
    expect(lowestAbove("npm", "4.17.21", ["4.17.21", "4.17.19"])).toBeNull();
    expect(lowestAbove("npm", "not-a-version", ["1.0.0"])).toBeNull();
    expect(lowestAbove("PyPI", "2.11.2", ["2.11.3", "3.0.0a1", "2.10"])).toBe("2.11.3");
    expect(lowestAbove("PyPI", "1.0", ["1.0.post1", "1.0.1"])).toBe("1.0.post1");
  });

  it("highest ignores unparseable versions", () => {
    expect(highest("npm", ["1.2.0", "junk", "1.10.0", "1.9.9"])).toBe("1.10.0");
    expect(highest("PyPI", [])).toBeNull();
  });

  it("dispatches by ecosystem", () => {
    expect(compareVersions("npm", "1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(compareVersions("PyPI", "1.0rc1", "1.0")).toBe(-1);
    expect(isValidVersion("npm", "1.0")).toBe(false);
    expect(isValidVersion("PyPI", "1.0")).toBe(true);
  });
});
