// ship_verify coverage merge: a verify run keeps the previous run's coverage for rules it did not re-run.

import { describe, expect, it } from "vitest";
import { mergeVerifyCoverage } from "../../src/mcp/verify.js";
import { finding, runResult } from "./synthetic.js";

const ALWAYS = [
  { area: "Running deployment", reason: "SECOR v1 reads files only" },
  { area: "Containers", reason: "not supported in v1" },
  { area: "Cloud accounts", reason: "not supported in v1" },
];

describe("mergeVerifyCoverage", () => {
  const previous = runResult({
    coverage: {
      applicable: 10,
      ran: 8,
      percent: 80,
      notChecked: [{ area: "Hallucinated package", reason: "network disabled (offline mode)" }, { area: "Git history", reason: "git not available" }, { area: "Rule A", reason: "old reason" }, ...ALWAYS],
    },
  });

  it("replaces only the re-run rules' share: a verify of one rule keeps the other gaps", () => {
    const verify = runResult({
      findings: [finding({ severity: "high" })],
      coverage: { applicable: 1, ran: 1, percent: 100, notChecked: [...ALWAYS] },
      score: { scoringVersion: 1, overall: 79, band: "needs-work", ship: 79, shipByKind: { api: 79, mcp: null, web: null }, connect: null, incomplete: false },
    });
    const merged = mergeVerifyCoverage(previous, verify, [{ id: "api/rule-b", title: "Rule B" }]);
    expect(merged.coverage.applicable).toBe(10);
    expect(merged.coverage.ran).toBe(8);
    expect(merged.coverage.percent).toBe(80);
    expect(merged.coverage.notChecked.map((n) => n.area)).toEqual(["Hallucinated package", "Git history", "Rule A", "Running deployment", "Containers", "Cloud accounts"]);
  });

  it("a re-run rule that ran before (it had findings) and now cannot run lowers coverage", () => {
    const ranBefore = runResult({
      findings: [finding({ ruleId: "api/rule-a" })],
      coverage: { applicable: 10, ran: 8, percent: 80, notChecked: [{ area: "Git history", reason: "git not available" }, ...ALWAYS] },
    });
    const verify = runResult({ coverage: { applicable: 1, ran: 0, percent: 0, notChecked: [{ area: "Rule A", reason: "internal error" }, ...ALWAYS] } });
    const merged = mergeVerifyCoverage(ranBefore, verify, [{ id: "api/rule-a", title: "Rule A" }]);
    expect(merged.coverage).toMatchObject({ applicable: 10, ran: 7, percent: 70 });
    expect(merged.coverage.notChecked.filter((n) => n.area === "Rule A")).toEqual([{ area: "Rule A", reason: "internal error" }]);
  });

  it("a re-run rule listed as not checked before, which now runs, raises coverage and drops the stale entry", () => {
    const verify = runResult({ coverage: { applicable: 1, ran: 1, percent: 100, notChecked: [...ALWAYS] } });
    const merged = mergeVerifyCoverage(previous, verify, [{ id: "api/rule-a", title: "Rule A" }]);
    expect(merged.coverage).toMatchObject({ applicable: 10, ran: 9, percent: 90 });
    expect(merged.coverage.notChecked.some((n) => n.area === "Rule A")).toBe(false);
  });

  it("a re-run rule that no longer applies leaves the count", () => {
    const verify = runResult({ coverage: { applicable: 0, ran: 0, percent: 100, notChecked: [...ALWAYS] } });
    expect(mergeVerifyCoverage(previous, verify, [{ id: "api/rule-b", title: "Rule B" }]).coverage).toMatchObject({ applicable: 9, ran: 7, percent: 78 });
  });

  it("recomputes the score, including the incomplete flag, from the merged coverage", () => {
    const low = runResult({ coverage: { applicable: 10, ran: 5, percent: 50, notChecked: [...ALWAYS] } });
    const verify = runResult({
      coverage: { applicable: 1, ran: 1, percent: 100, notChecked: [...ALWAYS] },
      score: { scoringVersion: 1, overall: 100, band: "no-known-critical-or-high", ship: 100, shipByKind: { api: 100, mcp: null, web: null }, connect: 90, incomplete: false },
    });
    const merged = mergeVerifyCoverage(low, verify, [{ id: "api/rule-b", title: "Rule B" }]);
    expect(merged.coverage.percent).toBe(50);
    expect(merged.score.incomplete).toBe(true);
    expect(merged.score.connect).toBe(90);
    expect(merged.score.overall).toBe(90);
  });
});
