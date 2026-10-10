// Data-driven fixture tests for every rule (spec section 14.1): each rule MUST fire with the expected
// severity on test/fixtures/<ruleId>/vulnerable/<case> and MUST NOT fire on test/fixtures/<ruleId>/clean/<case>.

import { afterAll, describe, expect, it } from "vitest";
import { allRules } from "../src/engine/rules/index.js";
import { cleanup, compareExpect, listCases, runCase } from "./helpers/fixtures.js";

const cases = listCases();
const temp: string[] = [];
afterAll(() => temp.forEach(cleanup));

describe("rule fixtures", () => {
  it("every case names a registered rule", () => {
    const ids = new Set(allRules().map((r) => r.id));
    const unknown = cases.filter((c) => !ids.has(c.spec.rule)).map((c) => `${c.name} → ${c.spec.rule}`);
    expect(unknown).toEqual([]);
  });

  it("every registered rule has at least one vulnerable and one clean case", () => {
    const missing: string[] = [];
    for (const r of allRules()) {
      const mine = cases.filter((c) => c.spec.rule === r.id);
      if (!mine.some((c) => c.variant === "vulnerable")) missing.push(`${r.id}: no vulnerable case`);
      if (!mine.some((c) => c.variant === "clean")) missing.push(`${r.id}: no clean case`);
    }
    expect(missing).toEqual([]);
  });

  for (const c of cases) {
    it(`${c.name}`, async () => {
      const { findings, root } = await runCase(c);
      temp.push(root);
      if (c.variant === "clean") expect(c.spec.expect, "clean cases expect nothing").toEqual([]);
      expect(compareExpect(c, findings)).toBe("");
    });
  }
});
