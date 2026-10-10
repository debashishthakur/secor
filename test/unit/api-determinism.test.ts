// Spec 14.1 determinism for the api pack: running Ship twice on every api fixture with all nine api rules gives
// identical findings, IDs, ordering, coverage and score. Running every api rule on every api fixture also checks
// that no rule fails with an internal error on code written for another rule.

import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { apiRules } from "../../src/engine/rules/api/index.js";
import type { RunResult } from "../../src/types.js";
import { FIXTURES, cleanup, listCases, runFixture } from "../helpers/fixtures.js";

const temp: string[] = [];
afterAll(() => temp.forEach(cleanup));

const API_RULES = apiRules.map((r) => r.id);

function stable(r: RunResult): unknown {
  return { findings: r.findings, coverage: r.coverage, score: r.score, units: r.units, inventory: r.inventory };
}

describe("api pack determinism", () => {
  const cases = listCases(join(FIXTURES, "api"));
  it("has api fixture cases for all nine rules", () => {
    expect(API_RULES).toHaveLength(9);
    expect(new Set(cases.map((c) => c.spec.rule))).toEqual(new Set(API_RULES));
  });
  for (const c of cases) {
    it(c.name, async () => {
      const a = await runFixture(c.dir, { onlyRules: API_RULES });
      const b = await runFixture(c.dir, { onlyRules: API_RULES });
      temp.push(a.root, b.root);
      expect(stable(b.result)).toEqual(stable(a.result));
      const titles = new Set(apiRules.map((r) => r.title));
      expect(a.result.coverage.notChecked.filter((n) => titles.has(n.area))).toEqual([]);
      expect(a.result.findings.every((f) => f.maturity === "experimental" && f.service === "api")).toBe(true);
    });
  }
});
