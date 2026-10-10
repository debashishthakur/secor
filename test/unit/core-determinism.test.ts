// Spec 14.1 determinism for the core pack: running Ship twice on every core fixture gives identical findings,
// IDs, ordering, coverage and score (only runId, startedAt, finishedAt and the temp project path may differ).

import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { RunResult } from "../../src/types.js";
import { FIXTURES, cleanup, listCases, runCase } from "../helpers/fixtures.js";

const temp: string[] = [];
afterAll(() => temp.forEach(cleanup));

function stable(r: RunResult): unknown {
  return { findings: r.findings, coverage: r.coverage, score: r.score, units: r.units, inventory: r.inventory };
}

describe("core pack determinism", () => {
  const cases = listCases(join(FIXTURES, "core"));
  it("has core fixture cases", () => expect(cases.length).toBeGreaterThan(40));
  for (const c of cases) {
    it(c.name, async () => {
      const a = await runCase(c);
      const b = await runCase(c);
      temp.push(a.root, b.root);
      expect(stable(b.result)).toEqual(stable(a.result));
    });
  }
});
