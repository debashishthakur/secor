// ship_verify coverage (spec sections 8.7, 10 and 11.2). runShip({onlyRules}) measures coverage over the re-run rules
// alone, so a verify run of one rule would report 1 of 1 checks and drop every other not-checked entry. A verify run
// must not look more complete than the check it verifies: its coverage is merged with the previous run's and the
// score (which carries the `incomplete` flag) is recomputed before the run is written.

import { buildCoverage } from "../engine/runner.js";
import { computeScore } from "../engine/score.js";
import type { RunResult } from "../types.js";

export interface RerunRule {
  id: string;
  title: string;
}

/**
 * Each re-run rule's share of the previous coverage is replaced by the verify run's. A rule with findings in
 * `previous` was applicable there and ran (the usual case: ship_verify takes findings of the latest run). A rule
 * listed by title as not checked was applicable but did not run. Any other rule most likely ran without findings.
 * Not-checked entries named after a re-run rule are dropped from the old list because the verify run reports them
 * afresh; every other old entry is kept.
 */
export function mergeVerifyCoverage(previous: RunResult, verify: RunResult, rerun: readonly RerunRule[]): RunResult {
  const withFindings = new Set(previous.findings.map((f) => f.ruleId));
  const notRun = new Set(previous.coverage.notChecked.map((n) => n.area));
  let applicable = previous.coverage.applicable;
  let ran = previous.coverage.ran;
  for (const r of new Map(rerun.map((x) => [x.id, x])).values()) {
    applicable -= 1;
    if (withFindings.has(r.id) || !notRun.has(r.title)) ran -= 1;
  }
  const titles = new Set(rerun.map((r) => r.title));
  const kept = previous.coverage.notChecked.filter((e) => !titles.has(e.area));
  const coverage = buildCoverage(Math.max(0, applicable) + verify.coverage.applicable, Math.max(0, ran) + verify.coverage.ran, [...kept, ...verify.coverage.notChecked]);
  const score = computeScore(verify.findings, verify.units, coverage.percent, verify.score.connect);
  return { ...verify, coverage, score };
}
