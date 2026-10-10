// Rule runner and coverage (spec sections 8.1 step 5 and 8.7).

import type { Coverage, Finding, NotCheckedEntry, Pack } from "../types.js";
import type { ProjectContext } from "./context.js";
import { sortFindings, uniqueIds } from "./finding.js";
import { NotChecked, type Rule } from "./rules/types.js";

export const ALWAYS_NOT_CHECKED: NotCheckedEntry[] = [
  { area: "Running deployment", reason: "SECOR v1 reads files only" },
  { area: "Containers", reason: "not supported in v1" },
  { area: "Cloud accounts", reason: "not supported in v1" },
];

export interface RuleRunOutcome {
  findings: Finding[];
  applicable: number;
  ran: number;
  /** Rules that were applicable, with whether they ran. */
  rules: { id: string; ran: boolean }[];
  notChecked: NotCheckedEntry[];
}

const yieldNow = () => new Promise<void>((r) => setImmediate(r));

export async function runRules(ctx: ProjectContext, rules: readonly Rule[], only?: ReadonlySet<string>): Promise<RuleRunOutcome> {
  const findings: Finding[] = [];
  const notChecked: NotCheckedEntry[] = [];
  const ruleOutcomes: { id: string; ran: boolean }[] = [];
  let applicable = 0;
  let ran = 0;
  for (const rule of [...rules].sort((a, b) => (a.id < b.id ? -1 : 1))) {
    if (!packEnabled(ctx.packs, rule.pack)) continue;
    if (only && !only.has(rule.id)) continue;
    let applies: boolean;
    try {
      applies = rule.appliesTo(ctx);
    } catch {
      applicable++;
      notChecked.push({ area: rule.title, reason: "internal error" });
      ruleOutcomes.push({ id: rule.id, ran: false });
      continue;
    }
    if (!applies) continue;
    applicable++;
    try {
      const fs = await rule.run(ctx);
      findings.push(...uniqueIds(fs));
      ran++;
      ruleOutcomes.push({ id: rule.id, ran: true });
    } catch (e) {
      notChecked.push(e instanceof NotChecked ? { area: e.area ?? rule.title, reason: e.reason } : { area: rule.title, reason: "internal error" });
      ruleOutcomes.push({ id: rule.id, ran: false });
      if (!(e instanceof NotChecked) && process.env.SECOR_DEBUG) console.error(`[secor] rule ${rule.id} failed:`, e);
    }
    await yieldNow();
  }
  return { findings: sortFindings(findings), applicable, ran, rules: ruleOutcomes, notChecked };
}

export function packEnabled(packs: ReadonlySet<Pack>, pack: Pack): boolean {
  return pack === "core" || packs.has(pack);
}

export function buildCoverage(applicable: number, ran: number, notChecked: readonly NotCheckedEntry[]): Coverage {
  const seen = new Set<string>();
  const list: NotCheckedEntry[] = [];
  for (const n of [...notChecked, ...ALWAYS_NOT_CHECKED]) {
    const key = `${n.area}\u0000${n.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    list.push({ area: n.area, reason: n.reason });
  }
  return { applicable, ran, percent: applicable === 0 ? 100 : Math.round((100 * ran) / applicable), notChecked: list };
}
