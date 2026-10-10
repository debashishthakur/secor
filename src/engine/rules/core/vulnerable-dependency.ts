// core/vulnerable-dependency (spec section 8.5): an exact (ecosystem, name, version) from a lockfile or a pinned
// requirement has an OSV advisory. One finding per name@version per lockfile, at the highest advisory severity,
// with every advisory ID in the evidence.

import { SEVERITY_RANK, type Severity } from "../../../types.js";
import { type LockedPackage, type Lockfile, scanLockfiles } from "../../lockfiles.js";
import { NotChecked, defineRule } from "../types.js";
import { OsvError, type OsvQuery, advisorySeverity, fetchAdvisories, fixSummary, isWithdrawn, planFix, queryKey, queryOsv } from "./osv.js";

const WHY = "This exact dependency version has a published security advisory, so the vulnerable code ships with the project. Known-vulnerable versions are easy for attackers to find and target.";

/** Packages to check in one lockfile: production packages only, one entry per name@version (first line wins). */
function checkable(l: Lockfile): LockedPackage[] {
  const seen = new Map<string, LockedPackage>();
  for (const p of l.packages) {
    if (p.dev) continue;
    const k = `${p.name}@${p.version}`;
    const prev = seen.get(k);
    if (!prev || p.line < prev.line) seen.set(k, p);
  }
  return [...seen.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) || (a.version < b.version ? -1 : a.version > b.version ? 1 : 0));
}

/** "name@1.2.3: ID1, ID2" kept within the evidence limit, ending with "(+N more)" when IDs do not fit. */
export function evidenceFor(name: string, version: string, ids: readonly string[]): string {
  const head = `${name}@${version}: `;
  for (let n = ids.length; n > 1; n--) {
    const more = ids.length - n;
    const text = `${head}${ids.slice(0, n).join(", ")}${more ? ` (+${more} more)` : ""}`;
    if (text.length <= 190) return text;
  }
  return `${head}${ids[0] ?? ""}${ids.length > 1 ? ` (+${ids.length - 1} more)` : ""}`;
}

export const vulnerableDependency = defineRule({
  id: "core/vulnerable-dependency",
  title: "Dependency with a known vulnerability",
  pack: "core",
  // Promoted after validation (DECISIONS.md, "Validation and promotion").
  maturity: "stable",
  appliesTo(ctx) {
    // A supported lockfile, or a requirements*.txt with at least one "==" pin.
    return scanLockfiles(ctx).lockfiles.length > 0;
  },
  async check(ctx, emit) {
    if (!ctx.network) throw new NotChecked("network disabled (offline mode)");
    const scan = scanLockfiles(ctx);
    for (const u of scan.unsupported) ctx.addGap(`Dependencies in ${u.file}`, u.reason);
    for (const u of scan.unpinned) ctx.addGap("Python dependencies", `unpinned in ${u.file}: ${u.names.join(", ")}`);

    const perFile = scan.lockfiles.map((l) => ({ lock: l, pkgs: checkable(l) }));
    const unique = new Map<string, OsvQuery>();
    for (const { lock, pkgs } of perFile) {
      for (const p of pkgs) {
        const q: OsvQuery = { ecosystem: lock.ecosystem, name: p.name, version: p.version };
        unique.set(queryKey(q), q);
      }
    }
    // Sorted queries give stable request bodies, so the 24-hour response cache keeps runs deterministic.
    const queries = [...unique.values()].sort((a, b) => (queryKey(a) < queryKey(b) ? -1 : queryKey(a) > queryKey(b) ? 1 : 0));
    if (!queries.length) return;

    let byQuery: Map<string, Set<string>>;
    try {
      byQuery = await queryOsv(ctx.net, queries);
    } catch (e) {
      if (e instanceof OsvError) throw new NotChecked(e.message);
      throw e;
    }
    const allIds = [...new Set([...byQuery.values()].flatMap((s) => [...s]))].sort();
    if (!allIds.length) return;
    const docs = await fetchAdvisories(ctx.net, allIds);
    const missing = allIds.filter((id) => docs.get(id) === null);
    if (missing.length) ctx.addGap("Dependency advisories", `details unavailable for ${missing.join(", ")}`);

    for (const { lock, pkgs } of [...perFile].sort((a, b) => (a.lock.file < b.lock.file ? -1 : a.lock.file > b.lock.file ? 1 : 0))) {
      for (const p of pkgs) {
        const ids = [...(byQuery.get(queryKey({ ecosystem: lock.ecosystem, name: p.name, version: p.version })) ?? [])]
          .filter((id) => !isWithdrawn(docs.get(id) ?? null))
          .sort();
        if (!ids.length) continue;
        let severity: Severity = "low";
        for (const id of ids) {
          const s = advisorySeverity(docs.get(id) ?? null);
          if (SEVERITY_RANK[s] < SEVERITY_RANK[severity]) severity = s;
        }
        const plan = planFix(lock.ecosystem, p.name, p.version, ids, docs);
        emit({
          severity,
          service: "core",
          file: lock.file,
          line: p.line,
          anchor: `${p.name}@${p.version}`,
          evidence: evidenceFor(p.name, p.version, ids),
          why: WHY,
          fix: { summary: fixSummary(p.name, p.version, plan) },
        });
      }
    }
  },
});
