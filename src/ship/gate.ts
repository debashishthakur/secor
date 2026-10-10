// `secor gate` decision (spec 11.1): fail when counted findings reach --fail-on, or when ignores / public
// entries grew since --base (unless --accept-config-changes).

import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { CONFIG_FILE, IGNORE_FILE } from "../engine/config.js";
import { runGit } from "../engine/files.js";
import { counted } from "../engine/finding.js";
import { readTextIfExists } from "../engine/util/fsx.js";
import { type Finding, SEVERITY_RANK, type Severity } from "../types.js";

export class GateError extends Error {}

export function findingReasons(findings: readonly Finding[], failOn: "critical" | "high"): string[] {
  return findings
    .filter((f) => counted(f) && SEVERITY_RANK[f.severity] <= SEVERITY_RANK[failOn as Severity])
    .map((f) => `${f.severity} ${f.ruleId} at ${f.location.file}:${f.location.line} (${f.id})`);
}

function countEntries(text: string | null, key: "ignores" | "public"): number {
  if (!text) return 0;
  try {
    const doc = parseYaml(text) as Record<string, unknown> | null;
    const v = doc?.[key];
    return Array.isArray(v) ? v.length : 0;
  } catch {
    return 0;
  }
}

/** Reasons the gate fails because `ignores` or `public` entries grew since `base`. */
export function configGrowth(root: string, base: string, accept: boolean): string[] {
  if (!/^[\w./~^@{}-]+$/.test(base) || base.startsWith("-")) throw new GateError(`invalid git ref "${base}"`);
  const check = runGit(["rev-parse", "--verify", "--quiet", `${base}^{commit}`], root);
  if (!check.ok) throw new GateError(`git ref "${base}" not found (is this a git repository with git available?)`);
  const reasons: string[] = [];
  const pairs: [string, "ignores" | "public"][] = [
    [IGNORE_FILE, "ignores"],
    [CONFIG_FILE, "public"],
  ];
  for (const [file, key] of pairs) {
    const atBase = runGit(["show", `${base}:./${file}`], root);
    const before = countEntries(atBase.ok ? atBase.stdout : null, key);
    const after = countEntries(readTextIfExists(join(root, file)), key);
    if (after > before && !accept) reasons.push(`${file}: ${key} grew from ${before} to ${after} since ${base} (review them, then pass --accept-config-changes)`);
  }
  return reasons;
}
