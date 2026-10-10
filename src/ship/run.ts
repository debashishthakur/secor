// The Ship run pipeline (spec section 8.1).

import { resolve } from "node:path";
import { connectPosture } from "../connect/posture.js";
import { type IgnoreFile, loadIgnoreFile, loadProjectConfig, projectName } from "../engine/config.js";
import { ProjectContext } from "../engine/context.js";
import { detectUnits } from "../engine/detect.js";
import { listFiles } from "../engine/files.js";
import { scanLockfiles } from "../engine/lockfiles.js";
import { sortFindings } from "../engine/finding.js";
import { toEntryPoint } from "../engine/inventory-types.js";
import { buildInventory } from "../engine/inventory.js";
import { createNetClient, type NetClient } from "../engine/net.js";
import { initParsers } from "../engine/parse.js";
import { newRunId, writeRun } from "../engine/report.js";
import { allRules } from "../engine/rules/index.js";
import type { Rule } from "../engine/rules/types.js";
import { buildCoverage, runRules } from "../engine/runner.js";
import { computeScore } from "../engine/score.js";
import { type Finding, type NotCheckedEntry, type Pack, RULES_VERSION, type RunResult } from "../types.js";
import { secorVersion } from "./version.js";

export { secorVersion };

export interface ShipOptions {
  root: string;
  packs?: ("api" | "mcp" | "web")[];
  offline?: boolean;
  /** Pre-assigned run ID (MCP jobs). */
  runId?: string;
  /** Re-run only these rules; findings of other rules are carried over from `carryOver` (ship_verify). */
  onlyRules?: string[];
  carryOver?: Finding[];
  /** Write .secor/ results (default true). */
  write?: boolean;
  now?: () => Date;
  net?: NetClient;
  rules?: Rule[];
}

export interface ShipOutcome {
  result: RunResult;
  warnings: string[];
}

export async function runShip(opts: ShipOptions): Promise<ShipOutcome> {
  const now = opts.now ?? (() => new Date());
  const root = resolve(opts.root);
  const started = now();
  const runId = opts.runId ?? newRunId(root, started);
  const warnings: string[] = [];

  // 1. Config.
  const config = loadProjectConfig(root);
  const ignores = loadIgnoreFile(root);
  const network = !opts.offline && config.network;
  const packs: Set<Pack> = new Set(["core"]);
  const selected = opts.packs ?? (config.packs === "auto" ? (["api", "mcp", "web"] as const) : config.packs);
  for (const p of selected) packs.add(p);

  // 2. Files.
  const listing = listFiles(root, config.exclude);
  await initParsers();
  const ctx = new ProjectContext({
    root,
    name: projectName(root, config),
    config,
    files: listing.files,
    git: listing.git,
    packs,
    network,
    net: opts.net ?? createNetClient(),
    runStartedAt: started,
  });

  try {
    // 3. Detect service units.
    ctx.detection = detectUnits({ files: ctx.files, read: (f) => ctx.read(f), mcpDeployment: config.mcp.deployment });
    ctx.units = ctx.detection.units;
    // 4. Inventory.
    ctx.inventory = buildInventory(ctx);
    // 5. Rules.
    const only = opts.onlyRules ? new Set(opts.onlyRules) : undefined;
    const outcome = await runRules(ctx, opts.rules ?? allRules(), only);
    let findings = outcome.findings;
    if (only && opts.carryOver) findings = sortFindings([...opts.carryOver.filter((f) => !only.has(f.ruleId)), ...findings]);
    // 6. Ignores.
    findings = applyIgnores(findings, ignores, warnings);
    // 7. Coverage and score.
    const disabled: NotCheckedEntry[] = [];
    for (const kind of new Set(ctx.units.map((u) => u.kind))) {
      if (!packs.has(kind)) disabled.push({ area: `${kind} checks`, reason: "pack not selected (packs setting or --packs)" });
    }
    // Lockfiles SECOR cannot read are listed even when no supported lockfile made core/vulnerable-dependency apply.
    const lockGaps: NotCheckedEntry[] = [];
    if (!only && !outcome.rules.some((r) => r.id === "core/vulnerable-dependency")) {
      for (const u of scanLockfiles(ctx).unsupported) lockGaps.push({ area: `Dependencies in ${u.file}`, reason: u.reason });
    }
    const coverage = buildCoverage(outcome.applicable, outcome.ran, [...outcome.notChecked, ...ctx.gaps, ...ctx.detection.notChecked, ...lockGaps, ...disabled]);
    const posture = connectPosture(root, started);
    const score = computeScore(findings, ctx.units, coverage.percent, posture.score);
    const result: RunResult = {
      runId,
      startedAt: started.toISOString(),
      finishedAt: now().toISOString(),
      secorVersion: secorVersion(),
      rulesVersion: RULES_VERSION,
      project: { name: ctx.name, root },
      units: ctx.units.map((u) => ({ kind: u.kind, framework: u.framework, root: u.root })),
      inventory: ctx.inventory.map(toEntryPoint),
      findings,
      coverage,
      score,
    };
    // 8. Write.
    const written = opts.write === false ? result : writeRun(root, result);
    return { result: written, warnings };
  } finally {
    ctx.dispose();
  }
}

export function applyIgnores(findings: Finding[], ignores: IgnoreFile, warnings: string[]): Finding[] {
  const byId = new Map(ignores.ignores.map((i) => [i.finding, i]));
  const ids = new Set(findings.map((f) => f.id));
  for (const i of ignores.ignores) {
    if (!ids.has(i.finding)) warnings.push(`.secor/ignore.yaml: finding ${i.finding} no longer exists`);
  }
  return findings.map((f) => {
    const ig = byId.get(f.id);
    if (!ig) {
      const { ignoreReason: _r, ...rest } = f;
      return { ...rest, status: "open" as const };
    }
    return { ...f, status: "ignored" as const, ignoreReason: ig.reason };
  });
}
