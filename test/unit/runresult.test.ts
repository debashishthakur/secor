// RunResult validates against the section 7 types (M1 acceptance); determinism (14.1); report files (5.4).

import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { newRunId } from "../../src/engine/report.js";
import { runShip } from "../../src/ship/run.js";
import type { RunResult } from "../../src/types.js";
import { FIXTURES, listCases, prepareFixture } from "../helpers/fixtures.js";

const Severity = z.enum(["critical", "high", "medium", "low"]);
const ServiceKind = z.enum(["api", "mcp", "web"]);
const Framework = z.enum(["express", "nextjs", "fastapi", "vite", "mcp-ts", "mcp-py"]);

const EntryPoint = z.strictObject({
  id: z.string().regex(/^[0-9a-f]{12}$/),
  kind: z.enum(["http_route", "server_action", "mcp_tool", "mcp_resource", "mcp_prompt", "page"]),
  service: ServiceKind,
  framework: Framework,
  method: z.string().regex(/^(?:[A-Z]+|\*)$/).optional(),
  path: z.string().optional(),
  name: z.string().optional(),
  file: z.string(),
  line: z.number().int().min(1),
  auth: z.strictObject({ guarded: z.boolean(), via: z.enum(["handler", "middleware", "dependency", "router", "server"]).nullable(), guard: z.string().optional() }),
  declaredPublic: z.boolean(),
  callsPaidApi: z.boolean(),
  writesDb: z.boolean(),
});

const Finding = z.strictObject({
  id: z.string().regex(/^[a-z]+-[a-z0-9-]+-[0-9a-f]{12}$/),
  ruleId: z.string().regex(/^(?:core|api|mcp|web|probe)\/[a-z0-9-]+$/),
  title: z.string().min(1),
  severity: Severity,
  advisory: z.boolean(),
  maturity: z.enum(["experimental", "stable"]),
  service: z.enum(["api", "mcp", "web", "core"]),
  location: z.strictObject({ file: z.string(), line: z.number().int().min(1), endLine: z.number().int().optional() }),
  entryPointId: z.string().optional(),
  evidence: z.string().max(200).refine((s) => !/[\r\n]/.test(s), "evidence must be one line"),
  why: z.string().min(1),
  fix: z.strictObject({ summary: z.string().min(1), patch: z.string().optional(), humanAction: z.string().optional(), testTemplate: z.string().optional() }),
  source: z.strictObject({ name: z.string(), url: z.string() }).optional(),
  status: z.enum(["open", "ignored"]),
  ignoreReason: z.string().optional(),
  probe: z.boolean().optional(),
});

export const RunResultSchema = z.strictObject({
  runId: z.string().regex(/^\d{8}T\d{6}Z(?:-\d+)?$/),
  startedAt: z.string().datetime(),
  finishedAt: z.string().datetime(),
  secorVersion: z.string(),
  rulesVersion: z.literal("1.0.0"),
  project: z.strictObject({ name: z.string().min(1), root: z.string().min(1) }),
  units: z.array(z.strictObject({ kind: ServiceKind, framework: Framework, root: z.string() })),
  inventory: z.array(EntryPoint),
  findings: z.array(Finding),
  coverage: z.strictObject({
    applicable: z.number().int().min(0),
    ran: z.number().int().min(0),
    percent: z.number().int().min(0).max(100),
    notChecked: z.array(z.strictObject({ area: z.string(), reason: z.string() })),
  }),
  score: z.strictObject({
    scoringVersion: z.literal(1),
    overall: z.number().int().min(0).max(100).nullable(),
    band: z.enum(["fix-before-deploy", "needs-work", "no-known-critical-or-high"]).nullable(),
    ship: z.number().int().nullable(),
    shipByKind: z.strictObject({ api: z.number().int().nullable(), mcp: z.number().int().nullable(), web: z.number().int().nullable() }),
    connect: z.number().int().nullable(),
    incomplete: z.boolean(),
  }),
});

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 } as const;

function checkOrdering(r: RunResult) {
  for (let i = 1; i < r.findings.length; i++) {
    const a = r.findings[i - 1]!;
    const b = r.findings[i]!;
    const key = (f: typeof a) => [SEVERITY_ORDER[f.severity], f.location.file, f.location.line, f.ruleId] as const;
    const ka = key(a);
    const kb = key(b);
    const cmp = ka[0] - kb[0] || (ka[1] < kb[1] ? -1 : ka[1] > kb[1] ? 1 : 0) || ka[2] - kb[2] || (ka[3] < kb[3] ? -1 : ka[3] > kb[3] ? 1 : 0);
    expect(cmp, `findings out of order at ${i}`).toBeLessThanOrEqual(0);
  }
}

const strip = (r: RunResult) => ({ ...r, runId: "", startedAt: "", finishedAt: "", project: { ...r.project, root: "" } });

let home: string;
const prevHome = process.env.HOME;
const prevSecor = process.env.SECOR_HOME;
beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), "secor-home-"));
  process.env.HOME = home;
  process.env.SECOR_HOME = join(home, ".secor");
});
afterAll(() => {
  process.env.HOME = prevHome;
  process.env.SECOR_HOME = prevSecor;
});

const projects = [
  ...["express", "nextjs", "fastapi", "vite", "mcp-ts", "mcp-py"].map((fw) => join(FIXTURES, "..", "inventory", "fixtures", fw)),
  ...listCases().map((c) => c.dir),
];

describe("RunResult shape, ordering and determinism", () => {
  for (const dir of projects) {
    it(dir.replace(/^.*test\//, ""), async () => {
      const root = prepareFixture(dir);
      const a = (await runShip({ root, write: false, offline: true })).result;
      const b = (await runShip({ root, write: false, offline: true })).result;
      const parsed = RunResultSchema.safeParse(JSON.parse(JSON.stringify(a)));
      expect(parsed.success ? "" : JSON.stringify(parsed.error.issues.slice(0, 3))).toBe("");
      checkOrdering(a);
      expect(new Set(a.findings.map((f) => f.id)).size).toBe(a.findings.length);
      expect(JSON.stringify(strip(b))).toBe(JSON.stringify(strip(a)));
    });
  }
});

describe("report files", () => {
  it("writes runs/<runId>.json, latest.json, history.jsonl and .secor/.gitignore", async () => {
    const root = prepareFixture(join(FIXTURES, "..", "inventory", "fixtures", "express"));
    const { result } = await runShip({ root, offline: true });
    const dir = join(root, ".secor");
    expect(readFileSync(join(dir, ".gitignore"), "utf8")).toBe("runs/\nlatest.json\nhistory.jsonl\n");
    expect(JSON.parse(readFileSync(join(dir, "latest.json"), "utf8")).runId).toBe(result.runId);
    expect(existsSync(join(dir, "runs", `${result.runId}.json`))).toBe(true);
    const hist = readFileSync(join(dir, "history.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(Object.keys(hist[0]).sort()).toEqual(["connect", "coverage", "finishedAt", "overall", "runId", "ship"]);
    const second = await runShip({ root, offline: true });
    expect(second.result.runId).not.toBe(result.runId);
    expect(readdirSync(join(dir, "runs"))).toHaveLength(2);
  });

  it("run IDs are UTC timestamps with -2, -3 suffixes on collision", () => {
    const root = mkdtempSync(join(tmpdir(), "secor-ids-"));
    const at = new Date("2026-10-10T12:34:56.789Z");
    expect(newRunId(root, at)).toBe("20261010T123456Z");
    expect(newRunId(root, at)).toBe("20261010T123456Z-2");
    expect(newRunId(root, at)).toBe("20261010T123456Z-3");
  });

  it("never writes outside .secor/ (source files untouched)", async () => {
    const root = prepareFixture(join(FIXTURES, "..", "inventory", "fixtures", "fastapi"));
    const before = snapshot(root);
    await runShip({ root, offline: true });
    const after = snapshot(root);
    for (const [f, content] of before) expect(after.get(f), f).toBe(content);
    expect([...after.keys()].filter((f) => !before.has(f)).every((f) => f.startsWith(".secor/"))).toBe(true);
  });

  it("invalid config is a clear error, not a crash", async () => {
    const root = prepareFixture(join(FIXTURES, "..", "inventory", "fixtures", "vite"));
    writeFileSync(join(root, "secor.config.yaml"), "version: 1\nbogus: true\n");
    await expect(runShip({ root, write: false, offline: true })).rejects.toThrow(/unknown key "bogus"/);
  });
});

function snapshot(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const visit = (rel: string) => {
    for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) visit(p);
      else out.set(p, readFileSync(join(root, p), "utf8"));
    }
  };
  visit("");
  return out;
}
