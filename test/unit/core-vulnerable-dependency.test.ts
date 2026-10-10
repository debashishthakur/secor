// core/vulnerable-dependency: OSV batching and pagination, severity and fix selection, failures, offline mode.

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { NetClient, NetResponse } from "../../src/engine/net.js";
import { advisorySeverity, fixSummary, fixedVersionsFor, planFix, queryOsv } from "../../src/engine/rules/core/osv.js";
import { evidenceFor } from "../../src/engine/rules/core/vulnerable-dependency.js";
import { runShip } from "../../src/ship/run.js";
import type { RunResult } from "../../src/types.js";
import { FIXTURES, cleanup, runFixture } from "../helpers/fixtures.js";

const temp: string[] = [];
const saved = { HOME: process.env.HOME, SECOR_HOME: process.env.SECOR_HOME };

beforeAll(() => {
  const home = mkdtempSync(join(tmpdir(), "secor-home-"));
  temp.push(home);
  process.env.HOME = home;
  process.env.SECOR_HOME = join(home, ".secor");
});

afterAll(() => {
  process.env.HOME = saved.HOME;
  process.env.SECOR_HOME = saved.SECOR_HOME;
  temp.forEach(cleanup);
});

interface Query {
  package: { ecosystem: string; name: string };
  version: string;
  page_token?: string;
}

/** A fake OSV that answers per query: `vulns` maps "eco/name@version" to advisory IDs, `docs` maps ID to document. */
function fakeOsv(opts: { vulns: Record<string, string[]>; docs?: Record<string, unknown>; pages?: Record<string, string[][]>; log?: { posts: Query[][]; gets: string[] } }): NetClient {
  const log = opts.log ?? { posts: [], gets: [] };
  return {
    postJson(url: string, body: unknown): Promise<NetResponse> {
      expect(url).toBe("https://api.osv.dev/v1/querybatch");
      const queries = (body as { queries: Query[] }).queries;
      log.posts.push(queries);
      return Promise.resolve({
        status: 200,
        body: {
          results: queries.map((q) => {
            const key = `${q.package.ecosystem}/${q.package.name}@${q.version}`;
            const pages = opts.pages?.[key];
            if (pages) {
              const idx = q.page_token ? Number(q.page_token) : 0;
              return { vulns: pages[idx]!.map((id) => ({ id })), ...(idx + 1 < pages.length ? { next_page_token: String(idx + 1) } : {}) };
            }
            const ids = opts.vulns[key] ?? [];
            return ids.length ? { vulns: ids.map((id) => ({ id })) } : {};
          }),
        },
      });
    },
    getJson(url: string): Promise<NetResponse> {
      log.gets.push(url);
      const id = decodeURIComponent(url.replace("https://api.osv.dev/v1/vulns/", ""));
      const doc = opts.docs?.[id];
      return Promise.resolve(doc === undefined ? { status: 404, body: { message: "Bug not found." } } : { status: 200, body: doc });
    },
  };
}

function adv(id: string, ecosystem: string, name: string, ranges: { introduced?: string; fixed?: string; last_affected?: string }[][], severity?: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    affected: [{ package: { ecosystem, name }, ranges: ranges.map((events) => ({ type: ecosystem === "npm" ? "SEMVER" : "ECOSYSTEM", events })) }],
    ...(severity ? { database_specific: { severity } } : {}),
    ...extra,
  };
}

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "secor-core-vulndep-"));
  temp.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

function npmProject(packages: Record<string, { version: string; dev?: boolean }>): string {
  const entries: Record<string, unknown> = { "": { name: "demo" } };
  for (const [name, p] of Object.entries(packages)) entries[`node_modules/${name}`] = { version: p.version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${p.version}.tgz`, ...(p.dev ? { dev: true } : {}) };
  return project({ "package.json": '{"name":"demo"}', "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: entries }, null, 2) });
}

async function ship(root: string, net: NetClient): Promise<RunResult> {
  const { result } = await runShip({ root, write: false, onlyRules: ["core/vulnerable-dependency"], net });
  return result;
}

const depFindings = (r: RunResult) => r.findings.filter((f) => f.ruleId === "core/vulnerable-dependency");

describe("OSV client", () => {
  it("follows next_page_token per result and merges the IDs", async () => {
    const log = { posts: [] as Query[][], gets: [] as string[] };
    const net = fakeOsv({ vulns: { "npm/b@1.0.0": ["GHSA-b"] }, pages: { "npm/a@1.0.0": [["GHSA-1", "GHSA-2"], ["GHSA-3"], ["GHSA-4"]] }, log });
    const out = await queryOsv(net, [
      { ecosystem: "npm", name: "a", version: "1.0.0" },
      { ecosystem: "npm", name: "b", version: "1.0.0" },
    ]);
    expect([...out.get("npm\u0000a\u00001.0.0")!].sort()).toEqual(["GHSA-1", "GHSA-2", "GHSA-3", "GHSA-4"]);
    expect([...out.get("npm\u0000b\u00001.0.0")!]).toEqual(["GHSA-b"]);
    expect(log.posts.map((p) => p.map((q) => `${q.package.name}:${q.page_token ?? ""}`))).toEqual([["a:", "b:"], ["a:1"], ["a:2"]]);
  });

  it("stops when a server repeats the same page token", async () => {
    let calls = 0;
    const net: NetClient = {
      postJson: () => {
        calls++;
        return Promise.resolve({ status: 200, body: { results: [{ vulns: [{ id: "GHSA-x" }], next_page_token: "same" }] } });
      },
      getJson: () => Promise.reject(new Error("unused")),
    };
    await queryOsv(net, [{ ecosystem: "npm", name: "a", version: "1.0.0" }]);
    expect(calls).toBe(2);
  });

  it("ignores advisory IDs that are not safe in a URL path", async () => {
    const net: NetClient = {
      postJson: () => Promise.resolve({ status: 200, body: { results: [{ vulns: [{ id: "../../evil" }, { id: "GHSA-ok" }, { id: 42 }] }] } }),
      getJson: () => Promise.reject(new Error("unused")),
    };
    const out = await queryOsv(net, [{ ecosystem: "npm", name: "a", version: "1.0.0" }]);
    expect([...out.values()].map((s) => [...s])).toEqual([["GHSA-ok"]]);
  });
});

describe("severity and fixes", () => {
  it("maps database_specific.severity, medium when absent or unknown", () => {
    expect(advisorySeverity({ database_specific: { severity: "CRITICAL" } })).toBe("critical");
    expect(advisorySeverity({ database_specific: { severity: "HIGH" } })).toBe("high");
    expect(advisorySeverity({ database_specific: { severity: "MODERATE" } })).toBe("medium");
    expect(advisorySeverity({ database_specific: { severity: "LOW" } })).toBe("low");
    expect(advisorySeverity({})).toBe("medium");
    expect(advisorySeverity({ database_specific: { severity: "WEIRD" } })).toBe("medium");
    expect(advisorySeverity(null)).toBe("medium");
  });

  it("uses only ranges for this package and ecosystem", () => {
    const doc = {
      affected: [
        { package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] },
        { package: { ecosystem: "npm", name: "lodash-es" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.30" }] }] },
        { package: { ecosystem: "RubyGems", name: "lodash" }, ranges: [{ type: "ECOSYSTEM", events: [{ fixed: "9.9.9" }] }] },
        { package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "GIT", repo: "x", events: [{ fixed: "abc123" }] }] },
      ],
    };
    expect(fixedVersionsFor(doc, "npm", "lodash")).toEqual(["4.17.21"]);
    expect(fixedVersionsFor({ affected: [{ package: { ecosystem: "PyPI", name: "Jinja2" }, ranges: [{ type: "ECOSYSTEM", events: [{ fixed: "2.11.3" }] }] }] }, "PyPI", "jinja2")).toEqual(["2.11.3"]);
  });

  it("picks the lowest fixed version above the current one, across several ranges and advisories", () => {
    const docs = new Map<string, Record<string, unknown> | null>([
      ["A", adv("A", "npm", "p", [[{ introduced: "0" }, { fixed: "1.2.5" }], [{ introduced: "2.0.0" }, { fixed: "2.1.3" }]])],
      ["B", adv("B", "npm", "p", [[{ introduced: "2.0.0" }, { fixed: "2.0.9" }]])],
      ["C", adv("C", "npm", "p", [[{ introduced: "0" }, { last_affected: "3.0.0" }]])],
      ["D", null],
    ]);
    expect(planFix("npm", "p", "2.0.5", ["A", "B"], docs)).toEqual({ target: "2.1.3", unfixed: [], unknown: [] });
    expect(planFix("npm", "p", "1.0.0", ["A"], docs)).toEqual({ target: "1.2.5", unfixed: [], unknown: [] });
    expect(planFix("npm", "p", "2.0.5", ["A", "C", "D"], docs)).toEqual({ target: "2.1.3", unfixed: ["C"], unknown: ["D"] });
    expect(fixSummary("p", "2.0.5", { target: "2.1.3", unfixed: [], unknown: [] })).toBe("Upgrade p from 2.0.5 to 2.1.3.");
    expect(fixSummary("p", "2.0.5", { target: null, unfixed: ["C"], unknown: [] })).toBe("No fixed version yet");
    expect(fixSummary("p", "2.0.5", { target: "2.1.3", unfixed: ["C"], unknown: ["D"] })).toBe(
      "Upgrade p from 2.0.5 to 2.1.3. No fixed version yet for C. Advisory details unavailable for D; check them at osv.dev.",
    );
  });

  it("keeps evidence within the limit and says how many IDs did not fit", () => {
    const ids = Array.from({ length: 30 }, (_, i) => `GHSA-${String(i).padStart(4, "0")}-aaaa-bbbb`);
    const ev = evidenceFor("big-package", "1.0.0", ids);
    expect(ev.length).toBeLessThanOrEqual(200);
    expect(ev).toMatch(/^big-package@1\.0\.0: GHSA-0000-aaaa-bbbb, .* \(\+\d+ more\)$/);
    expect(evidenceFor("p", "1.0.0", ["A", "B"])).toBe("p@1.0.0: A, B");
  });
});

describe("core/vulnerable-dependency end to end", () => {
  it("one finding per name@version at the highest severity, all IDs sorted, dev packages never queried", async () => {
    const root = npmProject({ lodash: { version: "4.17.15" }, "aaa-dev-tool": { version: "1.0.0", dev: true }, minimist: { version: "1.2.5" } });
    const log = { posts: [] as Query[][], gets: [] as string[] };
    const net = fakeOsv({
      vulns: { "npm/lodash@4.17.15": ["GHSA-z", "GHSA-a", "GHSA-m"], "npm/aaa-dev-tool@1.0.0": ["GHSA-dev"] },
      docs: {
        "GHSA-z": adv("GHSA-z", "npm", "lodash", [[{ introduced: "0" }, { fixed: "4.17.19" }]], "LOW"),
        "GHSA-a": adv("GHSA-a", "npm", "lodash", [[{ introduced: "0" }, { fixed: "4.17.21" }]], "CRITICAL"),
        "GHSA-m": adv("GHSA-m", "npm", "lodash", [[{ introduced: "0" }, { fixed: "4.17.20" }]], "MODERATE"),
      },
      log,
    });
    const r = await ship(root, net);
    expect(log.posts.flat().map((q) => q.package.name)).toEqual(["lodash", "minimist"]);
    const fs = depFindings(r);
    expect(fs).toHaveLength(1);
    expect(fs[0]).toMatchObject({
      severity: "critical",
      advisory: false,
      maturity: "stable",
      service: "core",
      evidence: "lodash@4.17.15: GHSA-a, GHSA-m, GHSA-z",
      fix: { summary: "Upgrade lodash from 4.17.15 to 4.17.21." },
      location: { file: "package-lock.json" },
    });
    expect(fs[0]!.id).toMatch(/^core-vulnerable-dependency-[0-9a-f]{12}$/);
    expect(log.gets.sort()).toEqual(["GHSA-a", "GHSA-m", "GHSA-z"].map((id) => `https://api.osv.dev/v1/vulns/${id}`));
  });

  it("ignores withdrawn advisories", async () => {
    const root = npmProject({ x: { version: "1.0.0" } });
    const net = fakeOsv({ vulns: { "npm/x@1.0.0": ["GHSA-w"] }, docs: { "GHSA-w": adv("GHSA-w", "npm", "x", [[{ introduced: "0" }, { fixed: "2.0.0" }]], "HIGH", { withdrawn: "2024-01-01T00:00:00Z" }) } });
    expect(depFindings(await ship(root, net))).toEqual([]);
  });

  it("reports advisories whose details are missing as medium, with a gap", async () => {
    const root = npmProject({ x: { version: "1.0.0" } });
    const r = await ship(root, fakeOsv({ vulns: { "npm/x@1.0.0": ["GHSA-gone"] } }));
    expect(depFindings(r).map((f) => [f.severity, f.fix.summary])).toEqual([["medium", "Advisory details unavailable for GHSA-gone; check them at osv.dev."]]);
    expect(r.coverage.notChecked).toContainEqual({ area: "Dependency advisories", reason: "details unavailable for GHSA-gone" });
  });

  it("marks the rule not checked when OSV fails", async () => {
    const root = npmProject({ x: { version: "1.0.0" } });
    const down: NetClient = { postJson: () => Promise.reject(new Error("ECONNRESET")), getJson: () => Promise.reject(new Error("down")) };
    const r1 = await ship(root, down);
    expect(r1.coverage.ran).toBe(0);
    expect(r1.coverage.notChecked).toContainEqual({ area: "Dependency with a known vulnerability", reason: "OSV query failed (ECONNRESET)" });
    const busy: NetClient = { postJson: () => Promise.resolve({ status: 503, body: null }), getJson: () => Promise.reject(new Error("down")) };
    const r2 = await ship(root, busy);
    expect(r2.coverage.notChecked).toContainEqual({ area: "Dependency with a known vulnerability", reason: "OSV query failed (HTTP 503)" });
  });

  it("is not checked in offline mode (coverage.notChecked)", async () => {
    const { result, root } = await runFixture(join(FIXTURES, "core", "vulnerable-dependency", "vulnerable", "npm-package-lock"), { onlyRules: ["core/vulnerable-dependency"], offline: true });
    temp.push(root);
    expect(depFindings(result)).toEqual([]);
    expect(result.coverage.applicable).toBe(1);
    expect(result.coverage.ran).toBe(0);
    expect(result.coverage.notChecked).toContainEqual({ area: "Dependency with a known vulnerability", reason: "network disabled (offline mode)" });
  });

  it("does not apply without a supported lockfile or pin", async () => {
    const root = project({ "package.json": '{"name":"x","dependencies":{"a":"^1"}}', "requirements.txt": "flask>=2\n" });
    const r = await ship(root, fakeOsv({ vulns: {} }));
    expect(r.coverage.applicable).toBe(0);
  });

  it("records unpinned requirements as a gap and queries normalised PyPI names", async () => {
    const root = project({ "requirements.txt": "Django==3.2.0\nrequests>=2\nPyYAML\n" });
    const log = { posts: [] as Query[][], gets: [] as string[] };
    const r = await ship(root, fakeOsv({ vulns: {}, log }));
    expect(log.posts.flat()).toEqual([{ package: { ecosystem: "PyPI", name: "django" }, version: "3.2.0" }]);
    expect(r.coverage.notChecked).toContainEqual({ area: "Python dependencies", reason: "unpinned in requirements.txt: requests, PyYAML" });
  });

  it("reports the same vulnerable version once per lockfile", async () => {
    const lock = (v: string) => JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/x": { version: v }, "node_modules/y/node_modules/x": { version: v } } }, null, 2);
    const root = project({ "package.json": "{}", "package-lock.json": lock("1.0.0"), "apps/a/package.json": "{}", "apps/a/package-lock.json": lock("1.0.0") });
    const log = { posts: [] as Query[][], gets: [] as string[] };
    const net = fakeOsv({ vulns: { "npm/x@1.0.0": ["GHSA-x"] }, docs: { "GHSA-x": adv("GHSA-x", "npm", "x", [[{ introduced: "0" }, { fixed: "1.0.1" }]], "HIGH") }, log });
    const fs = depFindings(await ship(root, net));
    expect(fs.map((f) => `${f.location.file}:${f.location.line}`).sort()).toEqual(["apps/a/package-lock.json:5", "package-lock.json:5"]);
    expect(log.posts).toHaveLength(1);
    expect(log.posts[0]).toHaveLength(1);
  });

  it("is deterministic across runs", async () => {
    const root = npmProject({ b: { version: "1.0.0" }, a: { version: "2.0.0" } });
    const docs = { "GHSA-1": adv("GHSA-1", "npm", "a", [[{ introduced: "0" }, { fixed: "2.0.1" }]], "HIGH"), "GHSA-2": adv("GHSA-2", "npm", "b", [[{ introduced: "0" }]]) };
    const net = () => fakeOsv({ vulns: { "npm/a@2.0.0": ["GHSA-1"], "npm/b@1.0.0": ["GHSA-2"] }, docs });
    const one = depFindings(await ship(root, net()));
    const two = depFindings(await ship(root, net()));
    expect(one).toEqual(two);
    expect(one.map((f) => [f.severity, f.evidence, f.fix.summary])).toEqual([
      ["high", "a@2.0.0: GHSA-1", "Upgrade a from 2.0.0 to 2.0.1."],
      ["medium", "b@1.0.0: GHSA-2", "No fixed version yet"],
    ]);
  });
});
