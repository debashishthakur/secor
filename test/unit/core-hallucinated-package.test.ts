// core/hallucinated-package: registry lookups, the 30-day window (measured from the run start), custom registries
// and indexes, failures, and which dependencies are looked up at all.

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { NetClient, NetResponse } from "../../src/engine/net.js";
import { npmDownloadsUrl, npmRegistryUrl, pypiUrl } from "../../src/engine/rules/core/hallucinated-package.js";
import { runShip } from "../../src/ship/run.js";
import type { RunResult } from "../../src/types.js";
import { FIXTURES, cleanup, runFixture } from "../helpers/fixtures.js";

const temp: string[] = [];
const saved = { HOME: process.env.HOME, SECOR_HOME: process.env.SECOR_HOME };
const RUN = new Date("2026-10-10T12:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;

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

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "secor-core-halluc-"));
  temp.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

/** Answers from a map of URL → response (or a thrown error); records every URL; fails on anything unmapped. */
function fakeNet(map: Record<string, NetResponse | Error>, log: string[] = []): NetClient {
  return {
    getJson(url) {
      log.push(url);
      const r = map[url];
      if (r === undefined) return Promise.reject(new Error(`unexpected request ${url}`));
      return r instanceof Error ? Promise.reject(r) : Promise.resolve(r);
    },
    postJson: (url) => Promise.reject(new Error(`unexpected POST ${url}`)),
  };
}

const npmDoc = (created: Date | string, extra: Record<string, unknown> = {}): NetResponse => ({
  status: 200,
  body: { time: { created: typeof created === "string" ? created : created.toISOString() }, versions: { "1.0.0": {} }, ...extra },
});
const pypiDoc = (...uploads: string[]): NetResponse => ({ status: 200, body: { releases: Object.fromEntries(uploads.map((u, i) => [`0.${i}`, [{ upload_time: u }]])) } });
const notFound: NetResponse = { status: 404, body: { error: "Not found" } };

async function ship(root: string, net: NetClient, now = RUN): Promise<RunResult> {
  const { result } = await runShip({ root, write: false, onlyRules: ["core/hallucinated-package"], net, now: () => now });
  return result;
}

const hp = (r: RunResult) => r.findings.filter((f) => f.ruleId === "core/hallucinated-package");
const pkgJson = (deps: Record<string, string>, extra: Record<string, unknown> = {}) => JSON.stringify({ name: "app", ...extra, dependencies: deps }, null, 2);

describe("URLs", () => {
  it("encodes scoped names for the registry and keeps them readable for download counts", () => {
    expect(npmRegistryUrl("@scope/name")).toBe("https://registry.npmjs.org/@scope%2fname");
    expect(npmRegistryUrl("left-pad")).toBe("https://registry.npmjs.org/left-pad");
    expect(npmDownloadsUrl("@scope/name")).toBe("https://api.npmjs.org/downloads/point/last-week/@scope/name");
    expect(pypiUrl("zope-interface")).toBe("https://pypi.org/pypi/zope-interface/json");
  });
});

describe("the 30-day window", () => {
  it("is measured from the run start, not the wall clock", async () => {
    const root = project({ "package.json": pkgJson({ fresh: "^1.0.0" }) });
    const net = () =>
      fakeNet({
        [npmRegistryUrl("fresh")]: npmDoc(new Date(RUN.getTime() - 29 * DAY)),
        [npmDownloadsUrl("fresh")]: { status: 200, body: { downloads: 499 } },
      });
    const inside = hp(await ship(root, net()));
    expect(inside.map((f) => [f.severity, f.advisory, f.location.line])).toEqual([["high", true, 4]]);
    expect(inside[0]!.evidence).toBe('"fresh": "^1.0.0" (first published 2026-09-11, 499 downloads last week)');
    // The same package 30 days later is no longer new.
    expect(hp(await ship(root, net(), new Date(RUN.getTime() + DAY)))).toEqual([]);
  });

  it("needs low downloads as well as a recent creation date (npm)", async () => {
    const root = project({ "package.json": pkgJson({ fresh: "^1.0.0" }) });
    const net = fakeNet({ [npmRegistryUrl("fresh")]: npmDoc(new Date(RUN.getTime() - DAY)), [npmDownloadsUrl("fresh")]: { status: 200, body: { downloads: 500 } } });
    expect(hp(await ship(root, net))).toEqual([]);
  });

  it("treats a download-count 404 as zero downloads", async () => {
    const root = project({ "package.json": pkgJson({ fresh: "^1.0.0" }) });
    const net = fakeNet({ [npmRegistryUrl("fresh")]: npmDoc(new Date(RUN.getTime() - DAY)), [npmDownloadsUrl("fresh")]: notFound });
    expect(hp(await ship(root, net)).map((f) => f.evidence)).toEqual(['"fresh": "^1.0.0" (first published 2026-10-09, 0 downloads last week)']);
  });

  it("uses the earliest upload across all PyPI releases (zone-less times are UTC)", async () => {
    const root = project({ "requirements.txt": "newpkg==0.2.0\noldpkg==9.0\n" });
    const net = fakeNet({
      [pypiUrl("newpkg")]: pypiDoc("2026-10-05T23:00:00", "2026-10-09T10:00:00"),
      [pypiUrl("oldpkg")]: pypiDoc("2026-10-09T00:00:00", "2026-09-01T00:00:00"),
    });
    expect(hp(await ship(root, net)).map((f) => [f.location.line, f.advisory, f.evidence])).toEqual([[1, true, "newpkg==0.2.0 (first uploaded 2026-10-05)"]]);
  });
});

describe("registries and indexes", () => {
  it("does not look up scoped packages served from a custom registry, and records a gap", async () => {
    const root = project({ "package.json": pkgJson({ "@corp/sdk": "^1.0.0", "@other/x": "^1.0.0" }), ".npmrc": "@corp:registry=https://npm.corp.example/\n@other:registry=https://registry.npmjs.org/\n" });
    const log: string[] = [];
    const r = await ship(root, fakeNet({ [npmRegistryUrl("@other/x")]: npmDoc("2015-01-01T00:00:00.000Z") }, log));
    expect(log).toEqual([npmRegistryUrl("@other/x")]);
    expect(hp(r)).toEqual([]);
    expect(r.coverage.notChecked).toContainEqual({ area: "Package @corp/sdk", reason: "served from a custom registry" });
  });

  it("applies a nested .npmrc to the manifests below it", async () => {
    const root = project({ "apps/web/package.json": pkgJson({ "@corp/ui": "^1.0.0" }), "apps/web/.npmrc": "@corp:registry=https://npm.corp.example/\n", "package.json": pkgJson({}) });
    const log: string[] = [];
    const r = await ship(root, fakeNet({}, log));
    expect(log).toEqual([]);
    expect(r.coverage.notChecked).toContainEqual({ area: "Package @corp/ui", reason: "served from a custom registry" });
  });

  it("turns a public 404 into a gap when the project uses its own npm registry or Python index", async () => {
    const root = project({
      "package.json": pkgJson({ "internal-thing": "^1.0.0" }),
      ".npmrc": "registry=https://artifactory.corp.example/api/npm/npm/\n",
      "requirements.txt": "--extra-index-url https://pypi.corp.example/simple\ninternal-py==1.0.0\n",
    });
    const r = await ship(root, fakeNet({ [npmRegistryUrl("internal-thing")]: notFound, [pypiUrl("internal-py")]: notFound }));
    expect(hp(r)).toEqual([]);
    expect(r.coverage.notChecked).toContainEqual({ area: "Package internal-thing", reason: "not found on the npm registry; the project also uses a custom registry" });
    expect(r.coverage.notChecked).toContainEqual({ area: "Package internal-py", reason: "not found on PyPI; the project also uses a custom index" });
  });

  it("treats a fully unpublished npm package as missing", async () => {
    const root = project({ "package.json": pkgJson({ gone: "^1.0.0" }) });
    const r = await ship(root, fakeNet({ [npmRegistryUrl("gone")]: { status: 200, body: { name: "gone", time: { created: "2015-01-01T00:00:00.000Z", unpublished: { time: "2020-01-01T00:00:00.000Z" } } } } }));
    expect(hp(r).map((f) => [f.severity, f.advisory])).toEqual([["high", false]]);
  });
});

describe("failures and scope", () => {
  it("records a gap (not a finding) when a lookup fails", async () => {
    const root = project({ "package.json": pkgJson({ a: "^1.0.0", b: "^1.0.0", c: "^1.0.0" }) });
    const r = await ship(
      root,
      fakeNet({
        [npmRegistryUrl("a")]: { status: 503, body: null },
        [npmRegistryUrl("b")]: new Error("ETIMEDOUT"),
        [npmRegistryUrl("c")]: npmDoc(new Date(RUN.getTime() - DAY)),
        [npmDownloadsUrl("c")]: { status: 500, body: null },
      }),
    );
    expect(hp(r)).toEqual([]);
    expect(r.coverage.ran).toBe(1);
    expect(r.coverage.notChecked).toEqual(
      expect.arrayContaining([
        { area: "Package a", reason: "registry lookup failed (HTTP 503)" },
        { area: "Package b", reason: "registry lookup failed" },
        { area: "Package c", reason: "download count lookup failed (HTTP 500)" },
      ]),
    );
  });

  it("looks each package up once and reports every manifest that lists it", async () => {
    const root = project({ "package.json": pkgJson({ ghost: "^1.0.0" }), "apps/a/package.json": pkgJson({ ghost: "^2.0.0" }, { name: "a" }) });
    const log: string[] = [];
    const fs = hp(await ship(root, fakeNet({ [npmRegistryUrl("ghost")]: notFound }, log)));
    expect(log).toEqual([npmRegistryUrl("ghost")]);
    expect(fs.map((f) => f.location.file).sort()).toEqual(["apps/a/package.json", "package.json"]);
  });

  it("checks devDependencies and pyproject [project].dependencies, but not peer/optional deps or extras", async () => {
    const root = project({
      "package.json": JSON.stringify({ name: "x", devDependencies: { devghost: "^1" }, peerDependencies: { peer: "^1" }, optionalDependencies: { opt: "^1" } }, null, 2),
      "pyproject.toml": '[project]\nname = "x"\ndependencies = ["pyghost>=1"]\n\n[project.optional-dependencies]\nextra = ["extraghost"]\n\n[dependency-groups]\ndev = ["groupghost"]\n',
    });
    const log: string[] = [];
    const fs = hp(await ship(root, fakeNet({ [npmRegistryUrl("devghost")]: notFound, [pypiUrl("pyghost")]: notFound }, log)));
    expect(log.sort()).toEqual([npmRegistryUrl("devghost"), pypiUrl("pyghost")].sort());
    expect(fs.map((f) => f.location.file).sort()).toEqual(["package.json", "pyproject.toml"]);
  });

  it("locates package.json dependencies inside their own section", async () => {
    const pkg = JSON.stringify({ name: "x", scripts: { ghostlint: "ghostlint ." }, dependencies: { ghostlint: "^1.0.0" }, devDependencies: { ghostlint: "^2.0.0" } }, null, 2);
    const root = project({ "package.json": pkg });
    const fs = hp(await ship(root, fakeNet({ [npmRegistryUrl("ghostlint")]: notFound })));
    const lines = pkg.split("\n");
    expect(fs.map((f) => lines[f.location.line - 1]!.trim()).sort()).toEqual(['"ghostlint": "^1.0.0"', '"ghostlint": "^2.0.0"']);
  });

  it("is not checked in offline mode", async () => {
    const { result, root } = await runFixture(join(FIXTURES, "core", "hallucinated-package", "vulnerable", "npm-404"), { onlyRules: ["core/hallucinated-package"], offline: true });
    temp.push(root);
    expect(hp(result)).toEqual([]);
    expect(result.coverage.notChecked).toContainEqual({ area: "Dependency that does not exist or is suspiciously new", reason: "network disabled (offline mode)" });
  });

  it("does not apply without direct dependencies", async () => {
    const root = project({ "package.json": JSON.stringify({ name: "x", peerDependencies: { react: "^18" } }) });
    expect((await ship(root, fakeNet({}))).coverage.applicable).toBe(0);
  });
});
