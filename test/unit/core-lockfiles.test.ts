// Lockfile parsers and discovery for core/vulnerable-dependency.

import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Manifest } from "../../src/engine/deps.js";
import { parseRequirementsTxt } from "../../src/engine/deps.js";
import {
  isNonRegistrySpec,
  npmAliasTarget,
  parsePackageLock,
  parsePnpmLock,
  parsePoetryLock,
  parseUvLock,
  parseYarnBerry,
  parseYarnV1,
  type ParseResult,
  requirementsPins,
  splitPnpmKey,
} from "../../src/engine/lockfiles.js";
import { runShip } from "../../src/ship/run.js";
import { cleanup } from "../helpers/fixtures.js";

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

function pkgs(r: ParseResult): { name: string; version: string; dev: boolean; line: number }[] {
  if (!r.ok) throw new Error(`parse failed: ${r.reason}`);
  return [...r.packages].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) || (a.version < b.version ? -1 : 1));
}

describe("package-lock.json", () => {
  const lock = JSON.stringify(
    {
      lockfileVersion: 3,
      packages: {
        "": { name: "root", version: "1.0.0" },
        "packages/web": { name: "web", version: "0.1.0" },
        "node_modules/web": { resolved: "packages/web", link: true },
        "node_modules/a": { version: "1.0.0" },
        "node_modules/b": { version: "2.0.0", dev: true },
        "node_modules/c": { version: "3.0.0", devOptional: true },
        "node_modules/a/node_modules/@s/d": { version: "4.0.0", optional: true },
        "node_modules/alias": { name: "real-pkg", version: "5.0.0" },
        "node_modules/fromgit": { version: "6.0.0", resolved: "git+ssh://git@github.com/x/y.git#abc" },
        "node_modules/local": { version: "7.0.0", resolved: "file:../local" },
        "node_modules/noversion": {},
      },
    },
    null,
    2,
  );

  const lineOf = (key: string) => lock.split("\n").findIndex((l) => l.includes(`"${key}": {`)) + 1;

  it("reads v2/v3 packages, flags dev-only ones, resolves aliases and skips local and git packages", () => {
    expect(pkgs(parsePackageLock(lock))).toEqual([
      { name: "@s/d", version: "4.0.0", dev: false, line: lineOf("node_modules/a/node_modules/@s/d") },
      { name: "a", version: "1.0.0", dev: false, line: lineOf("node_modules/a") },
      { name: "b", version: "2.0.0", dev: true, line: lineOf("node_modules/b") },
      { name: "c", version: "3.0.0", dev: false, line: lineOf("node_modules/c") },
      { name: "real-pkg", version: "5.0.0", dev: false, line: lineOf("node_modules/alias") },
    ]);
    expect(lineOf("node_modules/a")).toBe(16);
  });

  it("rejects lockfile v1 and unparseable files", () => {
    expect(parsePackageLock(JSON.stringify({ lockfileVersion: 1, dependencies: {} }))).toEqual({ ok: false, reason: "lockfileVersion 1 is not supported (v2 and v3 are)" });
    expect(parsePackageLock("{nope").ok).toBe(false);
  });
});

describe("pnpm-lock.yaml", () => {
  it("splits v6 and v9 keys, dropping peer suffixes", () => {
    expect(splitPnpmKey("/@scope/name@1.2.3(react@18.2.0)")).toEqual({ name: "@scope/name", version: "1.2.3" });
    expect(splitPnpmKey("name@1.2.3(peer@1.0.0)(other@2.0.0)")).toEqual({ name: "name", version: "1.2.3" });
    expect(splitPnpmKey("/name/1.2.3")).toBeNull();
  });

  it("v9: production packages are the ones reachable from importers' non-dev dependencies", () => {
    const text = [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      app-dep:",
      "        specifier: ^1.0.0",
      "        version: 1.0.0(react@18.2.0)",
      "      aliased:",
      "        specifier: npm:@real/thing@^2",
      "        version: '@real/thing@2.0.0'",
      "      linked:",
      "        specifier: workspace:*",
      "        version: link:../linked",
      "    optionalDependencies:",
      "      opt:",
      "        specifier: ^1",
      "        version: 1.1.0",
      "    devDependencies:",
      "      dev-tool:",
      "        specifier: ^3",
      "        version: 3.0.0",
      "  packages/web:",
      "    dependencies:",
      "      shared:",
      "        specifier: ^1",
      "        version: 1.0.0",
      "packages:",
      "  app-dep@1.0.0:",
      "    resolution: {integrity: sha512-x}",
      "  transitive@1.5.0:",
      "    resolution: {integrity: sha512-x}",
      "  '@real/thing@2.0.0':",
      "    resolution: {integrity: sha512-x}",
      "  opt@1.1.0:",
      "    resolution: {integrity: sha512-x}",
      "  dev-tool@3.0.0:",
      "    resolution: {integrity: sha512-x}",
      "  dev-only-transitive@0.1.0:",
      "    resolution: {integrity: sha512-x}",
      "  shared@1.0.0:",
      "    resolution: {integrity: sha512-x}",
      "  gitdep@1.0.0:",
      "    resolution: {type: git, repo: https://github.com/x/y, commit: abc}",
      "  tarball@https://example.com/t.tgz:",
      "    resolution: {tarball: https://example.com/t.tgz}",
      "snapshots:",
      "  app-dep@1.0.0(react@18.2.0):",
      "    dependencies:",
      "      transitive: 1.5.0",
      "  transitive@1.5.0: {}",
      "  '@real/thing@2.0.0': {}",
      "  opt@1.1.0: {}",
      "  dev-tool@3.0.0:",
      "    dependencies:",
      "      dev-only-transitive: 0.1.0",
      "  dev-only-transitive@0.1.0: {}",
      "  shared@1.0.0: {}",
      "",
    ].join("\n");
    expect(pkgs(parsePnpmLock(text)).map((p) => [p.name, p.dev, p.line])).toEqual([
      ["@real/thing", false, 32],
      ["app-dep", false, 28],
      ["dev-only-transitive", true, 38],
      ["dev-tool", true, 36],
      ["opt", false, 34],
      ["shared", false, 40],
      ["transitive", false, 30],
    ]);
  });

  it("v6: uses the dev flag", () => {
    const text = ["lockfileVersion: '6.0'", "packages:", "  /a@1.0.0:", "    dev: true", "  /b@2.0.0:", "    dev: false", "  /@s/c@3.0.0(x@1.0.0):", "    optional: true", ""].join("\n");
    expect(pkgs(parsePnpmLock(text)).map((p) => [p.name, p.version, p.dev, p.line])).toEqual([
      ["@s/c", "3.0.0", false, 7],
      ["a", "1.0.0", true, 3],
      ["b", "2.0.0", false, 5],
    ]);
  });

  it("rejects versions before 6", () => {
    expect(parsePnpmLock("lockfileVersion: 5.4\npackages: {}\n")).toEqual({ ok: false, reason: "lockfileVersion 5.4 is not supported (6 to 9 are)" });
  });
});

describe("yarn.lock", () => {
  it("v1: entries with several specs, scoped names, aliases, and skipped local/git entries", () => {
    const text = [
      "# yarn lockfile v1",
      "",
      "",
      '"@babel/core@^7.0.0", "@babel/core@^7.1.0":',
      '  version "7.24.0"',
      '  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"',
      "  dependencies:",
      '    version "9.9.9"',
      "",
      "lodash@^4.17.0:",
      '  version "4.17.21"',
      "",
      '"my-alias@npm:real-name@^1.0.0":',
      '  version "1.2.0"',
      "",
      '"local@file:../local":',
      '  version "0.0.1"',
      "",
      '"fromgit@git+https://github.com/x/y.git":',
      '  version "1.0.0"',
      '  resolved "git+https://github.com/x/y.git#abc"',
      "",
      '"shorthand@user/repo#main":',
      '  version "2.0.0"',
      "",
    ].join("\n");
    expect(pkgs(parseYarnV1(text))).toEqual([
      { name: "@babel/core", version: "7.24.0", dev: false, line: 4 },
      { name: "lodash", version: "4.17.21", dev: false, line: 10 },
      { name: "real-name", version: "1.2.0", dev: false, line: 13 },
    ]);
  });

  it("Berry: npm resolutions only (workspace and patch entries skipped), aliases resolved", () => {
    const text = [
      "__metadata:",
      "  version: 8",
      "",
      '"app@workspace:.":',
      "  version: 0.0.0-use.local",
      '  resolution: "app@workspace:."',
      "",
      '"lodash@npm:^4.17.0":',
      "  version: 4.17.21",
      '  resolution: "lodash@npm:4.17.21"',
      "",
      '"lodash@patch:lodash@npm%3A4.17.21#./.yarn/patches/x.patch::version=4.17.21&hash=1":',
      "  version: 4.17.21",
      '  resolution: "lodash@patch:lodash@npm%3A4.17.21#./.yarn/patches/x.patch::version=4.17.21&hash=1"',
      "",
      '"alias@npm:@scope/real@^2":',
      "  version: 2.1.0",
      '  resolution: "@scope/real@npm:2.1.0"',
      "",
    ].join("\n");
    expect(pkgs(parseYarnBerry(text))).toEqual([
      { name: "@scope/real", version: "2.1.0", dev: false, line: 16 },
      { name: "lodash", version: "4.17.21", dev: false, line: 8 },
    ]);
  });
});

describe("poetry.lock", () => {
  it("excludes category dev and groups without main, skips non-index sources, normalises names", () => {
    const text = [
      "[[package]]",
      'name = "Flask"',
      'version = "2.0.0"',
      'category = "main"',
      "",
      "[package.dependencies]",
      'name = "not-a-package-name"',
      "",
      "[[package]]",
      'name = "pytest"',
      'version = "7.0.0"',
      'category = "dev"',
      "",
      "[[package]]",
      'name = "black"',
      'version = "24.1.0"',
      'groups = ["dev", "lint"]',
      "",
      "[[package]]",
      'name = "zope.interface"',
      'version = "6.0"',
      'groups = ["main", "dev"]',
      "",
      "[[package]]",
      'name = "internal"',
      'version = "1.0.0"',
      "",
      "[package.source]",
      'type = "git"',
      'url = "https://example.com/internal.git"',
      "",
      "[[package]]",
      'name = "private-index"',
      'version = "1.0.0"',
      "",
      "[package.source]",
      'type = "legacy"',
      'url = "https://pypi.example.com/simple"',
      'reference = "private"',
      "",
      "[metadata]",
      'lock-version = "2.1"',
      "",
    ].join("\n");
    expect(pkgs(parsePoetryLock(text))).toEqual([
      { name: "black", version: "24.1.0", dev: true, line: 15 },
      { name: "flask", version: "2.0.0", dev: false, line: 2 },
      { name: "private-index", version: "1.0.0", dev: false, line: 33 },
      { name: "pytest", version: "7.0.0", dev: true, line: 10 },
      { name: "zope-interface", version: "6.0", dev: false, line: 20 },
    ]);
  });
});

describe("uv.lock", () => {
  it("production packages are reachable from workspace members' dependencies and extras, not dev groups", () => {
    const text = [
      "version = 1",
      "",
      "[[package]]",
      'name = "app"',
      'version = "0.1.0"',
      'source = { editable = "." }',
      "dependencies = [",
      '    { name = "httpx", extra = ["http2"] },',
      '    { name = "numpy", version = "2.0.0", source = { registry = "https://pypi.org/simple" } },',
      "]",
      "",
      "[package.optional-dependencies]",
      'cli = [{ name = "click" }]',
      "",
      "[package.dev-dependencies]",
      'dev = [{ name = "pytest" }]',
      "",
      "[[package]]",
      'name = "click"',
      'version = "8.1.7"',
      'source = { registry = "https://pypi.org/simple" }',
      "",
      "[[package]]",
      'name = "h2"',
      'version = "4.1.0"',
      'source = { registry = "https://pypi.org/simple" }',
      "",
      "[[package]]",
      'name = "httpx"',
      'version = "0.27.0"',
      'source = { registry = "https://pypi.org/simple" }',
      "",
      "[package.optional-dependencies]",
      'http2 = [{ name = "h2" }]',
      "",
      "[[package]]",
      'name = "numpy"',
      'version = "1.26.0"',
      'source = { registry = "https://pypi.org/simple" }',
      "",
      "[[package]]",
      'name = "numpy"',
      'version = "2.0.0"',
      'source = { registry = "https://pypi.org/simple" }',
      "",
      "[[package]]",
      'name = "pytest"',
      'version = "8.0.0"',
      'source = { registry = "https://pypi.org/simple" }',
      'dependencies = [{ name = "pluggy" }]',
      "",
      "[[package]]",
      'name = "pluggy"',
      'version = "1.4.0"',
      'source = { registry = "https://pypi.org/simple" }',
      "",
      "[[package]]",
      'name = "vendored"',
      'version = "1.0.0"',
      'source = { git = "https://example.com/v.git?rev=abc#abc" }',
      "",
    ].join("\n");
    expect(pkgs(parseUvLock(text)).map((p) => [p.name, p.version, p.dev, p.line])).toEqual([
      ["click", "8.1.7", false, 19],
      ["h2", "4.1.0", false, 24],
      ["httpx", "0.27.0", false, 29],
      ["numpy", "1.26.0", true, 37],
      ["numpy", "2.0.0", false, 42],
      ["pluggy", "1.4.0", true, 53],
      ["pytest", "8.0.0", true, 47],
    ]);
  });
});

describe("requirements*.txt", () => {
  it("pins become packages; ranges are unpinned; direct references and dev files are skipped", () => {
    const m = parseRequirementsTxt(
      ["Django==4.2.0", "requests>=2", "pkg @ https://example.com/pkg.tar.gz", "numpy==1.*", "attrs == 23.1.0 ; python_version >= '3.8'", "-r other.txt", "--index-url https://x"].join("\n"),
      "",
      "requirements.txt",
    );
    expect(requirementsPins(m)).toEqual({
      packages: [
        { name: "django", version: "4.2.0", dev: false, line: 1 },
        { name: "attrs", version: "23.1.0", dev: false, line: 5 },
      ],
      unpinned: ["requests", "numpy"],
    });
    const dev: Manifest = parseRequirementsTxt("pytest==7.0.0\nruff\n", "", "requirements-dev.txt");
    expect(requirementsPins(dev)).toEqual({ packages: [], unpinned: [] });
  });
});

describe("npm spec helpers", () => {
  it("recognises non-registry specs and npm aliases", () => {
    for (const s of ["file:../x", "link:../x", "workspace:*", "git+https://x/y.git", "git://x", "github:u/r", "u/r", "u/r#main", "https://x/y.tgz", "portal:../x", "./local", "../up"]) expect(isNonRegistrySpec(s), s).toBe(true);
    for (const s of ["^1.0.0", "1.x", "latest", "*", "npm:other@^1", ">=1 <2", "catalog:"]) expect(isNonRegistrySpec(s), s).toBe(false);
    expect(npmAliasTarget("npm:other@^1.0.0")).toBe("other");
    expect(npmAliasTarget("npm:@scope/real@2")).toBe("@scope/real");
    expect(npmAliasTarget("npm:bare")).toBe("bare");
    expect(npmAliasTarget("^1.0.0")).toBeNull();
  });
});

describe("discovery", () => {
  function project(files: Record<string, string>): string {
    const dir = mkdtempSync(join(tmpdir(), "secor-core-lock-"));
    temp.push(dir);
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(dir, rel)), { recursive: true });
      writeFileSync(join(dir, rel), text);
    }
    return dir;
  }

  it("reads lockfiles larger than the 2 MB context limit", async () => {
    const packages: Record<string, unknown> = { "": { name: "big" } };
    for (let i = 0; i < 9000; i++) packages[`node_modules/pkg-${i}`] = { version: "1.0.0", resolved: `https://registry.npmjs.org/pkg-${i}/-/pkg-${i}-1.0.0.tgz`, integrity: `sha512-${"x".repeat(200)}` };
    const lock = JSON.stringify({ lockfileVersion: 3, packages }, null, 2);
    expect(lock.length).toBeGreaterThan(2 * 1024 * 1024);
    const root = project({ "package.json": '{"name":"big"}', "package-lock.json": lock });
    const queried: number[] = [];
    const net = {
      postJson: (_url: string, body: unknown) => {
        queried.push((body as { queries: unknown[] }).queries.length);
        return Promise.resolve({ status: 200, body: { results: [] } });
      },
      getJson: () => Promise.reject(new Error("unexpected")),
    };
    const { result } = await runShip({ root, write: false, onlyRules: ["core/vulnerable-dependency"], net });
    expect(result.coverage.ran).toBe(1);
    expect(queried).toEqual([1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000]);
  });

  it("ignores a symlinked lockfile and reports unsupported lockfiles while the rule runs", async () => {
    const outside = project({ "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/x": { version: "1.0.0" } } }) });
    const root = project({
      "package.json": '{"name":"root"}',
      "apps/web/package.json": '{"name":"web"}',
      "apps/web/package-lock.json": JSON.stringify({ lockfileVersion: 1, dependencies: {} }),
      "apps/api/package.json": '{"name":"api"}',
      "apps/api/bun.lockb": "\u0000binary",
      "svc/requirements.txt": "fastapi==0.110.0\n",
    });
    symlinkSync(join(outside, "package-lock.json"), join(root, "package-lock.json"));
    const queries: unknown[] = [];
    const net = {
      postJson: (_url: string, body: unknown) => {
        queries.push(...(body as { queries: unknown[] }).queries);
        return Promise.resolve({ status: 200, body: { results: [{}] } });
      },
      getJson: () => Promise.reject(new Error("unexpected")),
    };
    const { result } = await runShip({ root, write: false, onlyRules: ["core/vulnerable-dependency"], net });
    expect(queries).toEqual([{ package: { ecosystem: "PyPI", name: "fastapi" }, version: "0.110.0" }]);
    expect(result.coverage.notChecked).toContainEqual({ area: "Dependencies in apps/web/package-lock.json", reason: "lockfileVersion 1 is not supported (v2 and v3 are)" });
    expect(result.coverage.notChecked).toContainEqual({ area: "Dependencies in apps/api/bun.lockb", reason: "lockfile format not supported in v1" });
  });
});
