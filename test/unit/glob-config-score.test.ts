// Globs, .gitignore semantics, config validation (spec 6), and the score (spec 10 + the 15 worked examples).

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ConfigError, loadIgnoreFile, loadProjectConfig } from "../../src/engine/config.js";
import { parseGitignore } from "../../src/engine/files.js";
import { band, computeScore, kindsOf, scoreFindings, serverScore } from "../../src/engine/score.js";
import { matchesGlob } from "../../src/engine/util/glob.js";
import type { Finding, ServiceKind, ServiceUnit, Severity } from "../../src/types.js";

describe("globs", () => {
  const t: [string, string, boolean][] = [
    ["node_modules/x/y.js", "**/node_modules/**", true],
    ["a/node_modules/x.js", "**/node_modules/**", true],
    ["node_modulesx/y.js", "**/node_modules/**", false],
    ["public/app.min.js", "**/*.min.js", true],
    ["deep/dir/app.min.js", "*.min.js", true],
    ["src/a.ts", "src/**/*.ts", true],
    ["src/x/y/a.ts", "src/**/*.ts", true],
    ["lib/a.ts", "src/**/*.ts", false],
    ["src/a.tsx", "src/*.{ts,tsx}", true],
    ["src/b.js", "src/[ab].js", true],
    ["src/c.js", "src/[!ab].js", true],
    ["src/a.js", "src/[!ab].js", false],
    ["vendor/lib/x.js", "vendor/", true],
    ["vendorx/lib.js", "vendor/", false],
    ["a.test.ts", "*.test.ts", true],
    ["x/a.test.ts", "*.test.ts", true],
  ];
  for (const [path, pat, want] of t) it(`${pat} ~ ${path} → ${want}`, () => expect(matchesGlob(path, pat)).toBe(want));
});

describe(".gitignore rules", () => {
  const ignored = (text: string, path: string, isDir = false) => {
    let res = false;
    for (const r of parseGitignore(text, "")) {
      if (r.dirOnly && !isDir) continue;
      if (r.re.test(path)) res = !r.negate;
    }
    return res;
  };
  it("basename patterns at any depth, anchored patterns, negation, dir-only, comments", () => {
    const gi = "# comment\n.env\n*.log\n!keep.log\n/build\nlogs/\nsecrets/*.key\n";
    expect(ignored(gi, ".env")).toBe(true);
    expect(ignored(gi, "app/.env")).toBe(true);
    expect(ignored(gi, "a/b.log")).toBe(true);
    expect(ignored(gi, "keep.log")).toBe(false);
    expect(ignored(gi, "build", true)).toBe(true);
    expect(ignored(gi, "src/build", true)).toBe(false);
    expect(ignored(gi, "logs", true)).toBe(true);
    expect(ignored(gi, "logs", false)).toBe(false);
    expect(ignored(gi, "secrets/a.key")).toBe(true);
    expect(ignored(gi, "x/secrets/a.key")).toBe(false);
  });
});

describe("config validation", () => {
  const project = (files: Record<string, string>) => {
    const dir = mkdtempSync(join(tmpdir(), "secor-cfg-"));
    for (const [f, c] of Object.entries(files)) {
      mkdirSync(join(dir, f, ".."), { recursive: true });
      writeFileSync(join(dir, f), c);
    }
    return dir;
  };

  it("defaults when the file is missing", () => {
    const c = loadProjectConfig(project({}));
    expect(c).toMatchObject({ version: 1, packs: "auto", exclude: [], public: [], gate: { failOn: "critical" }, network: true, mcp: { deployment: "auto" } });
  });

  it("unknown keys are an error naming the key", () => {
    expect(() => loadProjectConfig(project({ "secor.config.yaml": "version: 1\nfoo: 1\n" }))).toThrow(/unknown key "foo"/);
    expect(() => loadProjectConfig(project({ "secor.config.yaml": "version: 1\ngate:\n  failOn: high\n  extra: 1\n" }))).toThrow(/gate: unknown key "extra"/);
  });

  it("public entries need a non-empty reason and a valid shape", () => {
    expect(() => loadProjectConfig(project({ "secor.config.yaml": 'version: 1\npublic:\n  - route: "GET /api/health"\n    reason: ""\n' }))).toThrow(ConfigError);
    expect(() => loadProjectConfig(project({ "secor.config.yaml": 'version: 1\npublic:\n  - route: "/api/health"\n    reason: "x"\n' }))).toThrow(ConfigError);
    expect(() => loadProjectConfig(project({ "secor.config.yaml": 'version: 1\npublic:\n  - action: "app/actions.ts"\n    reason: "x"\n' }))).toThrow(ConfigError);
    const ok = loadProjectConfig(project({ "secor.config.yaml": 'version: 1\npublic:\n  - route: "* /api/health"\n    reason: "uptime"\n  - mcpServer: src/server.ts\n    reason: "docs"\n' }));
    expect(ok.public).toHaveLength(2);
  });

  it("version must be 1 and YAML must parse", () => {
    expect(() => loadProjectConfig(project({ "secor.config.yaml": "version: 2\n" }))).toThrow(ConfigError);
    expect(() => loadProjectConfig(project({ "secor.config.yaml": "version: [1\n" }))).toThrow(/invalid YAML/);
  });

  it("ignore entries need finding, reason, by and a YYYY-MM-DD date", () => {
    const good = 'version: 1\nignores:\n  - finding: "api-missing-auth-3f9a1c2b7d4e"\n    reason: "VPN only"\n    by: "Debashish"\n    date: "2026-10-10"\n';
    expect(loadIgnoreFile(project({ ".secor/ignore.yaml": good })).ignores).toHaveLength(1);
    expect(() => loadIgnoreFile(project({ ".secor/ignore.yaml": good.replace('    by: "Debashish"\n', "") }))).toThrow(ConfigError);
    expect(() => loadIgnoreFile(project({ ".secor/ignore.yaml": good.replace("2026-10-10", "10/10/2026") }))).toThrow(/YYYY-MM-DD/);
  });
});

// ---------------------------------------------------------------- score

let n = 0;
function f(severity: Severity, service: ServiceKind | "core", over: Partial<Finding> = {}): Finding {
  n++;
  return {
    id: `x-${n}`,
    ruleId: "x/y",
    title: "t",
    severity,
    advisory: false,
    maturity: "stable",
    service,
    location: { file: `f${n}.ts`, line: 1 },
    evidence: "",
    why: "",
    fix: { summary: "" },
    status: "open",
    ...over,
  };
}
const units: ServiceUnit[] = [
  { kind: "api", framework: "express", root: "" },
  { kind: "mcp", framework: "mcp-ts", root: "" },
  { kind: "web", framework: "vite", root: "" },
];

describe("score (scoring version 1)", () => {
  it("Example A", () => {
    const fs = [
      f("high", "api"),
      f("medium", "api"),
      f("medium", "api"),
      f("low", "api"),
      f("low", "api"),
      f("high", "mcp"),
      f("medium", "mcp"),
      f("low", "mcp"),
      f("medium", "web"),
      f("low", "web"),
      f("low", "web"),
      f("low", "web"),
    ];
    const github = serverScore({ vetted: true, scoped: true, transport: "http", sandbox: "n/a", changed: false, vetVerdict: "ok" });
    const notion = serverScore({ vetted: true, scoped: true, transport: "http", sandbox: "n/a", changed: true, vetVerdict: "ok" });
    const random = serverScore({ vetted: true, scoped: false, transport: "stdio", sandbox: "yes", changed: false, vetVerdict: "ok" });
    expect([github, notion, random]).toEqual([100, 90, 80]);
    const connect = Math.min(github, notion, random); // hooks on
    const s = computeScore(fs, units, 100, connect);
    expect(s.shipByKind).toEqual({ api: 79, mcp: 79, web: 94 });
    expect(s.ship).toBe(79);
    expect(s.connect).toBe(80);
    expect(s.overall).toBe(79);
    expect(s.band).toBe("needs-work");
  });

  it("Example B: one counted critical in web caps overall at 49", () => {
    const s = computeScore([f("critical", "web")], units, 100, 100);
    expect(s.shipByKind.web).toBeLessThanOrEqual(49);
    expect(s.overall).toBeLessThanOrEqual(49);
    expect(s.band).toBe("fix-before-deploy");
  });

  it("Example C: no servers → connect null → overall = ship", () => {
    const s = computeScore([f("medium", "api")], units, 100, null);
    expect(s.connect).toBeNull();
    expect(s.overall).toBe(s.ship);
  });

  it("only counted findings matter (open, not advisory, stable)", () => {
    expect(scoreFindings([f("critical", "api", { advisory: true }), f("critical", "api", { maturity: "experimental" }), f("critical", "api", { status: "ignored" })])).toBe(100);
  });

  it("floors at 0 and caps by worst severity", () => {
    expect(scoreFindings(Array.from({ length: 10 }, () => f("critical", "api")))).toBe(0);
    expect(scoreFindings([f("high", "api")])).toBe(79);
    expect(scoreFindings([f("medium", "api"), f("low", "api")])).toBe(96);
  });

  it("bands", () => {
    expect([band(0), band(49), band(50), band(79), band(80), band(100), band(null)]).toEqual([
      "fix-before-deploy",
      "fix-before-deploy",
      "needs-work",
      "needs-work",
      "no-known-critical-or-high",
      "no-known-critical-or-high",
      null,
    ]);
  });

  it("core findings attach to the units whose root contains the file, else to every unit", () => {
    const mono: ServiceUnit[] = [
      { kind: "api", framework: "express", root: "apps/api" },
      { kind: "web", framework: "vite", root: "apps/web" },
    ];
    expect([...kindsOf(f("low", "core", { location: { file: "apps/api/x.ts", line: 1 } }), mono)]).toEqual(["api"]);
    expect([...kindsOf(f("low", "core", { location: { file: "scripts/x.ts", line: 1 } }), mono)].sort()).toEqual(["api", "web"]);
    expect([...kindsOf(f("low", "web"), mono)]).toEqual(["web"]);
  });

  it("server score: unmanaged stdio = 25, unmanaged http = 50, verdict caps", () => {
    expect(serverScore({ vetted: false, scoped: false, transport: "stdio", sandbox: "no", changed: false, vetVerdict: null })).toBe(25);
    expect(serverScore({ vetted: false, scoped: false, transport: "http", sandbox: "n/a", changed: false, vetVerdict: null })).toBe(50);
    expect(serverScore({ vetted: true, scoped: true, transport: "http", sandbox: "n/a", changed: false, vetVerdict: "high-risk" })).toBe(49);
    expect(serverScore({ vetted: true, scoped: true, transport: "http", sandbox: "n/a", changed: false, vetVerdict: "review" })).toBe(79);
  });

  it("incomplete when coverage < 70%", () => {
    expect(computeScore([], units, 69, null).incomplete).toBe(true);
    expect(computeScore([], units, 70, null).incomplete).toBe(false);
  });

  it("no units → ship null; nothing at all → overall null", () => {
    const s = computeScore([f("critical", "core")], [], 100, null);
    expect(s).toMatchObject({ ship: null, overall: null, band: null });
  });
});
