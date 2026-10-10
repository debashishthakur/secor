// End-to-end CLI tests (spec 11.1): exit codes, JSON/text output, gate --base, init, redaction, no colour off-TTY.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { findingReasons } from "../src/ship/gate.js";
import type { Finding } from "../src/types.js";
import { buildCli } from "./helpers/build-cli.js";
import { FAKE, GIT, FIXTURES, git, prepareFixture } from "./helpers/fixtures.js";

let cli: string;
let home: string;

beforeAll(async () => {
  cli = await buildCli("cli-e2e");
  home = mkdtempSync(join(tmpdir(), "secor-cli-home-"));
});

function run(args: string[], cwd: string, input?: string) {
  const res = spawnSync(process.execPath, [cli, ...args], {
    cwd,
    input,
    encoding: "utf8",
    env: { ...process.env, HOME: home, SECOR_HOME: join(home, ".secor"), PATH: `${GIT.replace(/\/git$/, "")}:${process.env.PATH}`, NO_COLOR: "" },
    timeout: 60_000,
  });
  return { code: res.status, out: res.stdout, err: res.stderr };
}

const INV = (fw: string) => join(FIXTURES, "..", "inventory", "fixtures", fw);

describe("secor CLI", () => {
  it("--version and --help exit 0", () => {
    const v = run(["--version"], tmpdir());
    expect(v.code).toBe(0);
    expect(v.out.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    expect(run(["--help"], tmpdir()).code).toBe(0);
  });

  it("unknown command exits 2", () => {
    expect(run(["frobnicate"], tmpdir()).code).toBe(2);
  });

  it("ship --json prints a RunResult and exits 0", () => {
    const root = prepareFixture(INV("express"));
    const r = run(["ship", "--offline", "--json"], root);
    expect(r.code).toBe(0);
    const json = JSON.parse(r.out);
    expect(json.rulesVersion).toBe("1.0.0");
    expect(json.inventory.length).toBeGreaterThan(5);
    expect(existsSync(join(root, ".secor", "latest.json"))).toBe(true);
  });

  it("ship text output: band wording, notice, no 'secure', no ANSI colour when not a TTY", () => {
    const root = prepareFixture(INV("nextjs"));
    const r = run(["ship", "--offline"], root);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Overall");
    expect(r.out).toContain("It does not measure how hard your system is to attack.");
    expect(r.out.toLowerCase()).not.toMatch(/\bsecure\b|\bpassed\b/);
    expect(r.out).not.toContain("\x1b[");
  });

  it("ship [path] and --cwd", () => {
    const root = prepareFixture(INV("fastapi"));
    expect(run(["ship", root, "--offline", "--json"], tmpdir()).code).toBe(0);
    expect(run(["--cwd", root, "ship", "--offline", "--json"], tmpdir()).code).toBe(0);
  });

  it("invalid config exits 2 with a clear message", () => {
    const root = prepareFixture(INV("vite"));
    writeFileSync(join(root, "secor.config.yaml"), "version: 1\npacks: [api, nope]\n");
    const r = run(["ship", "--offline"], root);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/secor\.config\.yaml: packs/);
  });

  it("--packs validates its values", () => {
    expect(run(["ship", "--offline", "--packs", "api,bogus"], prepareFixture(INV("vite"))).code).toBe(2);
  });

  it("redacts secrets and personal data in text and JSON output", () => {
    const root = prepareFixture(INV("express"));
    mkdirSync(join(root, "config"), { recursive: true });
    writeFileSync(join(root, "config", "keys.ts"), `export const k = "${FAKE.OPENAI}"; // owner: jane.doe@acme.io\n`);
    const both = run(["ship", "--offline"], root).out + run(["ship", "--offline", "--json"], root).out + readFileSync(join(root, ".secor", "latest.json"), "utf8");
    expect(both).not.toContain(FAKE.OPENAI);
    expect(both).not.toContain("jane.doe@acme.io");
  });

  describe("gate", () => {
    it("passes (exit 0) with no counted findings", () => {
      const root = prepareFixture(INV("vite"));
      const r = run(["gate", "--offline"], root);
      expect(r.code).toBe(0);
      expect(r.out).toContain("Gate: no counted findings at or above critical.");
    });

    it("--base fails (exit 1) when public entries grew, and --accept-config-changes allows it", () => {
      const root = prepareFixture(INV("express"));
      git(root, "init", "-q", "-b", "main");
      writeFileSync(join(root, "secor.config.yaml"), "version: 1\npublic: []\n");
      git(root, "add", "-A");
      git(root, "commit", "-q", "-m", "base");
      writeFileSync(join(root, "secor.config.yaml"), 'version: 1\npublic:\n  - route: "GET /health"\n    reason: "uptime probe"\n');
      const fail = run(["gate", "--offline", "--base", "HEAD"], root);
      expect(fail.code).toBe(1);
      expect(fail.out).toMatch(/secor\.config\.yaml: public grew from 0 to 1 since HEAD/);
      expect(run(["gate", "--offline", "--base", "HEAD", "--accept-config-changes"], root).code).toBe(0);
      const j = JSON.parse(run(["gate", "--offline", "--base", "HEAD", "--json"], root).out);
      expect(j.status).toBe("fail");
    });

    it("--base also counts ignores, and a bad ref exits 2", () => {
      const root = prepareFixture(INV("vite"));
      git(root, "init", "-q", "-b", "main");
      git(root, "add", "-A");
      git(root, "commit", "-q", "-m", "base");
      mkdirSync(join(root, ".secor"), { recursive: true });
      writeFileSync(join(root, ".secor", "ignore.yaml"), 'version: 1\nignores:\n  - finding: "api-missing-auth-3f9a1c2b7d4e"\n    reason: "VPN"\n    by: "me"\n    date: "2026-10-10"\n');
      expect(run(["gate", "--offline", "--base", "HEAD"], root).code).toBe(1);
      expect(run(["gate", "--offline", "--base", "does-not-exist"], root).code).toBe(2);
      expect(run(["gate", "--offline", "--base", "--upload-pack=evil"], root).code).toBe(2);
    });

    it("fails on counted findings at or above --fail-on", () => {
      const mk = (severity: Finding["severity"], over: Partial<Finding> = {}): Finding => ({
        id: `x-${severity}`,
        ruleId: "api/missing-auth",
        title: "t",
        severity,
        advisory: false,
        maturity: "stable",
        service: "api",
        location: { file: "a.ts", line: 1 },
        evidence: "",
        why: "",
        fix: { summary: "" },
        status: "open",
        ...over,
      });
      expect(findingReasons([mk("high")], "critical")).toEqual([]);
      expect(findingReasons([mk("high")], "high")).toHaveLength(1);
      expect(findingReasons([mk("critical")], "critical")).toHaveLength(1);
      expect(findingReasons([mk("critical", { advisory: true }), mk("critical", { maturity: "experimental" }), mk("critical", { status: "ignored" })], "high")).toEqual([]);
    });
  });

  describe("init and finding", () => {
    it("init creates the config and .secor/.gitignore, and refuses to overwrite without a terminal", () => {
      const root = mkdtempSync(join(tmpdir(), "secor-init-"));
      expect(run(["init"], root).code).toBe(0);
      expect(readFileSync(join(root, "secor.config.yaml"), "utf8")).toContain("version: 1");
      expect(readFileSync(join(root, ".secor", ".gitignore"), "utf8")).toContain("runs/");
      const again = run(["init"], root);
      expect(again.code).toBe(2);
      expect(again.err).toMatch(/already exists/);
      expect(run(["ship", "--offline", "--json"], root).code).toBe(0);
    });

    it("finding exits 2 when there is no run or no such finding", () => {
      const root = mkdtempSync(join(tmpdir(), "secor-nofind-"));
      expect(run(["finding", "api-missing-auth-000000000000"], root).code).toBe(2);
      const proj = prepareFixture(INV("vite"));
      run(["ship", "--offline"], proj);
      const r = run(["finding", "api-missing-auth-000000000000"], proj);
      expect(r.code).toBe(2);
      expect(r.err).toMatch(/not in the latest run/);
    });
  });
});
