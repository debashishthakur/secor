// core/secrets: git history, .env tracked/ignored semantics, gaps, evidence redaction and the history parser.

import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { detectSecrets } from "../../src/engine/detectors/index.js";
import { resetGitCache } from "../../src/engine/files.js";
import { isEnvTemplate, parseGitLog, secretEvidence } from "../../src/engine/rules/core/secrets.js";
import { runShip } from "../../src/ship/run.js";
import type { RunResult } from "../../src/types.js";
import { FAKE, FIXTURES, cleanup, git, listCases, prepareFixture, runCase } from "../helpers/fixtures.js";

const temp: string[] = [];
const saved = { HOME: process.env.HOME, SECOR_HOME: process.env.SECOR_HOME, PATH: process.env.PATH };
const CLT = "/Library/Developer/CommandLineTools/usr/bin";

beforeAll(() => {
  const home = mkdtempSync(join(tmpdir(), "secor-home-"));
  temp.push(home);
  process.env.HOME = home;
  process.env.SECOR_HOME = join(home, ".secor");
  // /usr/bin/git can be an unusable Xcode shim; prefer the Command Line Tools git when present.
  if (existsSync(join(CLT, "git"))) process.env.PATH = `${CLT}:${process.env.PATH ?? ""}`;
  resetGitCache();
});

afterAll(() => {
  process.env.HOME = saved.HOME;
  process.env.SECOR_HOME = saved.SECOR_HOME;
  process.env.PATH = saved.PATH;
  resetGitCache();
  temp.forEach(cleanup);
});

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "secor-core-secrets-"));
  temp.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

function initRepo(dir: string): void {
  git(dir, "init", "-q", "-b", "main");
}

function commitAll(dir: string, message: string): string {
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", message, "--allow-empty");
  return git(dir, "rev-parse", "HEAD").trim();
}

async function ship(root: string): Promise<RunResult> {
  const { result } = await runShip({ root, write: false, offline: true, onlyRules: ["core/secrets"] });
  return result;
}

const secretFindings = (r: RunResult) => r.findings.filter((f) => f.ruleId === "core/secrets");

function expectNoRawSecrets(r: RunResult): void {
  const json = JSON.stringify(r);
  for (const [name, value] of Object.entries(FAKE)) {
    // Public-by-design values (publishable keys, anon JWTs, PostHog) may appear verbatim.
    if (["STRIPE_PUBLISHABLE", "SUPABASE_PUBLISHABLE", "ANON_JWT", "POSTHOG"].includes(name)) continue;
    expect(json.includes(value), `raw ${name} leaked`).toBe(false);
    // Nor a long fragment of its secret part (a partially cut secret is still a leak). Redaction keeps known
    // prefixes such as "sk_live_" and a private key's BEGIN line on purpose, so fragments skip those.
    const parts = name === "PRIVATE_KEY" ? value.split("\n").slice(1, -1) : [value.slice(12, 32)];
    for (const part of parts) if (part.length >= 16) expect(json.includes(part), `fragment of ${name} leaked`).toBe(false);
  }
}

describe("core/secrets with git", () => {
  it("reports a secret that exists only in git history, at the historical location, naming the commit", async () => {
    const root = project({ "src/config.ts": `// config\nexport const stripeKey = "${FAKE.STRIPE_LIVE}";\n` });
    initRepo(root);
    const added = commitAll(root, "add config");
    writeFileSync(join(root, "src/config.ts"), "// config\nexport const stripeKey = process.env.STRIPE_KEY;\n");
    commitAll(root, "remove key");
    const r = await ship(root);
    const fs = secretFindings(r);
    expect(fs).toHaveLength(1);
    expect(fs[0]!.severity).toBe("critical");
    expect(fs[0]!.location).toEqual({ file: "src/config.ts", line: 2 });
    expect(fs[0]!.evidence).toContain("git history");
    expect(fs[0]!.evidence).toContain(added.slice(0, 12));
    expect(fs[0]!.evidence).toContain("sk_live_…");
    expect(fs[0]!.fix.humanAction).toBe("Rotate this key at the provider, then load it from an environment variable.");
    expect(fs[0]!.fix.patch).toBeUndefined();
    expect(fs[0]!.fix.testTemplate).toBeUndefined();
    expect(r.coverage.notChecked.some((n) => n.area === "Git history")).toBe(false);
    expectNoRawSecrets(r);
  });

  it("merges a secret found in the current file and in history into one finding", async () => {
    const root = project({ ".env": `OPENAI_API_KEY=${FAKE.OPENAI}\n` });
    initRepo(root);
    commitAll(root, "env");
    const fs = secretFindings(await ship(root));
    expect(fs).toHaveLength(1);
    expect(fs[0]!.location.file).toBe(".env");
    expect(fs[0]!.evidence).toContain("also in git history");
  });

  it("keeps the oldest commit that added a history-only secret", async () => {
    const root = project({ "a.txt": `token: "${FAKE.GITHUB}"\n` });
    initRepo(root);
    const first = commitAll(root, "first");
    writeFileSync(join(root, "a.txt"), "nothing\n");
    commitAll(root, "drop");
    writeFileSync(join(root, "a.txt"), `token: "${FAKE.GITHUB}"\n`);
    const second = commitAll(root, "again");
    writeFileSync(join(root, "a.txt"), "nothing\n");
    commitAll(root, "drop again");
    const fs = secretFindings(await ship(root));
    expect(fs).toHaveLength(1);
    expect(fs[0]!.evidence).toContain(first.slice(0, 12));
    expect(fs[0]!.evidence).not.toContain(second.slice(0, 12));
  });

  it("fires on a .env that is tracked even though .gitignore now covers it", async () => {
    const root = project({ ".env": `STRIPE_SECRET_KEY=${FAKE.STRIPE_LIVE}\n`, "src/index.ts": "export {};\n" });
    initRepo(root);
    commitAll(root, "initial");
    writeFileSync(join(root, ".gitignore"), ".env\n");
    commitAll(root, "ignore env");
    const fs = secretFindings(await ship(root));
    expect(fs.map((f) => [f.location.file, f.severity])).toEqual([[".env", "critical"]]);
  });

  it("fires on an untracked .env that no .gitignore covers, without a history note", async () => {
    const root = project({ "src/index.ts": "export {};\n" });
    initRepo(root);
    commitAll(root, "initial");
    writeFileSync(join(root, ".env.local"), `ANTHROPIC_API_KEY=${FAKE.ANTHROPIC}\n`);
    const fs = secretFindings(await ship(root));
    expect(fs).toHaveLength(1);
    expect(fs[0]!.location.file).toBe(".env.local");
    expect(fs[0]!.evidence).not.toContain("git history");
  });

  it("does not fire on an untracked, gitignored .env", async () => {
    const root = project({ ".gitignore": ".env\n", "src/index.ts": "export {};\n" });
    initRepo(root);
    commitAll(root, "initial");
    writeFileSync(join(root, ".env"), `ANTHROPIC_API_KEY=${FAKE.ANTHROPIC}\n`);
    expect(secretFindings(await ship(root))).toEqual([]);
  });

  it("still reports a .env committed in the past and ignored now", async () => {
    const root = project({ ".env": `OPENAI_API_KEY=${FAKE.OPENAI}\n` });
    initRepo(root);
    commitAll(root, "oops");
    git(root, "rm", "-q", "--cached", ".env");
    writeFileSync(join(root, ".gitignore"), ".env\n");
    commitAll(root, "untrack env");
    const fs = secretFindings(await ship(root));
    expect(fs).toHaveLength(1);
    expect(fs[0]!.location.file).toBe(".env");
    expect(fs[0]!.evidence).toContain("git history");
  });

  it("skips history hunks whose value the current file still holds without it being a finding (Firebase config)", async () => {
    const cfg = (key: string) => `export const firebaseConfig = {\n  apiKey: "${key}",\n  authDomain: "demo.firebaseapp.com",\n  projectId: "demo",\n};\n`;
    const root = project({ "src/firebase.ts": cfg("") });
    initRepo(root);
    commitAll(root, "config");
    // A one-line change: the hunk has no authDomain/projectId context.
    writeFileSync(join(root, "src/firebase.ts"), cfg(FAKE.GOOGLE!));
    commitAll(root, "rotate web key");
    expect(secretFindings(await ship(root))).toEqual([]);
  });

  it("handles a repository with no commits", async () => {
    const root = project({ "src/index.ts": "export {};\n" });
    initRepo(root);
    const r = await ship(root);
    expect(secretFindings(r)).toEqual([]);
    expect(r.coverage.notChecked.filter((n) => n.area === "Git history")).toEqual([]);
  });

  it("scans the history of a project that is a subdirectory of a repository with paths relative to it", async () => {
    const root = project({ "apps/api/src/key.ts": `export const k = "${FAKE.SENDGRID}";\n`, "other/x.ts": `export const k = "${FAKE.SLACK}";\n` });
    initRepo(root);
    commitAll(root, "both");
    writeFileSync(join(root, "apps/api/src/key.ts"), "export const k = process.env.K;\n");
    writeFileSync(join(root, "other/x.ts"), "export const k = 1;\n");
    commitAll(root, "clean");
    const fs = secretFindings(await ship(join(root, "apps/api")));
    expect(fs.map((f) => f.location.file)).toEqual(["src/key.ts"]);
  });
});

describe("core/secrets gaps", () => {
  it("records 'not a git repository' outside git and still runs", async () => {
    const root = project({ "src/a.ts": `export const k = "${FAKE.OPENAI}";\n` });
    const r = await ship(root);
    expect(secretFindings(r)).toHaveLength(1);
    expect(r.coverage.notChecked).toContainEqual({ area: "Git history", reason: "not a git repository" });
    expect(r.coverage.ran).toBe(r.coverage.applicable);
  });

  it("records 'git not available' when no git binary works", async () => {
    const root = project({ "src/a.ts": "export {};\n" });
    const path = process.env.PATH;
    process.env.PATH = join(root, "no-bin-here");
    resetGitCache();
    try {
      const r = await ship(root);
      expect(r.coverage.notChecked).toContainEqual({ area: "Git history", reason: "git not available" });
      expect(r.coverage.ran).toBe(r.coverage.applicable);
    } finally {
      process.env.PATH = path;
      resetGitCache();
    }
  });
});

describe("core/secrets redaction", () => {
  it("never puts a raw secret in any output field, for every core/secrets fixture", async () => {
    const cases = listCases(join(FIXTURES, "core", "secrets"));
    expect(cases.length).toBeGreaterThan(5);
    for (const c of cases) {
      const { result, root } = await runCase(c);
      temp.push(root);
      expectNoRawSecrets(result);
      for (const f of result.findings) expect([...f.evidence].length).toBeLessThanOrEqual(200);
    }
  });

  it("keeps the history note within the evidence limit on very long lines", async () => {
    const long = `const x = "${"a".repeat(300)}"; const key = "${FAKE.ANTHROPIC}"; const y = "${"b".repeat(300)}";\n`;
    const root = project({ "src/long.ts": long });
    initRepo(root);
    commitAll(root, "long");
    const fs = secretFindings(await ship(root));
    expect(fs).toHaveLength(1);
    expect([...fs[0]!.evidence].length).toBeLessThanOrEqual(200);
    expect(fs[0]!.evidence).toContain("sk-ant-…");
    expect(fs[0]!.evidence).toContain("(also in git history)");
  });

  it("windows evidence around the value and redacts it even when the line alone would not re-detect it", () => {
    const text = `aws_secret_access_key =\n  "${FAKE.AWS_SECRET}"\n`;
    const m = detectSecrets(text, { configLike: true }).find((x) => x.kind === "aws-secret-key")!;
    expect(m).toBeDefined();
    const ev = secretEvidence(text, m);
    expect(ev).not.toContain(FAKE.AWS_SECRET);
    expect(ev).not.toContain(FAKE.AWS_SECRET!.slice(2, 30));
  });

  it("redacts a whole private key block", () => {
    const text = `key:\n${FAKE.PRIVATE_KEY}\nend\n`;
    const m = detectSecrets(text).find((x) => x.kind === "private-key")!;
    const ev = secretEvidence(text, m);
    // The header is assembled at runtime so this file holds no secret-shaped literal.
    const header = FAKE.PRIVATE_KEY!.split("\n")[0]!;
    expect(header).toMatch(/^-{5}BEGIN RSA PRIVATE/);
    expect(ev.startsWith(`${header}…`)).toBe(true);
    for (const line of FAKE.PRIVATE_KEY!.split("\n").slice(1, -1)) expect(ev).not.toContain(line);
  });
});

describe("core/secrets fixtures (temp copies)", () => {
  it("one finding per value per file, even when the value repeats", async () => {
    const root = prepareFixture(join(FIXTURES, "core", "secrets", "vulnerable", "openai-in-code"));
    temp.push(root);
    writeFileSync(join(root, "src/again.ts"), `export const a = "${FAKE.OPENAI}";\nexport const b = "${FAKE.OPENAI}";\n`);
    const fs = secretFindings(await ship(root)).filter((f) => f.location.file === "src/again.ts");
    expect(fs).toHaveLength(1);
    expect(fs[0]!.location.line).toBe(1);
  });
});

describe("isEnvTemplate", () => {
  it("matches the template names only", () => {
    for (const f of [".env.example", "app/.env.sample", ".env.template", ".env.local.example", ".ENV.EXAMPLE"]) expect(isEnvTemplate(f)).toBe(true);
    for (const f of [".env", ".env.local", ".env.production", "example.env", "src/.env.examples", "env.example"]) expect(isEnvTemplate(f)).toBe(false);
  });
});

describe("parseGitLog", () => {
  const sha1 = "a".repeat(40);
  const sha2 = "b".repeat(40);

  it("tracks files, hunk line numbers and contiguous added blocks", () => {
    const out = [
      `commit ${sha1}`,
      "",
      "diff --git a/src/x.ts b/src/x.ts",
      "index 1..2 100644",
      "--- a/src/x.ts",
      "+++ b/src/x.ts",
      "@@ -2 +2 @@ fn",
      "-old",
      "+new2",
      "@@ -10,0 +11,2 @@",
      "+eleven",
      "+twelve",
      "diff --git a/gone.ts b/gone.ts",
      "deleted file mode 100644",
      "--- a/gone.ts",
      "+++ /dev/null",
      "@@ -1 +0,0 @@",
      "-bye",
      `commit ${sha2}`,
      "",
      'diff --git "a/we\\"ird.txt" "b/we\\"ird.txt"',
      "new file mode 100644",
      "--- /dev/null",
      '+++ "b/we\\"ird.txt"',
      "@@ -0,0 +1,2 @@",
      "+++ not a header",
      "+second",
      "\\ No newline at end of file",
      "diff --git a/dir with space/f.txt b/dir with space/f.txt",
      "--- /dev/null",
      "+++ b/dir with space/f.txt\t",
      "@@ -0,0 +1 @@",
      "+k=1",
      "diff --git a/t\\303\\251st.txt b/t\\303\\251st.txt",
      "--- /dev/null",
      '+++ "b/t\\303\\251st.txt"',
      "@@ -0,0 +1 @@",
      "+v",
    ].join("\n");
    expect(parseGitLog(out)).toEqual([
      { commit: sha1, file: "src/x.ts", startLine: 2, text: "new2" },
      { commit: sha1, file: "src/x.ts", startLine: 11, text: "eleven\ntwelve" },
      { commit: sha2, file: 'we"ird.txt', startLine: 1, text: "++ not a header\nsecond" },
      { commit: sha2, file: "dir with space/f.txt", startLine: 1, text: "k=1" },
      { commit: sha2, file: "tést.txt", startLine: 1, text: "v" },
    ]);
  });

  it("returns nothing for empty output", () => {
    expect(parseGitLog("")).toEqual([]);
  });
});
