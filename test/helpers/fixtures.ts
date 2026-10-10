// Test helpers: copy a fixture project to a temp dir (substituting fake-secret tokens), run Ship on it,
// and compare findings with the case's expectations.
//
// Fixture layout: test/fixtures/<pack>/<rule>/<vulnerable|clean>/<case>/
//   case.json  { "rule": "api/missing-auth", "expect": [{ "severity": "critical", "file": "src/app.ts", "line": 4 }], ... }
//   ...project files (package.json / requirements.txt / sources)
// Fake secrets: write tokens such as __FAKE_OPENAI__ in fixture files; they are replaced at test time so the
// repository never contains secret-shaped strings.

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import type { NetClient, NetResponse } from "../../src/engine/net.js";
import { runShip } from "../../src/ship/run.js";
import type { Finding, RunResult } from "../../src/types.js";

export const FIXTURES = join(import.meta.dirname, "..", "fixtures");

// ---------------------------------------------------------------- deterministic fake secrets

function prng(seed: string): () => number {
  let h = 2166136261;
  for (const ch of seed) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
  return () => {
    h ^= h << 13;
    h ^= h >>> 17;
    h ^= h << 5;
    return (h >>> 0) / 4294967296;
  };
}

function rand(seed: string, len: number, alphabet: string): string {
  const r = prng(seed);
  let out = "";
  while (out.length < len) {
    out += alphabet[Math.floor(r() * alphabet.length)];
    if (/xxx|your|example|dummy|changeme/i.test(out)) out = out.slice(0, -3);
  }
  return out;
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const URLSAFE = `${ALNUM}_-`;

function jwt(role: string, seed: string): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", ref: rand(`${seed}ref`, 20, "abcdefghijklmnopqrstuvwxyz"), role, iat: 1700000000, exp: 2000000000 })}.${rand(`${seed}sig`, 43, URLSAFE)}`;
}

/** Fake secrets by token name. Every value matches its detector pattern and is not a placeholder. */
export const FAKE = {
  AWS_ACCESS_KEY: `AKIA${rand("aws", 16, UPPER_NUM)}`,
  AWS_SECRET: rand("awssecret", 40, `${ALNUM}/+`),
  GITHUB: `ghp_${rand("gh", 36, ALNUM)}`,
  STRIPE_LIVE: `sk_live_${rand("stripe", 24, ALNUM)}`,
  STRIPE_TEST: `sk_test_${rand("stripetest", 24, ALNUM)}`,
  STRIPE_PUBLISHABLE: `pk_live_${rand("stripepk", 24, ALNUM)}`,
  ANTHROPIC: `sk-ant-api03-${rand("anthropic", 40, URLSAFE)}`,
  OPENAI: `sk-proj-${rand("openai", 40, URLSAFE)}`,
  SLACK: `xoxb-${rand("slack1", 11, "0123456789")}-${rand("slack2", 24, ALNUM)}`,
  SENDGRID: `SG.${rand("sg1", 22, URLSAFE)}.${rand("sg2", 43, URLSAFE)}`,
  GOOGLE: `AIza${rand("google", 35, URLSAFE)}`,
  SUPABASE_SECRET: `sb_secret_${rand("sbsecret", 30, URLSAFE)}`,
  SUPABASE_PUBLISHABLE: `sb_publishable_${rand("sbpub", 30, URLSAFE)}`,
  SERVICE_ROLE_JWT: jwt("service_role", "svc"),
  ANON_JWT: jwt("anon", "anon"),
  GENERIC: rand("generic", 32, ALNUM),
  POSTHOG: `phc_${rand("posthog", 40, ALNUM)}`,
  // Header/footer assembled from fragments so the repo holds no PRIVATE KEY literal; the runtime value is unchanged.
  PRIVATE_KEY: `-----BEGIN RSA ${"PRIVATE"} KEY-----\n${rand("pem1", 64, `${ALNUM}+/`)}\n${rand("pem2", 64, `${ALNUM}+/`)}\n-----END RSA ${"PRIVATE"} KEY-----`,
  DB_PASSWORD: rand("dbpw", 20, ALNUM),
  SLACK_WEBHOOK: `https://hooks.${"slack"}.com/services/T${rand("swh1", 8, UPPER_NUM)}/B${rand("swh2", 8, UPPER_NUM)}/${rand("swh3", 24, ALNUM)}`,
} satisfies Record<string, string>;

/** The PEM header of FAKE.PRIVATE_KEY, built at runtime so no source file holds a key-shaped header. */
export const PEM_HEADER = ["-----BEGIN RSA", "PRIVATE KEY-----"].join(" ");

const FAKE_BY_NAME: Record<string, string> = FAKE;

export function substituteFakes(text: string): string {
  return text.replace(/__FAKE_([A-Z_]+?)__/g, (whole, name: string) => (Object.hasOwn(FAKE_BY_NAME, name) ? FAKE_BY_NAME[name]! : whole));
}

// ---------------------------------------------------------------- fixtures

export interface CaseSpec {
  rule: string;
  expect: { severity: string; file: string; line?: number; advisory?: boolean; evidenceIncludes?: string }[];
  /** Default true: the number of findings for the rule must equal expect.length. */
  exact?: boolean;
  offline?: boolean;
  /** Initialise a git repo and commit the fixture (needed for tracked/ignored checks). */
  git?: boolean;
  /** JSON file in the case dir mapping "METHOD URL" to { status, body } for a mocked network. */
  net?: string;
  /** Run these extra rules too (defaults to just `rule`). */
  rules?: string[];
}

export interface FixtureCase {
  dir: string;
  name: string;
  variant: "vulnerable" | "clean";
  spec: CaseSpec;
}

/** All fixture cases under test/fixtures (dirs that contain case.json). */
export function listCases(root = FIXTURES): FixtureCase[] {
  const out: FixtureCase[] = [];
  const visit = (dir: string) => {
    if (!existsSync(dir)) return;
    if (existsSync(join(dir, "case.json"))) {
      const rel = relative(root, dir).split("/");
      const variant = rel.includes("vulnerable") ? "vulnerable" : "clean";
      out.push({ dir, name: rel.join("/"), variant, spec: JSON.parse(readFileSync(join(dir, "case.json"), "utf8")) as CaseSpec });
      return;
    }
    for (const e of readdirSync(dir).sort()) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) visit(p);
    }
  };
  visit(root);
  return out;
}

function substituteTree(dir: string): void {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const st = statSync(p);
    if (st.isDirectory()) substituteTree(p);
    else if (st.size < 1_000_000) {
      const text = readFileSync(p, "utf8");
      if (text.includes("__FAKE_")) writeFileSync(p, substituteFakes(text));
    }
  }
}

export const GIT = existsSync("/Library/Developer/CommandLineTools/usr/bin/git") ? "/Library/Developer/CommandLineTools/usr/bin/git" : "git";

export function git(cwd: string, ...args: string[]): string {
  return execFileSync(GIT, args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t.invalid", GIT_CONFIG_NOSYSTEM: "1" },
  });
}

/** Copy a fixture (minus case.json) to a fresh temp dir with fake secrets substituted. */
export function prepareFixture(srcDir: string, opts: { git?: boolean } = {}): string {
  const dest = mkdtempSync(join(tmpdir(), "secor-fx-"));
  cpSync(srcDir, dest, { recursive: true, filter: (s) => !s.endsWith("case.json") && !s.endsWith("net.json") });
  substituteTree(dest);
  if (opts.git) {
    git(dest, "init", "-q", "-b", "main");
    git(dest, "add", "-A");
    git(dest, "commit", "-q", "-m", "fixture", "--allow-empty");
  }
  return dest;
}

export function cleanup(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

/** A NetClient that answers from a map of "METHOD URL" → response and fails on anything else. */
export function mockNet(responses: Record<string, NetResponse>, log: string[] = []): NetClient {
  const answer = (key: string): Promise<NetResponse> => {
    log.push(key);
    const r = responses[key] ?? responses[key.replace(/\?.*$/, "")];
    if (!r) return Promise.reject(new Error(`unmocked network request: ${key}`));
    return Promise.resolve(r);
  };
  return {
    getJson: (url) => answer(`GET ${url}`),
    postJson: (url) => answer(`POST ${url}`),
  };
}

export async function runCase(c: FixtureCase): Promise<{ result: RunResult; findings: Finding[]; root: string }> {
  const root = prepareFixture(c.dir, { git: c.spec.git });
  const netFile = c.spec.net ? join(c.dir, c.spec.net) : null;
  const net = netFile ? mockNet(JSON.parse(readFileSync(netFile, "utf8")) as Record<string, NetResponse>) : undefined;
  const { result } = await runShip({ root, write: false, offline: c.spec.offline ?? !net, onlyRules: c.spec.rules ?? [c.spec.rule], ...(net ? { net } : {}) });
  return { result, findings: result.findings.filter((f) => f.ruleId === c.spec.rule), root };
}

/** Run Ship over a fixture directory directly (for inventory / pipeline tests). */
export async function runFixture(srcDir: string, opts: { onlyRules?: string[]; offline?: boolean; git?: boolean; net?: NetClient } = {}): Promise<{ result: RunResult; root: string }> {
  const root = prepareFixture(srcDir, { git: opts.git });
  const { result } = await runShip({ root, write: false, offline: opts.offline ?? true, ...(opts.onlyRules ? { onlyRules: opts.onlyRules } : {}), ...(opts.net ? { net: opts.net } : {}) });
  return { result, root };
}

/** Human-readable mismatch report (empty string = match). */
export function compareExpect(c: FixtureCase, findings: Finding[]): string {
  const problems: string[] = [];
  const pool = [...findings];
  for (const e of c.spec.expect) {
    const idx = pool.findIndex(
      (f) =>
        f.severity === e.severity &&
        f.location.file === e.file &&
        (e.line === undefined || f.location.line === e.line) &&
        (e.advisory === undefined || f.advisory === e.advisory) &&
        (e.evidenceIncludes === undefined || f.evidence.includes(e.evidenceIncludes)),
    );
    if (idx < 0) problems.push(`missing: ${JSON.stringify(e)}`);
    else pool.splice(idx, 1);
  }
  if ((c.spec.exact ?? true) && pool.length) problems.push(`unexpected: ${pool.map((f) => `${f.severity} ${f.location.file}:${f.location.line} ${f.evidence}`).join(" | ")}`);
  return problems.join("\n");
}
