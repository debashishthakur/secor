// Shared helpers for SECOR Connect tests: isolated HOME / SECOR_HOME, demo server definitions, and fake secrets that
// are generated at run time (the repository never contains secret-shaped strings).

import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PromptIO } from "../../src/connect/add.js";
import type { DiscoveredServer } from "../../src/connect/discover.js";

export const CONNECT_DIR = import.meta.dirname;
export const SERVERS_DIR = join(CONNECT_DIR, "servers");
export const HOOK_CASES_DIR = join(CONNECT_DIR, "hooks");
export const REPO_ROOT = join(CONNECT_DIR, "..", "..");

export interface TempEnv {
  home: string;
  secorHome: string;
  project: string;
  restore(): void;
}

/** Point HOME and SECOR_HOME at fresh temp dirs (real paths, so symlinked /var does not confuse path checks). */
export function tempEnv(): TempEnv {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "secor-connect-")));
  const home = join(root, "home");
  const secorHome = join(home, ".secor");
  const project = join(root, "project");
  mkdirSync(home, { recursive: true });
  mkdirSync(project, { recursive: true });
  const saved = { HOME: process.env.HOME, SECOR_HOME: process.env.SECOR_HOME };
  process.env.HOME = home;
  process.env.SECOR_HOME = secorHome;
  return {
    home,
    secorHome,
    project,
    restore() {
      if (saved.HOME === undefined) delete process.env.HOME;
      else process.env.HOME = saved.HOME;
      if (saved.SECOR_HOME === undefined) delete process.env.SECOR_HOME;
      else process.env.SECOR_HOME = saved.SECOR_HOME;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/** A stdio DiscoveredServer that runs one demo server with the current node binary. */
export function demoServer(file: string, opts: { name?: string; env?: Record<string, string>; source?: string } = {}): DiscoveredServer {
  const name = opts.name ?? file.replace(/\.mjs$/, "");
  return {
    name,
    source: opts.source ?? `claude-code:project:${join(SERVERS_DIR, ".mcp.json")}`,
    editor: "claude-code",
    file: join(SERVERS_DIR, ".mcp.json"),
    keyPath: ["mcpServers", name],
    transport: "stdio",
    command: process.execPath,
    args: [join(SERVERS_DIR, file)],
    env: opts.env ?? {},
    sandbox: "no",
  };
}

// ---------------------------------------------------------------- fake secrets

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

function luhnComplete(prefix: string): string {
  for (let d = 0; d <= 9; d++) {
    const digits = `${prefix}${d}`;
    let sum = 0;
    let dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let v = digits.charCodeAt(i) - 48;
      if (dbl) {
        v *= 2;
        if (v > 9) v -= 9;
      }
      sum += v;
      dbl = !dbl;
    }
    if (sum % 10 === 0) return digits;
  }
  return `${prefix}0`;
}

/** Fake values by token name; each matches its detector and is not a placeholder. */
export const FAKES: Record<string, string> = {
  OPENAI: `sk-proj-${rand("c-openai", 40, URLSAFE)}`,
  ANTHROPIC: `sk-ant-api03-${rand("c-anthropic", 40, URLSAFE)}`,
  GITHUB: `ghp_${rand("c-gh", 36, ALNUM)}`,
  AWS_ACCESS_KEY: `AKIA${rand("c-aws", 16, UPPER_NUM)}`,
  STRIPE_LIVE: `sk_live_${rand("c-stripe", 24, ALNUM)}`,
  SLACK: `xoxb-${rand("c-slack1", 11, "0123456789")}-${rand("c-slack2", 24, ALNUM)}`,
  DB_URL: `postgres://app:${rand("c-dbpw", 18, ALNUM)}@db.prod.internal.net:5432/app`,
  DB_PASSWORD: rand("c-dbpw", 18, ALNUM),
  PASSWORD: `Pw${rand("c-pw", 14, ALNUM)}`,
  EMAIL: `${rand("c-mail", 8, "abcdefghijklmnopqrstuvwxyz")}.person@mailhost-${rand("c-dom", 6, "abcdefghijklmnopqrstuvwxyz")}.com`,
  PHONE: `+4479${rand("c-phone", 8, "0123456789")}`,
  CARD: luhnComplete(`4${rand("c-card", 14, "0123456789")}`),
};

/** Replace __FAKE_<NAME>__ tokens. */
export function substituteFakes(text: string): string {
  return text.replace(/__FAKE_([A-Z_]+?)__/g, (whole, name: string) => FAKES[name] ?? whole);
}

/** Fake values that must never appear unredacted in any output. */
export function fakeValues(): string[] {
  return Object.entries(FAKES)
    .filter(([k]) => k !== "DB_URL")
    .map(([, v]) => v);
}

/** PromptIO that answers from a script and records what was asked and printed (throws on an unexpected question). */
export function scripted(answers: string[]): PromptIO & { out: string[]; asked: string[] } {
  const queue = [...answers];
  const out: string[] = [];
  const asked: string[] = [];
  return {
    out,
    asked,
    async ask(q: string) {
      asked.push(q);
      if (queue.length === 0) throw new Error(`unexpected question: ${q}`);
      return queue.shift()!;
    },
    print(t: string) {
      out.push(t);
    },
  };
}
