// File listing (spec section 8.1, step 2) and git access.

import { spawnSync } from "node:child_process";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { matchesAny, translateGlob } from "./util/glob.js";

export const LOCKFILES = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "poetry.lock",
  "uv.lock",
  "Pipfile.lock",
];

export const DEFAULT_EXCLUDES = [
  "**/node_modules/**",
  "**/.venv/**",
  "**/venv/**",
  "**/__pycache__/**",
  "**/.git/**",
  "**/coverage/**",
  "**/*.min.js",
  ...LOCKFILES.map((f) => `**/${f}`),
  "**/.next/**",
  "**/dist/**",
  "**/build/**",
  "**/.secor/**",
];

/** Directory names never descended into during a walk (performance; they are excluded anyway). */
const SKIP_DIRS = new Set(["node_modules", ".venv", "venv", "__pycache__", ".git", "coverage", ".next", "dist", "build", ".secor"]);

const MAX_FILES = 200_000;

// ---------------------------------------------------------------- git

let gitOk: boolean | null = null;

/**
 * Options that stop a scanned repository's own config from running programs: core.fsmonitor can name a command
 * that git executes during ls-files/status, and diff/textconv drivers run during log -p.
 */
export const GIT_SAFE_OPTIONS = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "diff.external=", "-c", "core.pager=cat"];

export function runGit(args: string[], cwd: string, timeoutMs = 60_000): { ok: boolean; stdout: string } {
  const res = spawnSync("git", [...GIT_SAFE_OPTIONS, ...args], {
    cwd,
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 512 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C" },
  });
  return { ok: res.status === 0 && !res.error, stdout: res.stdout ?? "" };
}

/** True when a working `git` binary is on PATH (the macOS Xcode shim without an accepted licence counts as missing). */
export function gitAvailable(): boolean {
  if (gitOk === null) {
    const res = spawnSync("git", ["--version"], { encoding: "utf8", timeout: 10_000 });
    gitOk = res.status === 0 && /^git version/.test(res.stdout ?? "");
  }
  return gitOk;
}

/** Test hook: forget the cached git check. */
export function resetGitCache(): void {
  gitOk = null;
}

export interface GitInfo {
  available: boolean;
  isRepo: boolean;
  tracked: Set<string>;
}

export function gitInfo(root: string): GitInfo {
  if (!gitAvailable()) return { available: false, isRepo: false, tracked: new Set() };
  const inside = runGit(["rev-parse", "--is-inside-work-tree"], root, 10_000);
  if (!inside.ok || inside.stdout.trim() !== "true") return { available: true, isRepo: false, tracked: new Set() };
  const tracked = runGit(["ls-files", "--cached", "-z"], root);
  return { available: true, isRepo: true, tracked: new Set(tracked.stdout.split("\0").filter(Boolean)) };
}

/** Is `rel` ignored by git (or, outside a repo, by the .gitignore files on its path)? */
export function isGitIgnored(root: string, rel: string, git: GitInfo): boolean {
  if (git.isRepo) {
    const res = spawnSync("git", [...GIT_SAFE_OPTIONS, "check-ignore", "-q", "--", rel], { cwd: root, timeout: 10_000, env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" } });
    return res.status === 0;
  }
  const parts = rel.split("/");
  const stack: IgnoreRule[][] = [];
  let dir = "";
  for (let i = 0; i < parts.length; i++) {
    stack.push(readGitignore(root, dir));
    const sub = parts.slice(0, i + 1).join("/");
    const isLast = i === parts.length - 1;
    if (ignoredBy(stack, sub, !isLast)) return true;
    dir = sub;
  }
  return false;
}

// ---------------------------------------------------------------- .gitignore (walk mode)

interface IgnoreRule {
  base: string;
  negate: boolean;
  dirOnly: boolean;
  re: RegExp;
}

export function parseGitignore(text: string, base: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (let raw of text.split(/\r?\n/)) {
    raw = raw.replace(/(?<!\\)\s+$/, "");
    if (!raw || raw.startsWith("#")) continue;
    let negate = false;
    if (raw.startsWith("!")) {
      negate = true;
      raw = raw.slice(1);
    } else if (raw.startsWith("\\!") || raw.startsWith("\\#")) {
      raw = raw.slice(1);
    }
    let dirOnly = false;
    if (raw.endsWith("/")) {
      dirOnly = true;
      raw = raw.slice(0, -1);
    }
    const anchored = raw.startsWith("/") || raw.includes("/");
    if (raw.startsWith("/")) raw = raw.slice(1);
    if (!raw) continue;
    const body = translateGlob(raw);
    rules.push({ base, negate, dirOnly, re: new RegExp(anchored ? `^${body}$` : `^(?:.*/)?${body}$`) });
  }
  return rules;
}

function readGitignore(root: string, dir: string): IgnoreRule[] {
  try {
    return parseGitignore(readFileSync(join(root, dir, ".gitignore"), "utf8"), dir);
  } catch {
    return [];
  }
}

function ignoredBy(stack: IgnoreRule[][], rel: string, isDir: boolean): boolean {
  let ignored = false;
  for (const rules of stack) {
    for (const r of rules) {
      if (r.dirOnly && !isDir) continue;
      const sub = r.base ? (rel.startsWith(`${r.base}/`) ? rel.slice(r.base.length + 1) : null) : rel;
      if (sub === null) continue;
      if (r.re.test(sub)) ignored = !r.negate;
    }
  }
  return ignored;
}

// ---------------------------------------------------------------- listing

export interface Listing {
  files: string[];
  git: GitInfo;
}

function isRegularFile(abs: string): boolean {
  try {
    return lstatSync(abs).isFile();
  } catch {
    return false;
  }
}

function walk(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string, stack: IgnoreRule[][]) => {
    if (out.length >= MAX_FILES) return;
    const rules = [...stack, readGitignore(root, dir)];
    let entries;
    try {
      entries = readdirSync(join(root, dir), { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || ignoredBy(rules, rel, true)) continue;
        visit(rel, rules);
      } else if (e.isFile()) {
        if (!ignoredBy(rules, rel, false)) out.push(rel);
      }
    }
  };
  visit("", []);
  return out;
}

export function listFiles(root: string, extraExcludes: readonly string[]): Listing {
  const git = gitInfo(root);
  let files: string[];
  if (git.isRepo) {
    const others = runGit(["ls-files", "--others", "--exclude-standard", "-z"], root);
    const all = new Set([...git.tracked, ...others.stdout.split("\0").filter(Boolean)]);
    files = [...all].filter((f) => isRegularFile(join(root, f)));
  } else {
    files = walk(root);
  }
  const excludes = [...DEFAULT_EXCLUDES, ...extraExcludes];
  files = files.filter((f) => !matchesAny(f, excludes)).sort();
  return { files: files.slice(0, MAX_FILES), git };
}

/** Find files on disk (not via the listing), skipping SKIP_DIRS and symlinks. Used for `.env*` files and build output. */
export function findOnDisk(root: string, dir: string, pred: (rel: string) => boolean, opts: { skipDirs?: boolean; limit?: number } = {}): string[] {
  const out: string[] = [];
  const limit = opts.limit ?? 50_000;
  const visit = (d: string) => {
    if (out.length >= limit) return;
    let entries;
    try {
      entries = readdirSync(join(root, d), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const rel = d ? `${d}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if ((opts.skipDirs ?? true) && SKIP_DIRS.has(e.name)) continue;
        visit(rel);
      } else if (e.isFile() && pred(rel)) out.push(rel);
    }
  };
  visit(dir);
  return out.sort();
}
