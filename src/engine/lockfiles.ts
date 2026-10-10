// Lockfile discovery and parsing for core/vulnerable-dependency (spec section 8.5): package-lock.json v2/v3
// (and npm-shrinkwrap.json, same format), pnpm-lock.yaml v6–v9, yarn.lock (v1 and Berry), poetry.lock, uv.lock,
// and "==" pins in requirements*.txt. Lockfiles are excluded from the Ship listing (section 8.1), so they are read
// directly from each manifest directory and the project root.
//
// Dev-only packages are excluded where the lockfile itself says so: the `dev` flag (package-lock, pnpm v6),
// reachability from the importers' non-dev dependencies (pnpm v9), `category = "dev"` / `groups` without "main"
// (poetry), and reachability from the workspace members' non-dev dependencies (uv). yarn.lock records no dev
// information, so every yarn package is checked. See scratchpad decisions-core.md.

import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { sep } from "node:path";
import { parse as parseToml } from "smol-toml";
import { parse as parseYaml } from "yaml";
import { MAX_READ_BYTES, type ProjectContext } from "./context.js";
import { type Manifest, normalizePyName } from "./deps.js";
import { isValidVersion } from "./versions.js";

export type LockEcosystem = "npm" | "PyPI";
export type LockKind = "package-lock" | "pnpm" | "yarn-v1" | "yarn-berry" | "poetry" | "uv" | "requirements";

export interface LockedPackage {
  /** Registry name (npm aliases resolved to the real package; PyPI names normalised per PEP 503). */
  name: string;
  version: string;
  /** Dev-only according to the lockfile (excluded from advisory checks). */
  dev: boolean;
  /** 1-based line where the package appears in the lockfile (1 when unknown). */
  line: number;
}

export interface Lockfile {
  /** Project-relative path. */
  file: string;
  kind: LockKind;
  ecosystem: LockEcosystem;
  packages: LockedPackage[];
}

export type ParseResult = { ok: true; packages: LockedPackage[] } | { ok: false; reason: string };

export interface LockfileScan {
  lockfiles: Lockfile[];
  /** Lockfiles found but not supported (format or version). */
  unsupported: { file: string; reason: string }[];
  /** requirements*.txt entries without an exact "==" pin, per file. */
  unpinned: { file: string; names: string[] }[];
}

/** Largest lockfile read (lockfiles of big projects exceed ProjectContext's 2 MB read limit). */
export const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;

const SUPPORTED: { name: string; kind: Exclude<LockKind, "yarn-v1" | "yarn-berry" | "requirements"> | "yarn"; ecosystem: LockEcosystem }[] = [
  { name: "package-lock.json", kind: "package-lock", ecosystem: "npm" },
  { name: "npm-shrinkwrap.json", kind: "package-lock", ecosystem: "npm" },
  { name: "pnpm-lock.yaml", kind: "pnpm", ecosystem: "npm" },
  { name: "yarn.lock", kind: "yarn", ecosystem: "npm" },
  { name: "poetry.lock", kind: "poetry", ecosystem: "PyPI" },
  { name: "uv.lock", kind: "uv", ecosystem: "PyPI" },
];
const UNSUPPORTED_LOCKFILES = ["bun.lock", "bun.lockb", "Pipfile.lock"];

const YAML_OPTS = { maxAliasCount: 100, uniqueKeys: false, prettyErrors: false } as const;

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

/** Offset → 1-based line, by binary search over line starts. */
class LineIndex {
  private readonly starts: number[] = [0];
  constructor(text: string) {
    for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) this.starts.push(i + 1);
  }
  lineOf(offset: number): number {
    if (offset < 0) return 1;
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }
}

// ---------------------------------------------------------------- npm specs

/** Specs that do not come from a package registry: local paths, workspaces, git, URLs, GitHub shorthand. */
export function isNonRegistrySpec(spec: string): boolean {
  const s = spec.trim();
  return (
    /^(?:file:|link:|portal:|workspace:|git\+|git:|git@|github:|gitlab:|bitbucket:|gist:|https?:|exec:|patch:|jsr:|\.{0,2}\/|~\/)/i.test(s) ||
    /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(s)
  );
}

/** "npm:real@^1.2.3" → "real" (scoped names included); null for other specs. */
export function npmAliasTarget(spec: string): string | null {
  if (!spec.startsWith("npm:")) return null;
  const s = spec.slice(4);
  const at = s.indexOf("@", 1);
  const name = at > 0 ? s.slice(0, at) : s;
  return name || null;
}

// ---------------------------------------------------------------- package-lock.json / npm-shrinkwrap.json

export function parsePackageLock(text: string): ParseResult {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { ok: false, reason: "could not parse the lockfile" };
  }
  if (!isObj(doc)) return { ok: false, reason: "could not parse the lockfile" };
  const v = doc.lockfileVersion;
  if (v !== 2 && v !== 3) return { ok: false, reason: `lockfileVersion ${typeof v === "number" ? v : 1} is not supported (v2 and v3 are)` };
  const packages = isObj(doc.packages) ? doc.packages : {};
  const lines = new LineIndex(text);
  const out: LockedPackage[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    // "" is the root project; keys without node_modules/ are workspace members (local code).
    const nm = key.lastIndexOf("node_modules/");
    if (nm < 0 || !isObj(entry) || entry.link === true) continue;
    const version = str(entry.version);
    if (!version || !isValidVersion("npm", version)) continue;
    const resolved = str(entry.resolved) ?? "";
    if (resolved && isNonRegistrySpec(resolved) && !/^https?:/i.test(resolved)) continue;
    const name = str(entry.name) ?? key.slice(nm + "node_modules/".length);
    if (!name) continue;
    out.push({ name, version, dev: entry.dev === true, line: lines.lineOf(text.indexOf(JSON.stringify(key))) });
  }
  return { ok: true, packages: out };
}

// ---------------------------------------------------------------- pnpm-lock.yaml

/** "/@scope/name@1.2.3(peer@1.0.0)" (v6) or "name@1.2.3(peer@1.0.0)" (v9) → name and version. */
export function splitPnpmKey(key: string): { name: string; version: string } | null {
  let k = key.startsWith("/") ? key.slice(1) : key;
  const paren = k.indexOf("(");
  if (paren >= 0) k = k.slice(0, paren);
  const at = k.indexOf("@", 1);
  if (at <= 0) return null;
  return { name: k.slice(0, at), version: k.slice(at + 1) };
}

/** Line of each key directly under a top-level section (2-space indentation), e.g. the `packages:` map. */
function sectionKeyLines(text: string, section: string): Map<string, number> {
  const out = new Map<string, number>();
  let inSection = false;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!.replace(/\r$/, "");
    if (/^\S/.test(l)) {
      inSection = l.replace(/\s+$/, "") === `${section}:`;
      continue;
    }
    if (!inSection) continue;
    const m = /^ {2}(?:'((?:[^']|'')*)'|"((?:[^"\\]|\\.)*)"|([^\s'"][^:]*?|[^\s'"].*?)):(?:\s|$)/.exec(l);
    if (!m) continue;
    const key = m[1] !== undefined ? m[1].replace(/''/g, "'") : m[2] !== undefined ? m[2] : m[3]!;
    if (!out.has(key)) out.set(key, i + 1);
  }
  return out;
}

/** pnpm v9: "name@version" of every package reachable from the importers' dependencies and optionalDependencies. */
function pnpmProdSet(doc: Obj): Set<string> | null {
  const importers = isObj(doc.importers) ? doc.importers : null;
  if (!importers) return null;
  const snapshots = isObj(doc.snapshots) ? doc.snapshots : {};
  const visited = new Set<string>();
  const queue: string[] = [];
  const push = (name: string, ref: unknown) => {
    const r = typeof ref === "string" ? ref : isObj(ref) ? str(ref.version) : null;
    if (!r || /^(?:link:|file:)/.test(r)) return;
    // An alias resolves to "real@version"; versions themselves only contain "@" inside the peer suffix.
    const base = r.split("(")[0]!;
    const snapKey = base.indexOf("@", 1) > 0 ? r : `${name}@${r}`;
    if (!visited.has(snapKey)) {
      visited.add(snapKey);
      queue.push(snapKey);
    }
  };
  const pushAll = (holder: Obj) => {
    for (const section of ["dependencies", "optionalDependencies"]) {
      const deps = holder[section];
      if (isObj(deps)) for (const [n, ref] of Object.entries(deps)) push(n, ref);
    }
  };
  for (const imp of Object.values(importers)) if (isObj(imp)) pushAll(imp);
  while (queue.length) {
    const snap = snapshots[queue.pop()!];
    if (isObj(snap)) pushAll(snap);
  }
  const out = new Set<string>();
  for (const k of visited) {
    const id = splitPnpmKey(k);
    if (id) out.add(`${id.name}@${id.version}`);
  }
  return out;
}

export function parsePnpmLock(text: string): ParseResult {
  let doc: unknown;
  try {
    doc = parseYaml(text, YAML_OPTS);
  } catch {
    return { ok: false, reason: "could not parse the lockfile" };
  }
  if (!isObj(doc)) return { ok: false, reason: "could not parse the lockfile" };
  const raw = doc.lockfileVersion;
  const ver = Number.parseFloat(String(raw ?? ""));
  if (!(ver >= 6 && ver < 10)) return { ok: false, reason: `lockfileVersion ${raw === undefined ? "unknown" : String(raw)} is not supported (6 to 9 are)` };
  const packages = isObj(doc.packages) ? doc.packages : {};
  const lines = sectionKeyLines(text, "packages");
  const prod = ver >= 9 ? pnpmProdSet(doc) : null;
  const out: LockedPackage[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    const id = splitPnpmKey(key);
    if (!id || !isValidVersion("npm", id.version)) continue;
    const e = isObj(entry) ? entry : {};
    const res = isObj(e.resolution) ? e.resolution : {};
    if (res.type === "git" || res.type === "directory") continue;
    const dev = prod ? !prod.has(`${id.name}@${id.version}`) : e.dev === true;
    out.push({ name: id.name, version: id.version, dev, line: lines.get(key) ?? 1 });
  }
  return { ok: true, packages: out };
}

// ---------------------------------------------------------------- yarn.lock (v1 and Berry)

export function isYarnBerry(text: string): boolean {
  return /^__metadata:\s*$/m.test(text);
}

/** Split a yarn v1 entry header ("a@^1", "@s/b@^2") into its specs, honouring quotes. */
function splitYarnSpecs(header: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote = false;
  for (const ch of header) {
    if (ch === '"') quote = !quote;
    else if (ch === "," && !quote) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean);
}

/** "name@range" → parts; the separator is the first "@" after a leading scope "@". */
function splitSpec(spec: string): { name: string; range: string } {
  const at = spec.indexOf("@", 1);
  return at > 0 ? { name: spec.slice(0, at), range: spec.slice(at + 1) } : { name: spec, range: "" };
}

export function parseYarnV1(text: string): ParseResult {
  const lines = text.split("\n");
  const out: LockedPackage[] = [];
  let cur: { specs: string[]; line: number; version?: string; resolved?: string } | null = null;
  const flush = () => {
    if (!cur?.version || !isValidVersion("npm", cur.version)) return;
    if (cur.resolved && /^(?:file:|link:|git\+|git:|github:)/.test(cur.resolved)) return;
    const reg = cur.specs.map(splitSpec).find((s) => !isNonRegistrySpec(s.range));
    if (!reg) return;
    out.push({ name: npmAliasTarget(reg.range) ?? reg.name, version: cur.version, dev: false, line: cur.line });
  };
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!.replace(/\r$/, "");
    if (!l.trim() || l.startsWith("#")) continue;
    if (!/^\s/.test(l)) {
      flush();
      cur = l.endsWith(":") ? { specs: splitYarnSpecs(l.slice(0, -1)), line: i + 1 } : null;
      continue;
    }
    if (!cur) continue;
    const m = /^ {2}(version|resolved)\s+"?([^"]*)"?\s*$/.exec(l);
    if (m) cur[m[1] as "version" | "resolved"] = m[2]!;
  }
  flush();
  return { ok: true, packages: out };
}

/** Line of each top-level key (column 0), unquoted. */
function topLevelKeyLines(text: string): Map<string, number> {
  const out = new Map<string, number>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!.replace(/\r$/, "");
    const m = /^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^\s#'"].*?)):\s*$/.exec(l);
    if (!m) continue;
    const key = m[1] ?? (m[2] !== undefined ? m[2].replace(/''/g, "'") : m[3]!);
    if (!out.has(key)) out.set(key, i + 1);
  }
  return out;
}

export function parseYarnBerry(text: string): ParseResult {
  let doc: unknown;
  try {
    doc = parseYaml(text, YAML_OPTS);
  } catch {
    return { ok: false, reason: "could not parse the lockfile" };
  }
  if (!isObj(doc)) return { ok: false, reason: "could not parse the lockfile" };
  const lines = topLevelKeyLines(text);
  const out: LockedPackage[] = [];
  for (const [key, entry] of Object.entries(doc)) {
    if (key === "__metadata" || !isObj(entry)) continue;
    // Only registry packages: "name@npm:1.2.3". workspace:, patch:, git, file and link entries are skipped
    // (a patch: entry's base npm package has its own entry).
    const res = str(entry.resolution) ?? "";
    const idx = res.indexOf("@npm:", 1);
    if (idx <= 0) continue;
    const name = res.slice(0, idx);
    let version = str(entry.version) ?? "";
    if (!isValidVersion("npm", version)) version = res.slice(idx + "@npm:".length);
    if (!isValidVersion("npm", version)) continue;
    out.push({ name, version, dev: false, line: lines.get(key) ?? 1 });
  }
  return { ok: true, packages: out };
}

// ---------------------------------------------------------------- poetry.lock / uv.lock

/** For each [[package]] table, in order: the line of its `name = ...` key (or of the header). */
function tomlPackageLines(text: string): number[] {
  const out: number[] = [];
  const lines = text.split("\n");
  let inBlock = false;
  let named = false;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\s*\[\[\s*package\s*\]\]\s*(?:#.*)?$/.test(l)) {
      out.push(i + 1);
      inBlock = true;
      named = false;
      continue;
    }
    if (/^\s*\[(?!\[?\s*package[\].])/.test(l)) {
      inBlock = false;
      continue;
    }
    if (inBlock && !named && /^\s*name\s*=/.test(l)) {
      out[out.length - 1] = i + 1;
      named = true;
    }
  }
  return out;
}

export function parsePoetryLock(text: string): ParseResult {
  let doc: Obj;
  try {
    doc = parseToml(text) as Obj;
  } catch {
    return { ok: false, reason: "could not parse the lockfile" };
  }
  const pkgs = Array.isArray(doc.package) ? doc.package : [];
  const lines = tomlPackageLines(text);
  const out: LockedPackage[] = [];
  pkgs.forEach((p, i) => {
    if (!isObj(p)) return;
    const name = str(p.name);
    const version = str(p.version);
    if (!name || !version || !isValidVersion("PyPI", version)) return;
    // git, directory, file and url sources are not from an index; "legacy" is an alternative PyPI-style index.
    const src = isObj(p.source) ? str(p.source.type) : null;
    if (src && src !== "legacy") return;
    const groups = Array.isArray(p.groups) ? p.groups.filter((g): g is string => typeof g === "string") : null;
    const dev = p.category === "dev" || (groups !== null && groups.length > 0 && !groups.includes("main"));
    out.push({ name: normalizePyName(name), version, dev, line: lines[i] ?? 1 });
  });
  return { ok: true, packages: out };
}

export function parseUvLock(text: string): ParseResult {
  let doc: Obj;
  try {
    doc = parseToml(text) as Obj;
  } catch {
    return { ok: false, reason: "could not parse the lockfile" };
  }
  const pkgs: Obj[] = (Array.isArray(doc.package) ? doc.package : []).map((p) => (isObj(p) ? p : {}));
  const lines = tomlPackageLines(text);
  const byName = new Map<string, number[]>();
  pkgs.forEach((p, i) => {
    const n = str(p.name);
    if (!n) return;
    const k = normalizePyName(n);
    byName.set(k, [...(byName.get(k) ?? []), i]);
  });
  const sourceOf = (p: Obj): Obj => (isObj(p.source) ? p.source : {});
  // Workspace members (the project itself): editable or virtual sources.
  const roots = pkgs.map((p, i) => (sourceOf(p).editable !== undefined || sourceOf(p).virtual !== undefined ? i : -1)).filter((i) => i >= 0);

  let prod: Set<number> | null = null;
  if (roots.length) {
    const seen = new Set<number>();
    const seenExtra = new Set<string>();
    const queue: number[] = [];
    const visitList = (list: unknown) => {
      if (Array.isArray(list)) for (const d of list) visitDep(d);
    };
    const enqueue = (i: number, extras: string[]) => {
      if (!seen.has(i)) {
        seen.add(i);
        queue.push(i);
      }
      for (const x of extras) {
        const k = `${i}#${normalizePyName(x)}`;
        if (seenExtra.has(k)) continue;
        seenExtra.add(k);
        const opt = pkgs[i]!["optional-dependencies"];
        if (isObj(opt)) for (const [extra, list] of Object.entries(opt)) if (normalizePyName(extra) === normalizePyName(x)) visitList(list);
      }
    };
    const visitDep = (d: unknown) => {
      if (!isObj(d)) return;
      const n = str(d.name);
      if (!n) return;
      const want = str(d.version);
      const extras = Array.isArray(d.extra) ? d.extra.filter((x): x is string => typeof x === "string") : [];
      for (const i of byName.get(normalizePyName(n)) ?? []) if (!want || pkgs[i]!.version === want) enqueue(i, extras);
    };
    for (const r of roots) {
      enqueue(r, []);
      // The project's own extras are installable, so they count as production dependencies.
      const opt = pkgs[r]!["optional-dependencies"];
      if (isObj(opt)) for (const list of Object.values(opt)) visitList(list);
    }
    while (queue.length) visitList(pkgs[queue.pop()!]!.dependencies);
    prod = seen;
  }

  const out: LockedPackage[] = [];
  pkgs.forEach((p, i) => {
    const name = str(p.name);
    const version = str(p.version);
    if (!name || !version || !isValidVersion("PyPI", version)) return;
    if (typeof sourceOf(p).registry !== "string") return;
    out.push({ name: normalizePyName(name), version, dev: prod ? !prod.has(i) : false, line: lines[i] ?? 1 });
  });
  return { ok: true, packages: out };
}

// ---------------------------------------------------------------- requirements*.txt

export function isRequirementsManifest(m: Manifest): boolean {
  return m.ecosystem === "PyPI" && /^requirements[\w.-]*\.txt$/.test(m.file.split("/").pop() ?? "");
}

/** Pinned ("==") production requirements as locked packages, plus the names that are not pinned. */
export function requirementsPins(m: Manifest): { packages: LockedPackage[]; unpinned: string[] } {
  const packages: LockedPackage[] = [];
  const unpinned: string[] = [];
  for (const d of m.deps) {
    if (d.dev) continue; // requirements-dev.txt / requirements-test.txt (deps.ts flags the whole file)
    if (d.pinned && isValidVersion("PyPI", d.pinned)) packages.push({ name: normalizePyName(d.name), version: d.pinned, dev: false, line: d.line ?? 1 });
    else if (!d.spec.startsWith("@")) unpinned.push(d.name); // "name @ url" is a direct reference, not a range
  }
  return { packages, unpinned: [...new Set(unpinned)] };
}

// ---------------------------------------------------------------- discovery

/** Lockfile text: ProjectContext.read, or a direct read for regular files between 2 MB and 64 MB inside the root. */
export function readLockText(ctx: ProjectContext, rel: string): string | null {
  const text = ctx.read(rel);
  if (text !== null) return text;
  const abs = ctx.abs(rel);
  if (!abs) return null;
  try {
    const st = lstatSync(abs);
    if (!st.isFile() || st.size <= MAX_READ_BYTES || st.size > MAX_LOCKFILE_BYTES) return null;
    const real = realpathSync(abs);
    const root = realpathSync(ctx.root);
    if (!real.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) return null;
    const buf = readFileSync(real);
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

function isRegularFile(ctx: ProjectContext, rel: string): boolean {
  const abs = ctx.abs(rel);
  if (!abs) return false;
  try {
    return lstatSync(abs).isFile();
  } catch {
    return false;
  }
}

export function parseLockfile(name: string, text: string): { kind: LockKind; result: ParseResult } | null {
  switch (name) {
    case "package-lock.json":
    case "npm-shrinkwrap.json":
      return { kind: "package-lock", result: parsePackageLock(text) };
    case "pnpm-lock.yaml":
      return { kind: "pnpm", result: parsePnpmLock(text) };
    case "yarn.lock":
      return isYarnBerry(text) ? { kind: "yarn-berry", result: parseYarnBerry(text) } : { kind: "yarn-v1", result: parseYarnV1(text) };
    case "poetry.lock":
      return { kind: "poetry", result: parsePoetryLock(text) };
    case "uv.lock":
      return { kind: "uv", result: parseUvLock(text) };
    default:
      return null;
  }
}

const scans = new WeakMap<ProjectContext, LockfileScan>();

/** Every lockfile at the project root and at each manifest directory, parsed once per run. */
export function scanLockfiles(ctx: ProjectContext): LockfileScan {
  const cached = scans.get(ctx);
  if (cached) return cached;
  const scan: LockfileScan = { lockfiles: [], unsupported: [], unpinned: [] };
  const roots = ctx.detection?.roots ?? new Map<string, Manifest[]>();
  const dirs = [...new Set(["", ...roots.keys()])].sort();
  for (const dir of dirs) {
    const at = (name: string) => (dir ? `${dir}/${name}` : name);
    for (const s of SUPPORTED) {
      const rel = at(s.name);
      const text = readLockText(ctx, rel);
      if (text === null) continue;
      const parsed = parseLockfile(s.name, text)!;
      if (parsed.result.ok) scan.lockfiles.push({ file: rel, kind: parsed.kind, ecosystem: s.ecosystem, packages: parsed.result.packages });
      else scan.unsupported.push({ file: rel, reason: parsed.result.reason });
    }
    for (const name of UNSUPPORTED_LOCKFILES) {
      if (isRegularFile(ctx, at(name))) scan.unsupported.push({ file: at(name), reason: "lockfile format not supported in v1" });
    }
  }
  const manifests = [...roots.values()].flat().filter(isRequirementsManifest).sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  for (const m of manifests) {
    const { packages, unpinned } = requirementsPins(m);
    if (packages.length) scan.lockfiles.push({ file: m.file, kind: "requirements", ecosystem: "PyPI", packages });
    if (unpinned.length) scan.unpinned.push({ file: m.file, names: unpinned });
  }
  scans.set(ctx, scan);
  return scan;
}
