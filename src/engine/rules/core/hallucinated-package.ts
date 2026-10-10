// core/hallucinated-package (spec section 8.5): a direct dependency that does not exist on its public registry
// (high), or that appeared there very recently (high, advisory). Only package names are sent (section 13).

import { parse as parseToml } from "smol-toml";
import type { ProjectContext } from "../../context.js";
import { type Dep, type Manifest, normalizePyName } from "../../deps.js";
import { isNonRegistrySpec, npmAliasTarget } from "../../lockfiles.js";
import { type NetClient, mapLimit } from "../../net.js";
import { NotChecked, defineRule } from "../types.js";

const WHY =
  "AI assistants sometimes invent package names, and attackers publish malware under those names. A dependency that does not exist, or that appeared very recently, needs a human check before it is installed.";
const FIX = "Check that this package is the one you meant. Remove it if not.";
const NEW_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const LOW_DOWNLOADS = 500;
const NPM_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const PY_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

type Ecosystem = "npm" | "PyPI";

type Lookup = { kind: "missing" } | { kind: "new"; created: string; downloads?: number } | { kind: "ok" } | { kind: "error"; reason: string };

interface Candidate {
  manifest: Manifest;
  dep: Dep;
  ecosystem: Ecosystem;
  /** Name looked up on the registry (npm alias target; PyPI normalised). */
  name: string;
  /** The project points this ecosystem at another registry or index, so a public 404 is not conclusive. */
  privateSource: boolean;
}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

const byFile = (a: Manifest, b: Manifest) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0);

function manifests(ctx: ProjectContext): Manifest[] {
  return [...ctx.detection.roots.values()].flat().sort(byFile);
}

// ---------------------------------------------------------------- registries configured by the project

/** `.npmrc` settings that apply to a directory: the nearest file wins per key (root first, then nested). */
function npmrcFor(ctx: ProjectContext, dir: string): { scopes: Map<string, string>; registry: string | null } {
  const scopes = new Map<string, string>();
  let registry: string | null = null;
  const parts = dir ? dir.split("/") : [];
  for (let i = 0; i <= parts.length; i++) {
    const d = parts.slice(0, i).join("/");
    const text = ctx.read(d ? `${d}/.npmrc` : ".npmrc");
    if (!text) continue;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const scoped = /^(@[^:\s=]+)\s*:\s*registry\s*=\s*(.+)$/i.exec(line);
      if (scoped) scopes.set(scoped[1]!.toLowerCase(), scoped[2]!.trim().replace(/^["']|["']$/g, ""));
      const global = /^registry\s*=\s*(.+)$/i.exec(line);
      if (global) registry = global[1]!.trim().replace(/^["']|["']$/g, "");
    }
  }
  return { scopes, registry };
}

function isPublicNpmRegistry(url: string): boolean {
  return /^https?:\/\/registry\.(?:npmjs\.org|npmjs\.com|yarnpkg\.com)\/?$/i.test(url.trim());
}

/** A requirements file or pyproject.toml that adds or replaces the package index. */
function pythonPrivateIndex(ctx: ProjectContext, m: Manifest): boolean {
  const text = ctx.read(m.file) ?? "";
  if (m.file.endsWith(".txt")) {
    for (const raw of text.split(/\r?\n/)) {
      const mm = /^\s*(?:--index-url|--extra-index-url|-i)(?:\s+|=)(\S+)/.exec(raw);
      if (mm && !/^https?:\/\/(?:pypi\.org|pypi\.python\.org)\//i.test(mm[1]!)) return true;
    }
    return false;
  }
  try {
    const doc = parseToml(text) as Obj;
    const tool = isObj(doc.tool) ? doc.tool : {};
    const poetry = isObj(tool.poetry) ? tool.poetry : {};
    const uv = isObj(tool.uv) ? tool.uv : {};
    const pdm = isObj(tool.pdm) ? tool.pdm : {};
    return (
      (Array.isArray(poetry.source) && poetry.source.length > 0) ||
      (Array.isArray(uv.index) && uv.index.length > 0) ||
      typeof uv["index-url"] === "string" ||
      (Array.isArray(uv["extra-index-url"]) && uv["extra-index-url"].length > 0) ||
      (Array.isArray(pdm.source) && pdm.source.length > 0)
    );
  } catch {
    return false;
  }
}

/** Names of packages defined in this repository (workspaces, the Python project itself). */
function localNames(ctx: ProjectContext, all: readonly Manifest[]): { npm: Set<string>; py: Set<string> } {
  const npm = new Set<string>();
  const py = new Set<string>();
  for (const m of all) {
    if (m.ecosystem === "npm" && typeof m.pkg?.name === "string") npm.add(m.pkg.name);
    if (m.file.endsWith("pyproject.toml")) {
      try {
        const doc = parseToml(ctx.read(m.file) ?? "") as Obj;
        const project = isObj(doc.project) ? doc.project : {};
        const tool = isObj(doc.tool) ? doc.tool : {};
        const poetry = isObj(tool.poetry) ? tool.poetry : {};
        for (const n of [project.name, poetry.name]) if (typeof n === "string") py.add(normalizePyName(n));
      } catch {
        // unparseable pyproject: nothing to add
      }
    }
  }
  return { npm, py };
}

// ---------------------------------------------------------------- candidates

function directDeps(ctx: ProjectContext): { manifest: Manifest; dep: Dep }[] {
  return manifests(ctx).flatMap((m) => m.deps.filter((d) => d.direct).map((dep) => ({ manifest: m, dep })));
}

function candidates(ctx: ProjectContext): Candidate[] {
  const all = manifests(ctx);
  const local = localNames(ctx, all);
  const out: Candidate[] = [];
  const npmrc = new Map<string, ReturnType<typeof npmrcFor>>();
  const pyIndex = new Map<string, boolean>();
  for (const { manifest: m, dep: d } of directDeps(ctx)) {
    if (m.ecosystem === "npm") {
      const spec = d.spec.trim();
      const alias = npmAliasTarget(spec);
      if (!alias && isNonRegistrySpec(spec)) continue; // file:, link:, workspace:, git, URLs, GitHub shorthand
      const name = alias ?? d.name;
      if (local.npm.has(name) || !NPM_NAME.test(name) || name.length > 214) continue;
      if (!npmrc.has(m.dir)) npmrc.set(m.dir, npmrcFor(ctx, m.dir));
      const rc = npmrc.get(m.dir)!;
      const scope = name.startsWith("@") ? name.slice(0, name.indexOf("/")).toLowerCase() : null;
      const scopeRegistry = scope ? rc.scopes.get(scope) : undefined;
      if (scopeRegistry !== undefined && !isPublicNpmRegistry(scopeRegistry)) {
        ctx.addGap(`Package ${name}`, "served from a custom registry");
        continue;
      }
      out.push({ manifest: m, dep: d, ecosystem: "npm", name, privateSource: scopeRegistry === undefined && rc.registry !== null && !isPublicNpmRegistry(rc.registry) });
    } else {
      if (d.spec.trim().startsWith("@")) continue; // "name @ url" direct reference
      if (!PY_NAME.test(d.name)) continue;
      const name = normalizePyName(d.name);
      if (local.py.has(name)) continue;
      if (!pyIndex.has(m.file)) pyIndex.set(m.file, pythonPrivateIndex(ctx, m));
      out.push({ manifest: m, dep: d, ecosystem: "PyPI", name, privateSource: pyIndex.get(m.file)! });
    }
  }
  return out;
}

// ---------------------------------------------------------------- registry lookups

function isoDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

async function getJson(net: NetClient, url: string): Promise<{ status: number; body: unknown } | null> {
  try {
    return await net.getJson(url);
  } catch {
    return null;
  }
}

export function npmRegistryUrl(name: string): string {
  return `https://registry.npmjs.org/${name.startsWith("@") ? name.replace("/", "%2f") : encodeURIComponent(name)}`;
}

export function npmDownloadsUrl(name: string): string {
  return `https://api.npmjs.org/downloads/point/last-week/${name}`;
}

export function pypiUrl(name: string): string {
  return `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
}

async function npmLookup(net: NetClient, name: string, now: number): Promise<Lookup> {
  const res = await getJson(net, npmRegistryUrl(name));
  if (!res) return { kind: "error", reason: "registry lookup failed" };
  if (res.status === 404) return { kind: "missing" };
  if (res.status !== 200 || !isObj(res.body)) return { kind: "error", reason: `registry lookup failed (HTTP ${res.status})` };
  const time = isObj(res.body.time) ? res.body.time : {};
  // A fully unpublished package cannot be installed, and its name can be registered again.
  if (time.unpublished !== undefined && !isObj(res.body.versions)) return { kind: "missing" };
  const created = typeof time.created === "string" ? Date.parse(time.created) : Number.NaN;
  if (!Number.isFinite(created) || now - created >= NEW_WINDOW_MS) return { kind: "ok" };
  const dl = await getJson(net, npmDownloadsUrl(name));
  if (!dl) return { kind: "error", reason: "download count lookup failed" };
  const downloads = dl.status === 404 ? 0 : dl.status === 200 && isObj(dl.body) && typeof dl.body.downloads === "number" ? dl.body.downloads : null;
  if (downloads === null) return { kind: "error", reason: `download count lookup failed (HTTP ${dl.status})` };
  return downloads < LOW_DOWNLOADS ? { kind: "new", created: isoDate(created), downloads } : { kind: "ok" };
}

async function pypiLookup(net: NetClient, name: string, now: number): Promise<Lookup> {
  const res = await getJson(net, pypiUrl(name));
  if (!res) return { kind: "error", reason: "registry lookup failed" };
  if (res.status === 404) return { kind: "missing" };
  if (res.status !== 200 || !isObj(res.body)) return { kind: "error", reason: `registry lookup failed (HTTP ${res.status})` };
  let earliest = Number.POSITIVE_INFINITY;
  const releases = isObj(res.body.releases) ? res.body.releases : {};
  for (const files of Object.values(releases)) {
    if (!Array.isArray(files)) continue;
    for (const f of files) {
      if (!isObj(f)) continue;
      // upload_time has no zone (UTC); upload_time_iso_8601 has one.
      const t =
        typeof f.upload_time_iso_8601 === "string" ? Date.parse(f.upload_time_iso_8601) : typeof f.upload_time === "string" ? Date.parse(`${f.upload_time}Z`) : Number.NaN;
      if (Number.isFinite(t) && t < earliest) earliest = t;
    }
  }
  if (!Number.isFinite(earliest)) return { kind: "ok" }; // no uploaded files: nothing to date
  return now - earliest < NEW_WINDOW_MS ? { kind: "new", created: isoDate(earliest) } : { kind: "ok" };
}

// ---------------------------------------------------------------- rule

/**
 * 1-based line of the dependency. package.json: the name's first occurrence after its own section key (a script
 * or another field with the same name can come earlier in the file); otherwise the manifest parser's line.
 */
function depLineNumber(ctx: ProjectContext, c: Candidate): number {
  if (c.manifest.ecosystem === "npm") {
    const text = ctx.read(c.manifest.file) ?? "";
    const section = text.indexOf(c.dep.dev ? '"devDependencies"' : '"dependencies"');
    const at = section >= 0 ? text.indexOf(JSON.stringify(c.dep.name), section) : -1;
    if (at >= 0) return text.slice(0, at).split("\n").length;
  }
  return c.dep.line ?? 1;
}

function depLineText(ctx: ProjectContext, c: Candidate, line: number): string {
  const text = ((ctx.read(c.manifest.file) ?? "").split(/\r?\n/)[line - 1] ?? "").trim();
  return text || `${c.dep.name} ${c.dep.spec}`.trim();
}

export const hallucinatedPackage = defineRule({
  id: "core/hallucinated-package",
  title: "Dependency that does not exist or is suspiciously new",
  pack: "core",
  maturity: "experimental",
  appliesTo(ctx) {
    return directDeps(ctx).length > 0;
  },
  async check(ctx, emit) {
    if (!ctx.network) throw new NotChecked("network disabled (offline mode)");
    const list = candidates(ctx);
    const keys = [...new Set(list.map((c) => `${c.ecosystem}\u0000${c.name}`))].sort();
    // The 30-day window is measured from the run's start (spec 8.5), never from the wall clock mid-run.
    const now = ctx.runStartedAt.getTime();
    const results = await mapLimit(keys, 8, (k) => {
      const [eco, name] = k.split("\u0000") as [Ecosystem, string];
      return eco === "npm" ? npmLookup(ctx.net, name, now) : pypiLookup(ctx.net, name, now);
    });
    const byKey = new Map(keys.map((k, i) => [k, results[i]!]));

    for (const c of list) {
      const r = byKey.get(`${c.ecosystem}\u0000${c.name}`)!;
      const registry = c.ecosystem === "npm" ? "the npm registry" : "PyPI";
      if (r.kind === "error") {
        ctx.addGap(`Package ${c.name}`, r.reason);
        continue;
      }
      if (r.kind === "ok") continue;
      if (r.kind === "missing" && c.privateSource) {
        ctx.addGap(`Package ${c.name}`, `not found on ${registry}; the project also uses a custom ${c.ecosystem === "npm" ? "registry" : "index"}`);
        continue;
      }
      const note =
        r.kind === "missing"
          ? `not found on ${registry}`
          : r.downloads !== undefined
            ? `first published ${r.created}, ${r.downloads} downloads last week`
            : `first uploaded ${r.created}`;
      const line = depLineNumber(ctx, c);
      emit({
        severity: "high",
        advisory: r.kind === "new",
        service: "core",
        file: c.manifest.file,
        line,
        anchor: `${c.dep.name}@${c.dep.spec}`,
        evidence: `${depLineText(ctx, c, line)} (${note})`,
        why: WHY,
        fix: { summary: FIX },
      });
    }
  },
});
