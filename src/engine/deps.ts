// Dependency manifests: package.json, requirements*.txt and pyproject.toml.

import { parse as parseToml } from "smol-toml";

export interface Dep {
  name: string;
  spec: string;
  dev: boolean;
  /** 1-based line in the manifest, when known. */
  line?: number;
  /** For Python requirements: the exact version when pinned with "==". */
  pinned?: string;
  /** True when the dependency is a direct one listed in the main dependency table (used by core/hallucinated-package). */
  direct: boolean;
}

export interface Manifest {
  /** Directory relative to the project root ("" = root). */
  dir: string;
  file: string;
  ecosystem: "npm" | "PyPI";
  deps: Dep[];
  /** npm only: the parsed package.json. */
  pkg?: Record<string, unknown>;
}

export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

function lineOf(text: string, needle: string): number | undefined {
  const idx = text.indexOf(needle);
  return idx < 0 ? undefined : text.slice(0, idx).split("\n").length;
}

export function parsePackageJson(text: string, dir: string, file: string): Manifest | null {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  const deps: Dep[] = [];
  const add = (table: string, dev: boolean, direct: boolean) => {
    const t = pkg[table];
    if (!t || typeof t !== "object") return;
    // Search for each name after its table's key, so a script with the same name earlier in the file is not used.
    const section = text.indexOf(JSON.stringify(table));
    for (const [name, spec] of Object.entries(t as Record<string, unknown>)) {
      const at = section >= 0 ? text.indexOf(JSON.stringify(name), section) : -1;
      deps.push({ name, spec: String(spec), dev, direct, line: at >= 0 ? text.slice(0, at).split("\n").length : lineOf(text, `"${name}"`) });
    }
  };
  add("dependencies", false, true);
  add("devDependencies", true, true);
  add("peerDependencies", false, false);
  add("optionalDependencies", false, false);
  return { dir, file, ecosystem: "npm", deps, pkg };
}

const PEP508_NAME = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/;

/** Parse one PEP 508 requirement ("fastapi[all]>=0.110; python_version>'3.8'"). */
export function parseRequirement(req: string): { name: string; spec: string; pinned?: string } | null {
  const noMarker = req.split(";")[0]!.trim();
  if (!noMarker || /^(?:-|git\+|https?:|file:|\.)/.test(noMarker)) return null;
  const m = PEP508_NAME.exec(noMarker);
  if (!m) return null;
  const name = m[1]!;
  let spec = (m[3] ?? "").trim();
  if (spec.startsWith("@")) return { name, spec };
  spec = spec.replace(/^\(|\)$/g, "").trim();
  const pin = /^==\s*([A-Za-z0-9.+!_-]+)$/.exec(spec);
  return pin && !pin[1]!.includes("*") ? { name, spec, pinned: pin[1]! } : { name, spec };
}

export function parseRequirementsTxt(text: string, dir: string, file: string): Manifest {
  const deps: Dep[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const lineText = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!lineText || lineText.startsWith("-")) return;
    const r = parseRequirement(lineText.replace(/\s+\\$/, ""));
    if (r) deps.push({ name: r.name, spec: r.spec, pinned: r.pinned, dev: /dev|test/i.test(file), direct: true, line: i + 1 });
  });
  return { dir, file, ecosystem: "PyPI", deps };
}

export function parsePyproject(text: string, dir: string, file: string): Manifest | null {
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  const deps: Dep[] = [];
  const project = (doc.project ?? {}) as Record<string, unknown>;
  const addList = (list: unknown, dev: boolean, direct: boolean) => {
    if (!Array.isArray(list)) return;
    for (const item of list) {
      if (typeof item !== "string") continue;
      const r = parseRequirement(item);
      if (r) deps.push({ name: r.name, spec: r.spec, pinned: r.pinned, dev, direct, line: lineOf(text, item) });
    }
  };
  addList(project.dependencies, false, true);
  const optional = project["optional-dependencies"];
  if (optional && typeof optional === "object") for (const list of Object.values(optional)) addList(list, false, false);
  const groups = doc["dependency-groups"];
  if (groups && typeof groups === "object") for (const list of Object.values(groups)) addList(list, true, false);
  const poetry = ((doc.tool as Record<string, unknown> | undefined)?.poetry ?? {}) as Record<string, unknown>;
  const addTable = (table: unknown, dev: boolean) => {
    if (!table || typeof table !== "object") return;
    for (const [name, spec] of Object.entries(table as Record<string, unknown>)) {
      if (name.toLowerCase() === "python") continue;
      const s = typeof spec === "string" ? spec : typeof spec === "object" && spec && "version" in spec ? String((spec as { version: unknown }).version) : "";
      deps.push({ name, spec: s, dev, direct: false, line: lineOf(text, name) });
    }
  };
  addTable(poetry.dependencies, false);
  addTable(poetry["dev-dependencies"], true);
  const pgroups = poetry.group;
  if (pgroups && typeof pgroups === "object") for (const g of Object.values(pgroups as Record<string, { dependencies?: unknown }>)) addTable(g?.dependencies, true);
  return { dir, file, ecosystem: "PyPI", deps };
}

export function hasDep(manifests: readonly Manifest[], ecosystem: "npm" | "PyPI", name: string): boolean {
  const want = ecosystem === "PyPI" ? normalizePyName(name) : name;
  return manifests.some((m) => m.ecosystem === ecosystem && m.deps.some((d) => (ecosystem === "PyPI" ? normalizePyName(d.name) : d.name) === want));
}
