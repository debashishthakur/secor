// Module resolution inside the project: relative JS/TS imports (with tsconfig/jsconfig `paths`)
// and Python imports. Package imports are not followed.

import { dirname, join, normalize } from "node:path/posix";
import type { ProjectContext } from "./context.js";

const JS_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];

function norm(p: string): string | null {
  const n = normalize(p);
  if (n.startsWith("../") || n === "..") return null;
  return n.replace(/^\.\//, "");
}

function firstExisting(ctx: ProjectContext, base: string): string | null {
  const candidates = [base];
  const m = /\.(?:js|jsx|mjs|cjs)$/.exec(base);
  if (m) {
    const stem = base.slice(0, -m[0].length);
    candidates.push(`${stem}.ts`, `${stem}.tsx`, `${stem}.mts`, `${stem}.cts`);
  }
  for (const ext of JS_EXTS) candidates.push(base + ext);
  for (const ext of JS_EXTS) candidates.push(`${base}/index${ext}`);
  for (const c of candidates) if (ctx.hasFile(c)) return c;
  return null;
}

interface TsPaths {
  dir: string;
  baseUrl: string;
  paths: [string, string[]][];
}

const tsPathsCache = new WeakMap<ProjectContext, Map<string, TsPaths | null>>();

/** Lenient JSONC: strip comments and trailing commas. */
export function parseJsonc(text: string): unknown {
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inStr) {
      out += c;
      if (c === "\\") {
        out += text[i + 1] ?? "";
        i++;
      } else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else out += c;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

function tsPathsFor(ctx: ProjectContext, fromFile: string): TsPaths | null {
  let cache = tsPathsCache.get(ctx);
  if (!cache) {
    cache = new Map();
    tsPathsCache.set(ctx, cache);
  }
  let dir = dirname(fromFile);
  for (;;) {
    const key = dir === "." ? "" : dir;
    if (cache.has(key)) return cache.get(key)!;
    for (const name of ["tsconfig.json", "jsconfig.json"]) {
      const file = key ? `${key}/${name}` : name;
      const text = ctx.read(file);
      if (text === null) continue;
      let found: TsPaths | null = null;
      try {
        const json = parseJsonc(text) as { compilerOptions?: { baseUrl?: string; paths?: Record<string, string[]> } };
        const co = json.compilerOptions ?? {};
        if (co.paths) found = { dir: key, baseUrl: co.baseUrl ?? ".", paths: Object.entries(co.paths) };
      } catch {
        found = null;
      }
      cache.set(key, found);
      return found;
    }
    if (key === "") {
      cache.set("", null);
      return null;
    }
    dir = dirname(dir);
  }
}

/** Resolve a JS/TS import specifier from `fromFile` to a project file, or null (package import / not found). */
export function resolveJsModule(ctx: ProjectContext, fromFile: string, spec: string): string | null {
  if (spec.startsWith(".")) {
    const base = norm(join(dirname(fromFile), spec));
    return base === null ? null : firstExisting(ctx, base);
  }
  const tp = tsPathsFor(ctx, fromFile);
  if (!tp) return null;
  for (const [pattern, targets] of tp.paths) {
    const star = pattern.indexOf("*");
    let rest: string | null = null;
    if (star < 0) rest = pattern === spec ? "" : null;
    else if (spec.startsWith(pattern.slice(0, star)) && spec.endsWith(pattern.slice(star + 1))) rest = spec.slice(star, spec.length - (pattern.length - star - 1));
    if (rest === null) continue;
    for (const t of targets) {
      const target = t.replace("*", rest);
      const base = norm(join(tp.dir || ".", tp.baseUrl, target));
      if (base === null) continue;
      const hit = firstExisting(ctx, base);
      if (hit) return hit;
    }
  }
  return null;
}

/**
 * Resolve a Python module ("app.routers.users", level 0) or relative import (level ≥ 1) to a file.
 * Absolute modules are looked up from the unit root, the project root, their `src/` folders and the importing file's folder.
 */
export function resolvePyModule(ctx: ProjectContext, fromFile: string, module: string, level: number, unitRoot = ""): string | null {
  const rel = module ? module.split(".").join("/") : "";
  const bases: string[] = [];
  if (level > 0) {
    let dir = dirname(fromFile);
    for (let i = 1; i < level; i++) dir = dirname(dir);
    bases.push(dir === "." ? "" : dir);
  } else {
    const fromDir = dirname(fromFile) === "." ? "" : dirname(fromFile);
    for (const b of [unitRoot, "", unitRoot ? `${unitRoot}/src` : "src", "src", fromDir]) if (!bases.includes(b)) bases.push(b);
  }
  for (const b of bases) {
    const path = norm([b, rel].filter(Boolean).join("/") || ".");
    if (path === null) continue;
    const stem = path === "." ? "" : path;
    for (const cand of [stem ? `${stem}.py` : null, stem ? `${stem}/__init__.py` : "__init__.py"]) {
      if (cand && ctx.hasFile(cand)) return cand;
    }
  }
  return null;
}

/**
 * Resolve a Python `from <source> import <name>` binding: the name may be a submodule
 * (→ { file, attr: null }) or an attribute of the module (→ { file, attr: name }).
 */
export function resolvePyBinding(ctx: ProjectContext, fromFile: string, source: string, name: string, level: number, unitRoot = ""): { file: string; attr: string | null } | null {
  const sub = resolvePyModule(ctx, fromFile, source ? `${source}.${name}` : name, level, unitRoot);
  if (sub) return { file: sub, attr: null };
  const mod = resolvePyModule(ctx, fromFile, source, level, unitRoot);
  if (mod) return { file: mod, attr: name };
  return null;
}
