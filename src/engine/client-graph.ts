// Client-reachable code for web units (spec 8.5, web/client-secrets): the files a browser bundle can
// contain. Next.js: files with a "use client" directive plus everything they import (relative and
// tsconfig `paths` imports). Vite: everything reachable from index.html <script src> entries.
// Modules marked server-only ("use server" at the top, or `import "server-only"`) are never client code.

import { posix } from "node:path";
import { args, callee, hasDirective, stringValue, walk } from "./ast.js";
import type { ProjectContext } from "./context.js";
import type { UnitInfo } from "./detect.js";
import { langForFile, type ParsedFile, type SyntaxNode } from "./parse.js";
import { resolveJsModule } from "./resolve.js";

export interface ClientGraph {
  /** Client-reachable project files (sorted). Includes non-code files imported from client code (JSON, CSS). */
  files: string[];
  /** Entry files: "use client" files (Next.js) or index.html script entries (Vite). */
  seeds: string[];
  /** For each reachable file, the file that first imported it (seeds map to themselves). */
  via: Map<string, string>;
}

const cache = new WeakMap<ProjectContext, Map<string, ClientGraph>>();

export interface ImportSpec {
  spec: string;
  node: SyntaxNode;
}

/**
 * Module specifiers a JS/TS file loads at runtime: `import … from`, side-effect imports, `export … from`,
 * dynamic `import()` and `require()`. Type-only imports and re-exports are skipped (they are erased).
 */
export function runtimeImports(pf: ParsedFile): ImportSpec[] {
  const out: ImportSpec[] = [];
  walk(pf.root, (n) => {
    if (n.type === "import_statement") {
      if (/^import\s+type\s+(?!from\b)/.test(n.text)) return false;
      const s = stringValue(n.childForFieldName("source"));
      if (s !== null) out.push({ spec: s, node: n });
      return false;
    }
    if (n.type === "export_statement") {
      const src = n.childForFieldName("source");
      if (src && !/^export\s+type\b/.test(n.text)) {
        const s = stringValue(src);
        if (s !== null) out.push({ spec: s, node: n });
      }
      return true;
    }
    if (n.type === "call_expression") {
      const fn = callee(n);
      if (fn && (fn.type === "import" || (fn.type === "identifier" && fn.text === "require"))) {
        const s = stringValue(args(n)[0] ?? null);
        if (s !== null) out.push({ spec: s, node: n });
      }
    }
    return true;
  });
  return out;
}

function isJsFile(file: string): boolean {
  const l = langForFile(file);
  return !!l && l !== "python";
}

/** A module that never ships to the browser: top-level "use server", or `import "server-only"`. */
export function isServerOnlyModule(ctx: ProjectContext, file: string): boolean {
  if (!isJsFile(file)) return false;
  const text = ctx.read(file);
  if (text === null) return false;
  if (!text.includes("use server") && !text.includes("server-only")) return false;
  const pf = ctx.parse(file);
  if (!pf) return false;
  if (hasDirective(pf.root, "use server")) return true;
  return runtimeImports(pf).some((i) => i.spec === "server-only");
}

/** Files with a top-level "use client" directive. */
export function useClientFiles(ctx: ProjectContext, unit: UnitInfo): string[] {
  const out: string[] = [];
  for (const f of unit.files) {
    if (!isJsFile(f)) continue;
    const text = ctx.read(f);
    if (text === null || !text.includes("use client")) continue;
    const pf = ctx.parse(f);
    if (pf && hasDirective(pf.root, "use client")) out.push(f);
  }
  return out;
}

/** `<script src="…">` entries of a Vite unit's index.html, resolved to project files. */
export function viteEntries(ctx: ProjectContext, unit: UnitInfo): string[] {
  const html = unit.root ? `${unit.root}/index.html` : "index.html";
  const text = ctx.read(html);
  if (text === null) return [];
  const out: string[] = [];
  const noComments = text.replace(/<!--[\s\S]*?-->/g, "");
  for (const m of noComments.matchAll(/<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
    const src = m[1]!.split(/[?#]/)[0]!;
    if (/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(src)) continue;
    const rel = src.startsWith("/") ? src.slice(1) : posix.normalize(src);
    if (rel.startsWith("../")) continue;
    const file = unit.root ? `${unit.root}/${rel}` : rel;
    const hit = resolveEntry(ctx, file);
    if (hit && !out.includes(hit)) out.push(hit);
  }
  return out;
}

function resolveEntry(ctx: ProjectContext, file: string): string | null {
  if (ctx.hasFile(file)) return file;
  const fakeFrom = `${posix.dirname(file)}/__entry__.js`;
  return resolveJsModule(ctx, fakeFrom, `./${posix.basename(file)}`);
}

/** Next.js client instrumentation runs in the browser too. */
function nextClientExtras(ctx: ProjectContext, unit: UnitInfo): string[] {
  const prefix = unit.root ? `${unit.root}/` : "";
  const out: string[] = [];
  for (const dir of ["", "src/"]) for (const ext of ["ts", "js", "tsx", "jsx"]) {
    const f = `${prefix}${dir}instrumentation-client.${ext}`;
    if (ctx.hasFile(f)) out.push(f);
  }
  return out;
}

export function clientGraph(ctx: ProjectContext, unit: UnitInfo): ClientGraph {
  let perCtx = cache.get(ctx);
  if (!perCtx) {
    perCtx = new Map();
    cache.set(ctx, perCtx);
  }
  const key = `${unit.framework}\u0000${unit.root}`;
  const hit = perCtx.get(key);
  if (hit) return hit;

  let seeds: string[] = [];
  if (unit.framework === "nextjs") seeds = [...useClientFiles(ctx, unit), ...nextClientExtras(ctx, unit)];
  else if (unit.framework === "vite") seeds = viteEntries(ctx, unit);
  seeds = [...new Set(seeds)].sort();

  const via = new Map<string, string>();
  const queue: string[] = [];
  for (const s of seeds) {
    via.set(s, s);
    queue.push(s);
  }
  for (let qi = 0; qi < queue.length; qi++) {
    const file = queue[qi]!;
    if (!isJsFile(file)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const imp of runtimeImports(pf)) {
      const target = resolveJsModule(ctx, file, imp.spec);
      if (!target || via.has(target)) continue;
      if (isServerOnlyModule(ctx, target)) continue;
      via.set(target, file);
      queue.push(target);
    }
  }
  const graph: ClientGraph = { files: [...via.keys()].sort(), seeds, via };
  perCtx.set(key, graph);
  return graph;
}

/** Next.js files that only run on the server: route handlers, pages/api, middleware/proxy, server-only modules. */
export function isKnownServerFile(ctx: ProjectContext, unit: UnitInfo, file: string): boolean {
  const rel = unit.root ? file.slice(unit.root.length + 1) : file;
  if (unit.framework === "nextjs") {
    if (/^(?:src\/)?app\/(?:.*\/)?route\.[cm]?[jt]sx?$/.test(rel)) return true;
    if (/^(?:src\/)?pages\/api\//.test(rel)) return true;
    if (/^(?:src\/)?(?:middleware|proxy|instrumentation)\.[jt]s$/.test(rel)) return true;
  }
  return isServerOnlyModule(ctx, file);
}
