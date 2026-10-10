// Service-unit and framework detection (spec section 8.2).

import { dirname } from "node:path/posix";
import type { Framework, NotCheckedEntry, ServiceKind, ServiceUnit } from "../types.js";
import { type Manifest, hasDep, parsePackageJson, parsePyproject, parseRequirementsTxt } from "./deps.js";

export type Backend = "supabase" | "firebase";
export type McpTransport = "stdio" | "http";

export interface UnitInfo extends ServiceUnit {
  /** Listed files that belong to this unit's root (files under a nested candidate root belong to that root). */
  files: string[];
  manifests: Manifest[];
  backends: Set<Backend>;
  mcp?: { transports: Set<McpTransport>; deployment: "local" | "remote"; serverFiles: string[] };
}

export interface Detection {
  units: UnitInfo[];
  /** Candidate roots ("" = project root) with their manifests. */
  roots: Map<string, Manifest[]>;
  backends: Set<Backend>;
  notChecked: NotCheckedEntry[];
}

interface DetectInput {
  files: readonly string[];
  read(rel: string): string | null;
  mcpDeployment: "auto" | "local" | "remote";
}

// wrangler.json / wrangler.jsonc are the current names of wrangler.toml (DECISIONS.md).
const DEPLOY_FILES = ["Dockerfile", "fly.toml", "render.yaml", "railway.json", "railway.toml", "vercel.json", "netlify.toml", "Procfile", "app.yaml", "serverless.yml", "wrangler.toml", "wrangler.json", "wrangler.jsonc"];

export function rootOf(file: string, roots: readonly string[]): string | null {
  let best: string | null = null;
  for (const r of roots) {
    if (r === "" || file === r || file.startsWith(`${r}/`)) {
      if (best === null || r.length > best.length) best = r;
    }
  }
  return best;
}

export function under(root: string, file: string): boolean {
  return root === "" || file.startsWith(`${root}/`);
}

function rel(root: string, file: string): string {
  return root === "" ? file : file.slice(root.length + 1);
}

function isRequirementsFile(base: string): boolean {
  return /^requirements[\w.-]*\.txt$/.test(base);
}

export function detectUnits(input: DetectInput): Detection {
  const { files, read } = input;
  const fileSet = new Set(files);
  // 1. Candidate roots and their manifests.
  const roots = new Map<string, Manifest[]>();
  for (const f of files) {
    const base = f.split("/").pop()!;
    const dir = dirname(f) === "." ? "" : dirname(f);
    let m: Manifest | null = null;
    if (base === "package.json") {
      const text = read(f);
      m = text === null ? null : parsePackageJson(text, dir, f);
    } else if (base === "pyproject.toml") {
      const text = read(f);
      m = text === null ? null : parsePyproject(text, dir, f);
    } else if (isRequirementsFile(base)) {
      const text = read(f);
      m = text === null ? null : parseRequirementsTxt(text, dir, f);
    } else continue;
    if (!roots.has(dir)) roots.set(dir, []);
    if (m) roots.get(dir)!.push(m);
  }
  const rootList = [...roots.keys()].sort();
  const filesByRoot = new Map<string, string[]>(rootList.map((r) => [r, []]));
  for (const f of files) {
    const r = rootOf(f, rootList);
    if (r !== null) filesByRoot.get(r)!.push(f);
  }

  const units: UnitInfo[] = [];
  const allBackends = new Set<Backend>();
  const notChecked: NotCheckedEntry[] = [];
  const unsupported = new Set<string>();

  for (const root of rootList) {
    const manifests = roots.get(root)!;
    const unitFiles = filesByRoot.get(root)!;
    const backends = new Set<Backend>();
    if (hasDep(manifests, "npm", "@supabase/supabase-js") || hasDep(manifests, "npm", "@supabase/ssr") || hasDep(manifests, "PyPI", "supabase")) backends.add("supabase");
    if (hasDep(manifests, "npm", "firebase") || hasDep(manifests, "npm", "firebase-admin") || fileSet.has(root ? `${root}/firebase.json` : "firebase.json") || fileSet.has("firebase.json"))
      backends.add("firebase");
    for (const b of backends) allBackends.add(b);

    const add = (kind: ServiceKind, framework: Framework, extra: Partial<UnitInfo> = {}) =>
      units.push({ kind, framework, root, files: unitFiles, manifests, backends, ...extra });

    // Next.js
    if (hasDep(manifests, "npm", "next") && unitFiles.some((f) => /^(?:src\/)?(?:app|pages)\//.test(rel(root, f)))) {
      add("web", "nextjs");
      add("api", "nextjs");
    }
    if (hasDep(manifests, "npm", "express")) add("api", "express");
    if (hasDep(manifests, "PyPI", "fastapi")) add("api", "fastapi");
    if (hasDep(manifests, "npm", "vite") && fileSet.has(root ? `${root}/index.html` : "index.html")) add("web", "vite");

    // MCP (TypeScript)
    if (hasDep(manifests, "npm", "@modelcontextprotocol/sdk")) {
      const serverFiles = unitFiles.filter((f) => /\.(?:[cm]?[jt]sx?)$/.test(f) && constructsMcpServerTs(read(f) ?? ""));
      if (serverFiles.length) add("mcp", "mcp-ts", { mcp: { transports: transportsTs(unitFiles, read), deployment: deployment(root, fileSet, input.mcpDeployment, unitFiles, read), serverFiles } });
    }
    // MCP (Python)
    if (hasDep(manifests, "PyPI", "mcp") || hasDep(manifests, "PyPI", "fastmcp")) {
      const serverFiles = unitFiles.filter((f) => f.endsWith(".py") && constructsMcpServerPy(read(f) ?? ""));
      if (serverFiles.length) add("mcp", "mcp-py", { mcp: { transports: transportsPy(unitFiles, read), deployment: deployment(root, fileSet, input.mcpDeployment, [], read), serverFiles } });
    }

    if (hasDep(manifests, "PyPI", "flask")) unsupported.add("Flask");
    if (hasDep(manifests, "npm", "hono")) unsupported.add("Hono");
  }
  for (const f of files) {
    const base = f.split("/").pop()!;
    if (base === "manage.py") unsupported.add("Django");
    if (base === "go.mod") unsupported.add("Go");
    if (base === "Gemfile" && /\brails\b/.test(read(f) ?? "")) unsupported.add("Rails");
  }
  for (const fw of [...unsupported].sort()) notChecked.push({ area: `${fw} routes`, reason: "not supported in v1" });

  units.sort((a, b) => (a.root < b.root ? -1 : a.root > b.root ? 1 : 0) || a.kind.localeCompare(b.kind) || a.framework.localeCompare(b.framework));
  return { units, roots, backends: allBackends, notChecked };
}

/** `new McpServer(` anywhere, or `new Server(` when Server comes from the MCP SDK. */
export function constructsMcpServerTs(text: string): boolean {
  if (/\bnew\s+McpServer\s*\(/.test(text)) return true;
  if (/\bnew\s+Server\s*\(/.test(text) && /@modelcontextprotocol\/sdk\/server/.test(text)) return true;
  return false;
}

/** `FastMCP(` / `MCPServer(` (mcp 2.x), or a low-level `Server(` imported from the mcp package. */
export function constructsMcpServerPy(text: string): boolean {
  if (/\b(?:FastMCP|MCPServer)\s*\(/.test(text)) return true;
  if (/(?<![\w.])Server\s*\(/.test(text) && /^\s*from\s+mcp\.server(?:\.lowlevel)?(?:\.server)?\s+import\s+[^\n]*\bServer\b/m.test(text)) return true;
  return false;
}

/** Hosting adapters that exist only to serve MCP over HTTP from a platform (Cloudflare Agents, Vercel mcp-handler). */
// Anchored to real `import` / `class` lines, so code quoted inside strings (tests, docs) does not count.
const REMOTE_ONLY_TS = /^\s*import\s[^;]*?from\s+["'](?:agents\/mcp|mcp-handler|@vercel\/mcp-adapter)["']|^\s*(?:export\s+)?(?:default\s+)?class\s+\w+\s+extends\s+McpAgent\b/m;

function transportsTs(files: readonly string[], read: (f: string) => string | null): Set<McpTransport> {
  const out = new Set<McpTransport>();
  for (const f of files) {
    if (!/\.(?:[cm]?[jt]sx?)$/.test(f)) continue;
    const t = read(f) ?? "";
    if (/\bStdioServerTransport\b/.test(t)) out.add("stdio");
    if (/\b(?:WebStandard)?StreamableHTTPServerTransport\b|\bSSEServerTransport\b/.test(t) || REMOTE_ONLY_TS.test(t)) out.add("http");
  }
  if (out.size === 0) out.add("stdio");
  return out;
}

/** Receivers whose `.run(...)` is not an MCP server run (uvicorn.run, asyncio.run, subprocess.run, ...). */
const NON_MCP_RUN = /(?:^|[^\w.])(?:uvicorn|asyncio|anyio|trio|subprocess|app|loop|runner|thread|pool|executor|cli|typer|click)\.run\s*\($/;

function transportsPy(files: readonly string[], read: (f: string) => string | null): Set<McpTransport> {
  const out = new Set<McpTransport>();
  for (const f of files) {
    if (!f.endsWith(".py")) continue;
    const t = read(f) ?? "";
    // Only `<server>.run(...)` where <server> was assigned FastMCP(...) / MCPServer(...), when such a variable exists.
    const servers = [...t.matchAll(/^\s*(\w+)\s*(?::[^=\n]+)?=\s*(?:\w+\.)?(?:FastMCP|MCPServer)\s*\(/gm)].map((m) => m[1]!);
    for (const m of t.matchAll(/([\w.]*)\.run\s*\(([^)]*)\)/g)) {
      const recv = m[1] ?? "";
      if (servers.length ? !servers.includes(recv) : NON_MCP_RUN.test(`${recv}.run(`)) continue;
      const a = m[2] ?? "";
      if (/["'](?:streamable-http|http|sse)["']/.test(a)) out.add("http");
      else if (!/transport\s*=/.test(a) || /["']stdio["']/.test(a)) out.add("stdio");
    }
    if (/\.(?:streamable_http_app|sse_app|http_app)\s*\(/.test(t)) out.add("http");
    // Low-level servers served over HTTP through the SDK's session manager / transports.
    if (/\b(?:StreamableHTTPSessionManager|SseServerTransport|StreamableHTTPServerTransport)\s*\(/.test(t)) out.add("http");
    if (/stdio_server\s*\(/.test(t)) out.add("stdio");
  }
  if (out.size === 0) out.add("stdio");
  return out;
}

function deployment(root: string, fileSet: ReadonlySet<string>, configured: "auto" | "local" | "remote", files: readonly string[], read: (f: string) => string | null): "local" | "remote" {
  if (configured !== "auto") return configured;
  for (const f of DEPLOY_FILES) {
    if (fileSet.has(f) || (root && fileSet.has(`${root}/${f}`))) return "remote";
  }
  // Cloudflare Agents (McpAgent) and Vercel mcp-handler only run on the hosting platform.
  if (files.some((f) => /\.(?:[cm]?[jt]sx?)$/.test(f) && REMOTE_ONLY_TS.test(read(f) ?? ""))) return "remote";
  return "local";
}
