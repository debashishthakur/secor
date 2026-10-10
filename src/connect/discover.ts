// MCP server discovery from editor configs (spec section 9.1). Values from `env` and `headers`
// are passed through for connecting but never logged or printed.

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseJsonc } from "../engine/resolve.js";
import { canonicalJson, sha256Hex } from "../engine/util/hash.js";
import { home } from "../engine/util/paths.js";

export type Editor = "claude-code" | "cursor" | "claude-desktop" | "vscode";

export interface DiscoveredServer {
  name: string;
  /**
   * "<editor>:<scope>:<config file>", e.g. "claude-code:project:/Users/me/app/.mcp.json".
   * Claude Code local-scope entries live under projects["<abs project>"] in ~/.claude.json, so their
   * source also names the project: "claude-code:local:/Users/me/.claude.json#/Users/me/app".
   */
  source: string;
  editor: Editor;
  file: string;
  /** JSON key path of the entry inside the config file (used by --apply-sandbox). */
  keyPath: string[];
  transport: "stdio" | "http";
  /** For http entries: "http" | "streamable-http" | "sse". */
  type?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  sandbox: "yes" | "no" | "n/a";
}

/** Expand ${VAR} and ${VAR:-default} from the process environment; unset variables without a default stay as written. */
export function expandVars(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (whole, name: string, dflt: string | undefined) => {
    const v = env[name];
    if (v !== undefined && v !== "") return v;
    if (dflt !== undefined) return dflt;
    return whole;
  });
}

export interface ConfigSpec {
  editor: Editor;
  scope: string;
  file: string;
  /** Key path to the servers object inside the file. */
  key: string[];
  /** Extra text appended to the source (the project path for Claude Code local scope). */
  sourceSuffix?: string;
}

/** Absolute project path as Claude Code records it in ~/.claude.json (the real path when it exists). */
export function projectKey(projectRoot: string): string {
  const abs = resolve(projectRoot);
  try {
    return realpathSync(abs);
  } catch {
    return abs;
  }
}

export function claudeDesktopConfigFile(): string | null {
  if (process.platform === "darwin") return join(home(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
  if (process.platform === "win32" && process.env.APPDATA) return join(process.env.APPDATA, "Claude", "claude_desktop_config.json");
  return null;
}

export function configSpecs(projectRoot: string): ConfigSpec[] {
  const h = home();
  const proj = projectKey(projectRoot);
  const specs: ConfigSpec[] = [
    { editor: "claude-code", scope: "project", file: join(proj, ".mcp.json"), key: ["mcpServers"] },
    { editor: "claude-code", scope: "local", file: join(h, ".claude.json"), key: ["projects", proj, "mcpServers"], sourceSuffix: `#${proj}` },
    { editor: "claude-code", scope: "user", file: join(h, ".claude.json"), key: ["mcpServers"] },
    { editor: "cursor", scope: "user", file: join(h, ".cursor", "mcp.json"), key: ["mcpServers"] },
    { editor: "cursor", scope: "project", file: join(proj, ".cursor", "mcp.json"), key: ["mcpServers"] },
    { editor: "vscode", scope: "project", file: join(proj, ".vscode", "mcp.json"), key: ["servers"] },
  ];
  const desktop = claudeDesktopConfigFile();
  if (desktop) specs.push({ editor: "claude-desktop", scope: "user", file: desktop, key: ["mcpServers"] });
  return specs;
}

function readConfig(file: string, cache: Map<string, unknown>): unknown {
  if (cache.has(file)) return cache.get(file);
  let data: unknown = null;
  try {
    if (existsSync(file)) data = parseJsonc(readFileSync(file, "utf8"));
  } catch {
    data = null;
  }
  cache.set(file, data);
  return data;
}

function at(obj: unknown, path: string[]): unknown {
  let cur = obj;
  for (const k of path) {
    if (!cur || typeof cur !== "object" || !Object.hasOwn(cur, k)) return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

function strRecord(v: unknown): Record<string, string> | undefined {
  if (!v || typeof v !== "object") return undefined;
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) if (typeof val === "string") out[k] = expandVars(val);
  return out;
}

export function sandboxStatus(command: string | undefined, args: readonly string[] | undefined, transport: "stdio" | "http"): "yes" | "no" | "n/a" {
  if (transport === "http") return "n/a";
  const base = (command ?? "").split(/[\\/]/).pop();
  return base === "docker" && args?.[0] === "run" ? "yes" : "no";
}

function sourceOf(spec: ConfigSpec): string {
  return `${spec.editor}:${spec.scope}:${spec.file}${spec.sourceSuffix ?? ""}`;
}

/** Build a DiscoveredServer from one raw config entry, or null when the entry is not a usable server. */
export function parseServerEntry(name: string, entryRaw: unknown, spec: ConfigSpec): DiscoveredServer | null {
  if (!entryRaw || typeof entryRaw !== "object" || Array.isArray(entryRaw)) return null;
  const e = entryRaw as Record<string, unknown>;
  const type = typeof e.type === "string" ? e.type : undefined;
  const isHttp = type === "http" || type === "streamable-http" || type === "sse" || (type === undefined && typeof e.url === "string");
  const base = { name, source: sourceOf(spec), editor: spec.editor, file: spec.file, keyPath: [...spec.key, name] };
  if (isHttp) {
    return {
      ...base,
      transport: "http",
      type: type ?? "http",
      url: typeof e.url === "string" ? expandVars(e.url) : undefined,
      headers: strRecord(e.headers),
      sandbox: "n/a",
    };
  }
  if ((type === undefined || type === "stdio") && typeof e.command === "string") {
    const args = Array.isArray(e.args) ? e.args.filter((a): a is string => typeof a === "string").map((a) => expandVars(a)) : [];
    const command = expandVars(e.command);
    return { ...base, transport: "stdio", command, args, env: strRecord(e.env), sandbox: sandboxStatus(command, args, "stdio") };
  }
  return null;
}

function serversIn(spec: ConfigSpec, cache: Map<string, unknown>): DiscoveredServer[] {
  const servers = at(readConfig(spec.file, cache), spec.key);
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return [];
  const out: DiscoveredServer[] = [];
  for (const [name, entryRaw] of Object.entries(servers as Record<string, unknown>)) {
    // A "__proto__" key cannot be used safely as a record key anywhere downstream.
    if (!name || name === "__proto__") continue;
    const s = parseServerEntry(name, entryRaw, spec);
    if (s) out.push(s);
  }
  return out;
}

function byNameThenSource(a: DiscoveredServer, b: DiscoveredServer): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : a.source < b.source ? -1 : a.source > b.source ? 1 : 0;
}

export function discoverServers(projectRoot: string): DiscoveredServer[] {
  const cache = new Map<string, unknown>();
  const out: DiscoveredServer[] = [];
  for (const spec of configSpecs(projectRoot)) out.push(...serversIn(spec, cache));
  return out.sort(byNameThenSource);
}

/** Parse a source string back into the config location it names (null when it is not one SECOR reads). */
export function specFromSource(source: string): ConfigSpec | null {
  const m = /^(claude-code|cursor|claude-desktop|vscode):(project|local|user):(.+)$/.exec(source);
  if (!m) return null;
  const editor = m[1] as Editor;
  const scope = m[2]!;
  const rest = m[3]!;
  if (editor === "claude-code" && scope === "local") {
    const marker = ".claude.json#";
    const idx = rest.indexOf(marker);
    if (idx < 0) return null;
    const file = rest.slice(0, idx + ".claude.json".length);
    const project = rest.slice(idx + marker.length);
    if (!project) return null;
    return { editor, scope, file, key: ["projects", project, "mcpServers"], sourceSuffix: `#${project}` };
  }
  return { editor, scope, file: rest, key: [editor === "vscode" ? "servers" : "mcpServers"] };
}

/** The current definition of a server at a recorded source (used by drift and approve), or null when it is gone. */
export function serverFromSource(name: string, source: string): DiscoveredServer | null {
  const spec = specFromSource(source);
  if (!spec) return null;
  return serversIn(spec, new Map()).find((s) => s.name === name) ?? null;
}

/** Pick one discovered server by name (and source when names collide with different definitions). */
export function findServer(all: DiscoveredServer[], name: string, source?: string): { server?: DiscoveredServer; error?: string } {
  const matches = all.filter((s) => s.name === name && (!source || s.source === source));
  if (matches.length === 0) return { error: source ? `No server named "${name}" in ${source}.` : `No MCP server named "${name}" was found in editor configs.` };
  const distinct = new Map(matches.map((m) => [definitionKey(m), m]));
  if (distinct.size > 1) {
    return { error: `"${name}" is defined differently in several places. Pass --source with one of:\n${matches.map((m) => `  ${m.source}`).join("\n")}` };
  }
  return { server: matches[0] };
}

/** Identity of a definition. env and header values are compared by hash only, never kept or printed. */
export function definitionKey(s: DiscoveredServer): string {
  const secrets = sha256Hex(canonicalJson({ env: s.env ?? {}, headers: s.headers ?? {} }));
  return JSON.stringify([s.transport, s.command ?? null, s.args ?? null, s.url ?? null, s.type ?? null, secrets]);
}
