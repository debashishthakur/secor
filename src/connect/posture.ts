// Connect posture for score and dashboard: discovered servers, their scores, and hooks status (spec section 10).

import { join } from "node:path";
import { readJsonFile } from "../engine/util/fsx.js";
import { home } from "../engine/util/paths.js";
import { serverScore } from "../engine/score.js";
import type { HooksStatus, VetReport } from "../types.js";
import { type DiscoveredServer, discoverServers } from "./discover.js";
import { readLedger } from "./ledger.js";
import { loadScopes } from "./scopes.js";
import { loadServers } from "./servers.js";

export interface ServerPosture {
  name: string;
  source: string;
  managed: boolean;
  transport: "stdio" | "http";
  sandbox: "yes" | "no" | "n/a";
  vetted: boolean;
  vetVerdict: VetReport["verdict"] | null;
  scoped: boolean;
  changed: boolean;
  score: number;
}

export interface ConnectPosture {
  servers: ServerPosture[];
  hooks: HooksStatus;
  score: number | null;
}

const DAY = 86_400_000;

export function claudeSettingsFiles(projectRoot: string): string[] {
  const h = home();
  const files = [
    join(h, ".claude", "settings.json"),
    join(h, ".claude", "settings.local.json"),
    join(projectRoot, ".claude", "settings.json"),
    join(projectRoot, ".claude", "settings.local.json"),
  ];
  if (process.platform === "darwin") files.push("/Library/Application Support/ClaudeCode/managed-settings.json");
  else if (process.platform === "linux") files.push("/etc/claude-code/managed-settings.json");
  return files;
}

export const SECOR_HOOK_COMMAND = /(?:^|[\s/"'])secor(?:\.js)?["']?\s+hook\s+(?:pre|post|protect)\b/;

/** Every `command` string under a settings `hooks` block. */
export function hookCommands(v: unknown, out: string[] = []): string[] {
  if (Array.isArray(v)) for (const x of v) hookCommands(x, out);
  else if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      if (k === "command" && typeof x === "string") out.push(x);
      else hookCommands(x, out);
    }
  }
  return out;
}

export function settingsHaveSecorHook(projectRoot: string): boolean {
  for (const f of claudeSettingsFiles(projectRoot)) {
    let data: { hooks?: unknown } | null;
    try {
      data = readJsonFile<{ hooks?: unknown }>(f);
    } catch {
      continue;
    }
    if (data && hookCommands(data.hooks).some((c) => SECOR_HOOK_COMMAND.test(c))) return true;
  }
  return false;
}

export function hooksStatus(projectRoot: string, now = new Date()): HooksStatus {
  const recent = readLedger(7 * DAY, now);
  const configured = settingsHaveSecorHook(projectRoot) || recent.length > 0;
  if (!configured) return "off";
  const cutoff = new Date(now.getTime() - DAY).toISOString();
  return recent.some((e) => e.decision === "error" && e.ts >= cutoff) ? "degraded" : "on";
}

/** SECOR's own MCP server is not a third-party server and is not scored. */
export function isSecorItself(s: DiscoveredServer): boolean {
  const base = (s.command ?? "").split(/[\\/]/).pop();
  return s.transport === "stdio" && (base === "secor" || base === "secor.js") && s.args?.[0] === "mcp";
}

export function connectPosture(projectRoot: string, now = new Date()): ConnectPosture {
  const discovered = discoverServers(projectRoot).filter((s) => !isSecorItself(s));
  let managed: ReturnType<typeof loadServers>["servers"] = {};
  let scopedNames = new Set<string>();
  try {
    managed = loadServers().servers;
  } catch {
    managed = {};
  }
  try {
    scopedNames = new Set(Object.keys(loadScopes().servers));
  } catch {
    scopedNames = new Set();
  }
  const servers: ServerPosture[] = discovered.map((d) => {
    // Own keys only: a server named "constructor" or "toString" must not read Object.prototype.
    const m = Object.hasOwn(managed, d.name) ? managed[d.name] : undefined;
    const verdict = m?.vet?.verdict ?? null;
    const p = {
      name: d.name,
      source: d.source,
      managed: !!m,
      transport: d.transport,
      sandbox: d.sandbox,
      vetted: !!m && verdict !== null && verdict !== "incomplete",
      vetVerdict: verdict,
      scoped: scopedNames.has(d.name),
      changed: m?.changed === true,
    };
    return { ...p, score: serverScore(p) };
  });
  const hooks = hooksStatus(projectRoot, now);
  let score: number | null = servers.length ? Math.min(...servers.map((s) => s.score)) : null;
  if (score !== null && hooks !== "on") score = Math.min(score, 79);
  return { servers, hooks, score };
}
