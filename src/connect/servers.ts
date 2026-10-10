// ~/.secor/servers.json (spec section 6.4). Written by SECOR; approval state changes only through
// interactive CLI commands run by a human (`secor connect add`, `secor connect approve`).
// Server and tool names come from editor configs and MCP servers, so records are read with own-key lookups only.

import { join } from "node:path";
import type { VetFinding, VetReport } from "../types.js";
import { readJsonFile, writeFileAtomic } from "../engine/util/fsx.js";
import { secorHome } from "../engine/util/paths.js";

export interface ToolChange {
  tool: string;
  change: "added" | "removed" | "changed";
}

export interface ManagedServer {
  source: string;
  transport: "stdio" | "http";
  addedAt: string;
  vet: { at: string; verdict: VetReport["verdict"]; findings: VetFinding[] } | null;
  toolHashes: Record<string, string>;
  approvedAt: string | null;
  changed: boolean;
  changes: ToolChange[];
  sandbox: "yes" | "no" | "n/a";
  lastDriftCheck: string | null;
}

export interface ServersFile {
  version: 1;
  servers: Record<string, ManagedServer>;
}

export function serversPath(): string {
  return join(secorHome(), "servers.json");
}

export function loadServers(path = serversPath()): ServersFile {
  const data = readJsonFile<ServersFile>(path);
  if (!data) return { version: 1, servers: {} };
  if (data.version !== 1 || typeof data.servers !== "object" || data.servers === null || Array.isArray(data.servers)) {
    throw new Error("~/.secor/servers.json: unsupported format (expected version 1)");
  }
  return data;
}

export function saveServers(file: ServersFile, path = serversPath()): void {
  const servers = Object.create(null) as Record<string, ManagedServer>;
  for (const name of Object.keys(file.servers).sort()) servers[name] = file.servers[name]!;
  writeFileAtomic(path, `${JSON.stringify({ version: 1, servers }, null, 2)}\n`);
}

/** The managed entry for `name`, by own key only. */
export function managedServer(file: ServersFile, name: string): ManagedServer | undefined {
  return Object.hasOwn(file.servers, name) ? file.servers[name] : undefined;
}

export function isManaged(file: ServersFile, name: string): boolean {
  return Object.hasOwn(file.servers, name);
}

/** Tool names of every managed server except `exceptName` (for vet/name-collision). */
export function otherManagedTools(file: ServersFile, exceptName: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const name of Object.keys(file.servers).sort()) {
    if (name === exceptName) continue;
    const hashes = file.servers[name]?.toolHashes;
    out.set(name, hashes && typeof hashes === "object" ? Object.keys(hashes).sort() : []);
  }
  return out;
}

/** Re-read servers.json, apply `fn` to the fresh copy and save, so concurrent writers lose as little as possible. */
export function updateServers(fn: (file: ServersFile) => void, path = serversPath()): ServersFile {
  const file = loadServers(path);
  fn(file);
  saveServers(file, path);
  return file;
}
