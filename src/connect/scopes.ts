// ~/.secor/scopes.yaml (spec section 6.3). Humans own this file: only `secor connect add` (interactive) writes it.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { parseYamlFile, validate } from "../engine/config.js";
import type { DataClass } from "../types.js";
import { secorHome } from "../engine/util/paths.js";

const DataClassEnum = z.enum(["secret", "credential", "personal_data", "confidential"]);

const ServerScope = z.strictObject({
  description: z.string().optional(),
  tools: z.array(z.string().min(1)).optional(),
  never: z.array(DataClassEnum).optional(),
  fromServers: z.array(z.string().min(1)).default([]),
  paths: z.array(z.string().min(1)).default([]),
  onViolation: z.enum(["ask", "block"]).optional(),
  sandbox: z.strictObject({ mounts: z.array(z.string().min(1)).default([]) }).optional(),
});

export const ScopesFileSchema = z.strictObject({
  version: z.literal(1),
  defaults: z
    .strictObject({
      never: z.array(DataClassEnum).default(["secret", "credential", "personal_data", "confidential"]),
      onViolation: z.enum(["ask", "block"]).default("ask"),
      unvetted: z.enum(["pass", "ask", "block"]).default("ask"),
      maxArgChars: z.number().int().positive().default(20000),
      failMode: z.enum(["open", "closed"]).default("open"),
    })
    .default({ never: ["secret", "credential", "personal_data", "confidential"], onViolation: "ask", unvetted: "ask", maxArgChars: 20000, failMode: "open" }),
  confidential: z
    .strictObject({
      paths: z.array(z.string().min(1)).default([]),
      patterns: z
        .array(
          z.string().refine((p) => {
            try {
              new RegExp(p);
              return true;
            } catch {
              return false;
            }
          }, "not a valid regular expression"),
        )
        .default([]),
    })
    .default({ paths: [], patterns: [] }),
  servers: z.record(z.string(), ServerScope).default({}),
});

export type ScopesFile = z.infer<typeof ScopesFileSchema>;
export type ServerScopeEntry = z.infer<typeof ServerScope>;

export interface EffectiveScope {
  server: string;
  managedScope: boolean;
  tools: string[] | null;
  never: DataClass[];
  fromServers: string[];
  paths: string[];
  onViolation: "ask" | "block";
}

export function scopesPath(): string {
  return join(secorHome(), "scopes.yaml");
}

export function defaultScopes(): ScopesFile {
  return ScopesFileSchema.parse({ version: 1 });
}

export function loadScopes(path = scopesPath()): ScopesFile {
  if (!existsSync(path)) return defaultScopes();
  return validate(ScopesFileSchema, parseYamlFile(path, "~/.secor/scopes.yaml"), "~/.secor/scopes.yaml");
}

/** The server's scope entry, if the human wrote one (own keys only, so "constructor" etc. never match). */
export function scopeEntry(scopes: ScopesFile, server: string): ServerScopeEntry | undefined {
  return Object.hasOwn(scopes.servers, server) ? scopes.servers[server] : undefined;
}

/** The server's scope merged over defaults. `never` on a server replaces defaults.never. */
export function effectiveScope(scopes: ScopesFile, server: string): EffectiveScope {
  const s = scopeEntry(scopes, server);
  return {
    server,
    managedScope: !!s,
    tools: s?.tools ?? null,
    never: (s?.never ?? scopes.defaults.never) as DataClass[],
    fromServers: s?.fromServers ?? [],
    paths: s?.paths ?? [],
    onViolation: s?.onViolation ?? scopes.defaults.onViolation,
  };
}
