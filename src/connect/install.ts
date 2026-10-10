// `secor connect install-hooks` / `uninstall-hooks` (spec section 9.4, manual route). Merges SECOR's hook block into a
// Claude Code settings file after backing it up; idempotent; keeps every other hook. Uninstall removes only SECOR's
// entries. The same block ships as hooks/hooks.json for the plugin route (section 11.4).
//
// Matchers are anchored regexes (Claude Code treats a matcher as an unanchored regex unless it contains only
// letters, digits, "_", "|", " " and "-"), so "mcp__.*" cannot match a tool that merely contains "mcp__", and
// "Read" cannot match "ReadMcpResourceTool". "Edit|Write|MultiEdit" is an exact-name list as written.

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { writeFileAtomic } from "../engine/util/fsx.js";
import { home } from "../engine/util/paths.js";
import { backupFile } from "./backup.js";
import { SECOR_HOOK_COMMAND } from "./posture.js";

export const HOOK_TIMEOUT_SECONDS = 5;

export const SECOR_HOOKS = {
  hooks: {
    PreToolUse: [
      { matcher: "^mcp__.*", hooks: [{ type: "command", command: "secor hook pre", timeout: HOOK_TIMEOUT_SECONDS }] },
      { matcher: "Edit|Write|MultiEdit", hooks: [{ type: "command", command: "secor hook protect", timeout: HOOK_TIMEOUT_SECONDS }] },
    ],
    PostToolUse: [{ matcher: "^(mcp__.*|Read)$", hooks: [{ type: "command", command: "secor hook post", timeout: HOOK_TIMEOUT_SECONDS }] }],
  },
} as const;

type Json = Record<string, unknown>;

export function settingsFileFor(scope: "user" | "project", projectRoot: string): string {
  return scope === "user" ? join(home(), ".claude", "settings.json") : join(projectRoot, ".claude", "settings.json");
}

function isObj(v: unknown): v is Json {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function isSecorHook(h: unknown): boolean {
  return isObj(h) && typeof h.command === "string" && SECOR_HOOK_COMMAND.test(h.command);
}

/** Settings with every SECOR hook removed (groups and events emptied by that are removed too). */
export function removeSecorHooks(settings: Json): { settings: Json; changed: boolean } {
  const out = structuredClone(settings);
  const hooks = out.hooks;
  if (!isObj(hooks)) return { settings: out, changed: false };
  let changed = false;
  for (const event of Object.keys(hooks)) {
    const groups = hooks[event];
    if (!Array.isArray(groups)) continue;
    const kept: unknown[] = [];
    for (const g of groups) {
      if (!isObj(g) || !Array.isArray(g.hooks) || !g.hooks.some(isSecorHook)) {
        kept.push(g);
        continue;
      }
      changed = true;
      const rest = g.hooks.filter((h) => !isSecorHook(h));
      if (rest.length) kept.push({ ...g, hooks: rest });
    }
    if (kept.length) hooks[event] = kept;
    else if (kept.length !== groups.length) delete hooks[event];
  }
  if (changed && Object.keys(hooks).length === 0) delete out.hooks;
  return { settings: out, changed };
}

function secorHookCount(settings: Json): number {
  const hooks = settings.hooks;
  if (!isObj(hooks)) return 0;
  let n = 0;
  for (const groups of Object.values(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) if (isObj(g) && Array.isArray(g.hooks)) n += g.hooks.filter(isSecorHook).length;
  }
  return n;
}

/** True when the settings already hold exactly SECOR's block (and no other SECOR hook). */
export function hasSecorBlock(settings: Json): boolean {
  const hooks = settings.hooks;
  if (!isObj(hooks)) return false;
  let expected = 0;
  for (const [event, groups] of Object.entries(SECOR_HOOKS.hooks)) {
    const present = hooks[event];
    if (!Array.isArray(present)) return false;
    for (const g of groups) {
      expected += g.hooks.length;
      if (!present.some((p) => isDeepStrictEqual(p, g))) return false;
    }
  }
  return secorHookCount(settings) === expected;
}

/** Settings with SECOR's block merged in (older SECOR entries replaced, other hooks kept in place). */
export function mergeSecorHooks(settings: Json): { settings: Json; changed: boolean } {
  if (hasSecorBlock(settings)) return { settings: structuredClone(settings), changed: false };
  const { settings: out } = removeSecorHooks(settings);
  if (out.hooks !== undefined && !isObj(out.hooks)) throw new Error('"hooks" in the settings file is not an object');
  const hooks = (out.hooks ?? {}) as Json;
  for (const [event, groups] of Object.entries(SECOR_HOOKS.hooks)) {
    const present = hooks[event];
    if (present !== undefined && !Array.isArray(present)) throw new Error(`"hooks.${event}" in the settings file is not a list`);
    hooks[event] = [...((present as unknown[] | undefined) ?? []), ...structuredClone(groups as unknown as unknown[])];
  }
  out.hooks = hooks;
  return { settings: out, changed: true };
}

function readSettings(path: string): Json {
  if (!existsSync(path)) return {};
  const text = readFileSync(path, "utf8");
  if (!text.trim()) return {};
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new Error(`${path} is not valid JSON; fix it first (SECOR did not change it)`);
  }
  if (!isObj(v)) throw new Error(`${path} does not hold a JSON object; fix it first (SECOR did not change it)`);
  return v;
}

function writeSettings(path: string, settings: Json, existed: boolean): void {
  const mode = existed ? statSync(path).mode & 0o777 : 0o600;
  writeFileAtomic(path, `${JSON.stringify(settings, null, 2)}\n`, mode);
}

export interface HookFileResult {
  path: string;
  changed: boolean;
  backup: string | null;
}

export function installHooks(scope: "user" | "project", projectRoot: string, now = new Date()): HookFileResult {
  const path = settingsFileFor(scope, projectRoot);
  const existed = existsSync(path);
  const current = readSettings(path);
  const { settings, changed } = mergeSecorHooks(current);
  if (!changed) return { path, changed: false, backup: null };
  const backup = existed ? backupFile(path, now) : null;
  writeSettings(path, settings, existed);
  return { path, changed: true, backup };
}

/** Remove SECOR's hooks from the user and project settings files (or one scope). */
export function uninstallHooks(projectRoot: string, scope?: "user" | "project", now = new Date()): HookFileResult[] {
  const files =
    scope === "user"
      ? [join(home(), ".claude", "settings.json"), join(home(), ".claude", "settings.local.json")]
      : scope === "project"
        ? [join(projectRoot, ".claude", "settings.json"), join(projectRoot, ".claude", "settings.local.json")]
        : [join(home(), ".claude", "settings.json"), join(home(), ".claude", "settings.local.json"), join(projectRoot, ".claude", "settings.json"), join(projectRoot, ".claude", "settings.local.json")];
  const out: HookFileResult[] = [];
  for (const path of [...new Set(files)]) {
    if (!existsSync(path)) continue;
    const { settings, changed } = removeSecorHooks(readSettings(path));
    if (!changed) {
      out.push({ path, changed: false, backup: null });
      continue;
    }
    const backup = backupFile(path, now);
    writeSettings(path, settings, true);
    out.push({ path, changed: true, backup });
  }
  return out;
}
