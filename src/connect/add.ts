// `secor connect add` (spec section 9.3) and `secor connect approve` (section 9.7): interactive commands run by a
// human in a terminal. They are the only writers of scopes.yaml and of the approval state in servers.json
// (invariant 6). The prompt logic takes an injectable PromptIO so tests can drive it; the CLI refuses to run them
// when stdin is not a terminal.

import { readFileSync, statSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { parseJsonc } from "../engine/resolve.js";
import { writeFileAtomic } from "../engine/util/fsx.js";
import { expandHome, home } from "../engine/util/paths.js";
import { DATA_CLASSES, type DataClass, EVIDENCE_NOTICE, type VetReport } from "../types.js";
import { backupFile } from "./backup.js";
import { type DiscoveredServer, discoverServers, expandVars, findServer, serverFromSource } from "./discover.js";
import { diffToolHashes } from "./drift.js";
import { findValueSpan, replaceJsonValue } from "./jsonedit.js";
import { isPlainName, normalizeMcpName } from "./names.js";
import { isSecorItself } from "./posture.js";
import { checkMounts, commandBase, forwardableEnvNames, sandboxImageFor, shellQuote, wrapperArgs } from "./sandbox.js";
import { loadScopes, scopeEntry } from "./scopes.js";
import { type NewServerScope, writeServerScope } from "./scopes-write.js";
import { type ManagedServer, loadServers, managedServer, otherManagedTools, updateServers } from "./servers.js";
import { displayName, safeText } from "./text.js";
import { type VetOutcome, powerfulTools, vetServer } from "./vet.js";

export interface PromptIO {
  /** Ask one question and return the line the human typed. */
  ask(question: string): Promise<string>;
  /** Print text (already redacted by the caller where needed). */
  print(text: string): void;
}

export interface FlowOptions {
  name: string;
  source?: string;
  allowUnsandboxed?: boolean;
  projectRoot: string;
  now?: () => Date;
  timeoutMs?: number;
  /** Injected for tests. */
  vet?: typeof vetServer;
}

export interface AddOptions extends FlowOptions {
  applySandbox?: boolean;
}

export const LEAST_PRIVILEGE =
  "Least privilege: give this server read-only tokens where the provider offers them, and only the scopes it needs. (Guidance only; not scored.)";

// ---------------------------------------------------------------- report text

const VERDICT_TEXT: Record<VetReport["verdict"], string> = {
  ok: "ok (no risky patterns found in the tool list)",
  review: "review (medium findings: check them before use)",
  "high-risk": "high-risk (high findings)",
  incomplete: "incomplete (the tool list could not be read)",
};

/** Human-readable vet report. Server text appears only after "evidence:" and is escaped and redacted. */
export function formatVetReport(r: VetReport): string {
  const lines = [
    `Vet report · ${displayName(r.server)} · ${safeText(r.source)}`,
    `Transport ${r.transport} · sandboxed ${r.sandboxed ? "yes" : "no"} · ${r.toolCount} tool${r.toolCount === 1 ? "" : "s"}`,
    `Verdict: ${VERDICT_TEXT[r.verdict]}${r.incompleteReason ? ` · reason: ${safeText(r.incompleteReason)}` : ""}`,
  ];
  if (r.findings.length) {
    lines.push("Findings:");
    for (const f of r.findings) {
      const sev = f.severity[0]!.toUpperCase() + f.severity.slice(1);
      lines.push(`  ${sev.padEnd(7)} ${f.checkId}${f.tool !== undefined ? `  tool ${f.tool}` : ""}`);
      lines.push(`          evidence: ${f.evidence}`);
    }
    lines.push(EVIDENCE_NOTICE);
  } else if (r.verdict !== "incomplete") {
    lines.push("Findings: none");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------- choosing items

export type ToggleAnswer = { kind: "accept" } | { kind: "all" } | { kind: "none" } | { kind: "toggle"; indexes: number[] } | { kind: "error"; message: string };

/** Parse an answer to a tick-list prompt: Enter, "all", "none", or 1-based numbers and ranges ("2,5" / "1-3"). */
export function parseToggleAnswer(answer: string, count: number): ToggleAnswer {
  const a = answer.trim().toLowerCase();
  if (a === "") return { kind: "accept" };
  if (a === "all") return { kind: "all" };
  if (a === "none") return { kind: "none" };
  const indexes: number[] = [];
  for (const part of a.split(/[\s,]+/).filter(Boolean)) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!m) return { kind: "error", message: `"${part}" is not a number or range` };
    const from = Number(m[1]);
    const to = m[2] !== undefined ? Number(m[2]) : from;
    if (from < 1 || to > count || from > to) return { kind: "error", message: `${part} is outside 1-${count}` };
    for (let i = from; i <= to; i++) indexes.push(i - 1);
  }
  return { kind: "toggle", indexes };
}

export interface TickItem {
  label: string;
  checked: boolean;
  note?: string;
}

/** Interactive tick list. Returns the final checked state of each item. */
export async function chooseItems(io: PromptIO, title: string, items: TickItem[]): Promise<boolean[]> {
  const state = items.map((i) => i.checked);
  for (let round = 0; round < 100; round++) {
    io.print(`${title}:`);
    items.forEach((it, i) => io.print(`  [${state[i] ? "x" : " "}] ${String(i + 1).padStart(2)}  ${it.label}${it.note ? `  (${it.note})` : ""}`));
    const ans = parseToggleAnswer(await io.ask(`Enter to accept, numbers to toggle (e.g. 2,5 or 1-3), "all" or "none": `), items.length);
    if (ans.kind === "accept") return state;
    if (ans.kind === "all") state.fill(true);
    else if (ans.kind === "none") state.fill(false);
    else if (ans.kind === "toggle") for (const i of ans.indexes) state[i] = !state[i];
    else io.print(ans.message);
  }
  throw new Error("too many answers without accepting the list");
}

function yes(answer: string): boolean {
  return /^(y|yes)$/i.test(answer.trim());
}

// ---------------------------------------------------------------- sandbox wrapper for the editor config

function rawEntry(server: DiscoveredServer): { text: string; entry: Record<string, unknown> } {
  const text = readFileSync(server.file, "utf8");
  const span = findValueSpan(text, server.keyPath);
  if (!span) throw new Error(`could not find "${server.name}" in ${server.file}`);
  const entry = parseJsonc(text.slice(span.start, span.end));
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`the entry for "${server.name}" in ${server.file} is not an object`);
  return { text, entry: entry as Record<string, unknown> };
}

export interface WrapperPlan {
  args: string[];
  image: string;
}

/**
 * The docker wrapper for a stdio entry, built from the entry as written in the config (so ${VAR} placeholders stay
 * placeholders and no expanded value is ever written or printed). Mounts come from the scope, read-only.
 */
export function sandboxWrapper(server: DiscoveredServer, raw: Record<string, unknown>, mounts: readonly string[]): WrapperPlan | { error: string } {
  if (!server.command) return { error: "no command configured" };
  const image = sandboxImageFor(server.command);
  if (!image) return { error: "no sandbox image for this command" };
  const rawArgs = Array.isArray(raw.args) ? raw.args.filter((a): a is string => typeof a === "string") : [];
  const plan = { image, command: [commandBase(server.command), ...rawArgs], envNames: forwardableEnvNames(server.env), envValues: {} };
  return { image, args: wrapperArgs(plan, mounts) };
}

/** Back up the editor config and rewrite only this server's entry to run inside Docker. Returns the backup path. */
export function applySandboxToConfig(server: DiscoveredServer, wrapper: WrapperPlan, now: Date): string {
  const { text, entry } = rawEntry(server);
  const next: Record<string, unknown> = { ...entry, command: "docker", args: wrapper.args };
  const out = replaceJsonValue(text, server.keyPath, next);
  let check: unknown = parseJsonc(out);
  for (const k of server.keyPath) check = check && typeof check === "object" ? (check as Record<string, unknown>)[k] : undefined;
  if (!isDeepStrictEqual(check, next)) throw new Error(`could not rewrite ${server.file} safely; it was not changed`);
  const backup = backupFile(server.file, now);
  writeFileAtomic(server.file, out, statSync(server.file).mode & 0o777);
  return backup;
}

/** Expand ~ and ${VAR} in scope mounts and validate them. */
export function resolveMounts(mounts: readonly string[]): { mounts: string[]; errors: string[] } {
  return checkMounts(mounts.map((m) => expandHome(expandVars(m.trim()))).filter(Boolean));
}

// ---------------------------------------------------------------- add

function managedRecord(server: DiscoveredServer, outcome: VetOutcome, at: string): ManagedServer {
  const complete = outcome.report.verdict !== "incomplete";
  return {
    source: server.source,
    transport: server.transport,
    addedAt: at,
    vet: { at, verdict: outcome.report.verdict, findings: outcome.report.findings },
    toolHashes: outcome.toolHashes,
    approvedAt: at,
    changed: false,
    changes: [],
    sandbox: server.sandbox,
    lastDriftCheck: complete ? at : null,
  };
}

function scopeToolName(name: string): string {
  return isPlainName(name) ? name : normalizeMcpName(name);
}

export async function connectAdd(opts: AddOptions, io: PromptIO): Promise<number> {
  const now = opts.now ?? (() => new Date());
  const vet = opts.vet ?? vetServer;
  const found = findServer(discoverServers(opts.projectRoot), opts.name, opts.source);
  if (!found.server) {
    io.print(found.error ?? "Server not found.");
    return 2;
  }
  const server = found.server;
  const shown = displayName(server.name);
  if (isSecorItself(server)) {
    io.print("That is SECOR's own MCP server; it does not need to be added.");
    return 2;
  }
  let servers;
  let scopes;
  try {
    servers = loadServers();
    scopes = loadScopes();
  } catch (e) {
    io.print(`${safeText((e as Error).message)}\nFix that file before adding a server.`);
    return 2;
  }
  const existing = managedServer(servers, server.name);
  if (existing) {
    io.print(`${shown} is already managed (added ${existing.addedAt}). After its tools change, a human runs: secor connect approve ${shown}`);
    return 2;
  }
  const existingScope = scopeEntry(scopes, server.name);

  // Step 2: vet and print the report.
  if (opts.allowUnsandboxed && server.transport === "stdio") io.print(`Running ${shown} directly on this machine (not sandboxed), as you allowed.`);
  io.print(`Vetting ${shown} …`);
  const outcome = await vet(server, { allowUnsandboxed: opts.allowUnsandboxed === true, timeoutMs: opts.timeoutMs, otherManagedTools: otherManagedTools(servers, server.name) });
  io.print(formatVetReport(outcome.report));
  const verdict = outcome.report.verdict;
  if (verdict === "incomplete") {
    if (!yes(await io.ask("Vetting was incomplete, so the tool list is unknown. Add the server anyway, with every tool allowed? [y/N] "))) {
      io.print("Not added.");
      return 2;
    }
  } else if (verdict === "high-risk") {
    const typed = await io.ask(`This server is high-risk. Type its name (${shown}) to continue: `);
    if (typed.trim() !== server.name) {
      io.print("Not added: the name did not match.");
      return 2;
    }
  }

  // Steps 3-4: tools and forbidden data classes (only when the human has no scope for it yet).
  let entry: NewServerScope | null = null;
  let mountsWritten: string[] = [];
  if (existingScope) {
    io.print(`Keeping your existing scope for ${shown} in ~/.secor/scopes.yaml.`);
    mountsWritten = existingScope.sandbox?.mounts ?? [];
  } else {
    entry = {};
    if (verdict !== "incomplete") {
      const powerful = powerfulTools(outcome.tools);
      const tools = [...outcome.tools].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      const picked = await chooseItems(
        io,
        "Allowed tools (x = allowed; tools flagged vet/powerful-tool start unticked)",
        tools.map((t) => ({ label: displayName(t.name), checked: !powerful.has(t.name), ...(powerful.has(t.name) ? { note: "powerful" } : {}) })),
      );
      entry.tools = [...new Set(tools.filter((_, i) => picked[i]).map((t) => scopeToolName(t.name)))];
    }
    const defaults = scopes.defaults.never as DataClass[];
    const classes = await chooseItems(
      io,
      "Data classes this server must never receive (x = forbidden)",
      DATA_CLASSES.map((c) => ({ label: c, checked: defaults.includes(c) })),
    );
    const never = DATA_CLASSES.filter((_, i) => classes[i]);
    // Equal to defaults.never → inherit the defaults (a later change to the defaults then applies here too).
    if (!isDeepStrictEqual([...never].sort(), [...defaults].sort())) entry.never = never;
    if (server.transport === "stdio" && server.sandbox !== "yes") {
      for (let attempt = 0; attempt < 3; attempt++) {
        const ans = await io.ask("Directories the sandboxed server may read (read-only; comma-separated; Enter for none): ");
        const list = ans
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        const { errors } = resolveMounts(list);
        if (errors.length) {
          io.print(errors.join("\n"));
          continue;
        }
        mountsWritten = list;
        break;
      }
      if (mountsWritten.length) entry.sandbox = { mounts: mountsWritten };
    }
  }

  // Step 5: scopes.yaml (append only) and servers.json.
  const at = now().toISOString();
  if (entry) {
    const backup = writeServerScope(server.name, entry, now());
    io.print(`Added a scope for ${shown} to ~/.secor/scopes.yaml${backup ? ` (previous file backed up to ${backup})` : ""}.`);
  }
  updateServers((f) => {
    Object.defineProperty(f.servers, server.name, { value: managedRecord(server, outcome, at), enumerable: true, writable: true, configurable: true });
  });
  io.print(`Recorded ${shown} in ~/.secor/servers.json (approved ${outcome.tools.length} tool definition${outcome.tools.length === 1 ? "" : "s"}).`);

  // Step 6: sandbox (stdio only).
  if (server.transport === "stdio") {
    if (server.sandbox === "yes") io.print("This entry already runs in Docker (sandbox: yes).");
    else {
      const { mounts, errors } = resolveMounts(mountsWritten);
      for (const e of errors) io.print(`Skipping mount: ${e}`);
      for (const m of mounts) if (m === "/" || m === home()) io.print(`Note: mount ${m} exposes ${m === "/" ? "the whole disk" : "your whole home directory"} to the server (read-only).`);
      const wrapper = sandboxWrapper(server, rawEntry(server).entry, mounts);
      if ("error" in wrapper) io.print(`No sandbox: ${wrapper.error}. The server keeps running unsandboxed.`);
      else {
        io.print(`Sandbox command (env values stay in the config's "env"; only their names are passed with -e):\n  ${safeText(["docker", ...wrapper.args].map(shellQuote).join(" "))}`);
        if (opts.applySandbox) {
          const backup = applySandboxToConfig(server, wrapper, now());
          updateServers((f) => {
            const cur = managedServer(f, server.name);
            if (cur) cur.sandbox = "yes";
          });
          io.print(`Backed up ${server.file} to ${backup} and changed only the "${shown}" entry to run in Docker. Restart your editor to use it.`);
        } else {
          io.print("To use it, run this command again with --apply-sandbox, or edit the editor config by hand.");
        }
      }
    }
  } else if (opts.applySandbox) {
    io.print("--apply-sandbox applies to stdio servers only; this is an HTTP server.");
  }

  // Step 7: least-privilege guidance.
  io.print(LEAST_PRIVILEGE);
  return 0;
}

// ---------------------------------------------------------------- approve

export async function connectApprove(opts: FlowOptions, io: PromptIO): Promise<number> {
  const now = opts.now ?? (() => new Date());
  const vet = opts.vet ?? vetServer;
  let servers;
  try {
    servers = loadServers();
  } catch (e) {
    io.print(safeText((e as Error).message));
    return 2;
  }
  const m = managedServer(servers, opts.name);
  const shown = displayName(opts.name);
  if (!m) {
    io.print(`${shown} is not managed. A human adds it with: secor connect add ${shown}`);
    return 2;
  }
  let def: DiscoveredServer | null;
  if (opts.source) {
    const found = findServer(discoverServers(opts.projectRoot), opts.name, opts.source);
    if (!found.server) {
      io.print(found.error ?? "Server not found.");
      return 2;
    }
    def = found.server;
  } else def = serverFromSource(opts.name, m.source);
  if (!def) {
    io.print(`${shown} is no longer defined in ${safeText(m.source)}. Pass --source to approve a definition from another config.`);
    return 2;
  }
  if (opts.allowUnsandboxed && def.transport === "stdio") io.print(`Running ${shown} directly on this machine (not sandboxed), as you allowed.`);
  io.print(`Listing the tools of ${shown} …`);
  const outcome = await vet(def, { allowUnsandboxed: opts.allowUnsandboxed === true, timeoutMs: opts.timeoutMs, otherManagedTools: otherManagedTools(servers, opts.name) });
  io.print(formatVetReport(outcome.report));
  if (outcome.report.verdict === "incomplete") {
    io.print("Cannot approve: the tool list could not be read.");
    return 2;
  }
  const changes = diffToolHashes(m.toolHashes ?? {}, outcome.toolHashes);
  if (changes.length) {
    io.print("Changes since the last approval:");
    for (const c of changes) io.print(`  ${c.change.padEnd(8)} ${displayName(c.tool)}`);
  } else io.print("No tool changes since the last approval.");
  if (outcome.report.verdict === "high-risk") {
    const typed = await io.ask(`This server is high-risk. Type its name (${shown}) to approve: `);
    if (typed.trim() !== opts.name) {
      io.print("Not approved: the name did not match.");
      return 2;
    }
  } else if (!yes(await io.ask(`Approve these tool definitions for ${shown}? [y/N] `))) {
    io.print("Not approved.");
    return 2;
  }
  const at = now().toISOString();
  updateServers((f) => {
    const cur = managedServer(f, opts.name);
    if (!cur) return;
    cur.toolHashes = outcome.toolHashes;
    cur.approvedAt = at;
    cur.changed = false;
    cur.changes = [];
    cur.vet = { at, verdict: outcome.report.verdict, findings: outcome.report.findings };
    cur.lastDriftCheck = at;
    cur.sandbox = def.sandbox;
    cur.source = def.source;
    cur.transport = def.transport;
  });
  io.print(`Approved ${outcome.tools.length} tool definitions for ${shown}.`);
  try {
    const scope = scopeEntry(loadScopes(), opts.name);
    if (scope?.tools) {
      const allowed = new Set(scope.tools.map(normalizeMcpName));
      const missing = changes.filter((c) => c.change === "added" && !allowed.has(normalizeMcpName(c.tool))).map((c) => displayName(c.tool));
      if (missing.length) io.print(`New tools not in the allowed list for ${shown} in ~/.secor/scopes.yaml: ${missing.join(", ")}. Add them there by hand if you want to allow them.`);
    }
  } catch {
    // scopes.yaml problems are reported by other commands
  }
  return 0;
}

export type { VetOutcome };
