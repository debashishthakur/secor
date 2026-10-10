// Vetting (spec section 9.2): act as an MCP client, read the server's tool list (and prompts and resources when
// advertised), and check it for risky patterns. Vetting writes nothing. stdio servers run inside Docker unless a
// human explicitly allowed running them directly; the MCP tool connect_vet never allows that.
//
// Every text taken from the server is data: it appears only in `evidence` fields (escaped, redacted, truncated),
// and incomplete reasons are fixed strings that never quote the server.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport, SseError } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport, type StdioServerParameters } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { detectInstructions } from "../engine/detectors/index.js";
import { canonicalJson, sha256Hex } from "../engine/util/hash.js";
import { SEVERITY_RANK, type Severity, type VetFinding, type VetReport } from "../types.js";
import type { DiscoveredServer } from "./discover.js";
import { dockerAvailable, dockerClientEnv, ensureImage, removeContainer, sandboxPlan, vetContainerName, vetDockerArgs } from "./sandbox.js";
import { loadServers, otherManagedTools as managedToolsExcept } from "./servers.js";
import { displayName, vetEvidence } from "./text.js";

export interface ListedTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface VetOutcome {
  report: VetReport;
  tools: ListedTool[];
  toolHashes: Record<string, string>;
  prompts: unknown[];
  resources: unknown[];
}

export interface Listing {
  tools: ListedTool[];
  prompts: unknown[];
  resources: unknown[];
  sandboxed: boolean;
  incompleteReason?: string;
}

export const VET_TIMEOUT_MS = 30_000;
const MAX_PAGES = 1000;
const MAX_ITEMS = 10_000;

// ---------------------------------------------------------------- listing

class ListError extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

class RedirectError extends Error {}

interface HttpState {
  lastStatus: number;
  authRequired: boolean;
}

const PageSchema = z.looseObject({
  tools: z.unknown().optional(),
  prompts: z.unknown().optional(),
  resources: z.unknown().optional(),
  nextCursor: z.unknown().optional(),
});

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

async function collectPages(client: Client, method: "tools/list" | "prompts/list" | "resources/list", key: "tools" | "prompts" | "resources", signal: AbortSignal, remaining: () => number): Promise<unknown[]> {
  const items: unknown[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const res = await client.request({ method, params: cursor === undefined ? {} : { cursor } }, PageSchema, { signal, timeout: remaining() });
    const arr = res[key];
    if (!Array.isArray(arr)) throw new ListError(`the server sent an invalid response to ${method}`);
    items.push(...(arr as unknown[]));
    if (items.length > MAX_ITEMS) throw new ListError(`the server listed more than ${MAX_ITEMS} items in ${method}`);
    const next = res.nextCursor;
    if (typeof next !== "string" || next === "") return items;
    if (seen.has(next)) throw new ListError(`the server repeated a page cursor in ${method}`);
    seen.add(next);
    cursor = next;
  }
  throw new ListError(`the server returned more than ${MAX_PAGES} pages in ${method}`);
}

/** Tools with a non-empty string name; a non-string description is ignored, the input schema is kept as sent. */
export function toListedTools(raw: unknown[]): ListedTool[] {
  const out: ListedTool[] = [];
  for (const t of raw) {
    if (!isObj(t) || typeof t.name !== "string" || t.name === "") continue;
    const tool: ListedTool = { name: t.name };
    if (typeof t.description === "string") tool.description = t.description;
    if (t.inputSchema !== undefined) tool.inputSchema = t.inputSchema;
    out.push(tool);
  }
  return out;
}

function clientVersion(): string {
  return "1.0.0";
}

function reasonFor(e: unknown, step: string, timedOut: boolean, timeoutMs: number, http: HttpState | null): string {
  if (http?.authRequired) return "auth required";
  if ((e instanceof StreamableHTTPError || e instanceof SseError) && (e.code === 401 || e.code === 403)) return "auth required";
  if (timedOut || (e instanceof McpError && e.code === ErrorCode.RequestTimeout)) return `timed out after ${Math.round(timeoutMs / 1000)} s`;
  if (e instanceof ListError) return e.reason;
  if (e instanceof RedirectError) return "the server redirected to another origin";
  const code = (e as { code?: unknown } | null)?.code;
  if (code === "ENOENT" || code === "EACCES" || code === "EPERM") return "could not start the server command";
  if (e instanceof McpError && e.code === ErrorCode.ConnectionClosed) {
    return step === "initialize" ? "the server exited or closed the connection before it initialized" : `the server closed the connection during ${step}`;
  }
  if (e instanceof McpError) return `the server returned an error to ${step}`;
  if (http && http.lastStatus >= 400) return `the server answered HTTP ${http.lastStatus}`;
  if ((e instanceof StreamableHTTPError || e instanceof SseError) && typeof e.code === "number" && e.code >= 400) return `the server answered HTTP ${e.code}`;
  if (e instanceof TypeError && /fetch failed/i.test(e.message)) return "could not connect to the server URL";
  if (e instanceof z.ZodError || (e as { name?: unknown } | null)?.name === "ZodError") return `the server sent an invalid response to ${step}`;
  return `the server could not be listed (${step} failed)`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms).unref());
}

async function listWith(transport: Transport, sandboxed: boolean, timeoutMs: number, ac: AbortController, http: HttpState | null): Promise<Listing> {
  const client = new Client({ name: "secor-vet", version: clientVersion() }, { capabilities: {} });
  client.onerror = () => {};
  const deadline = Date.now() + timeoutMs;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    ac.abort();
  }, timeoutMs);
  timer.unref();
  const remaining = () => Math.max(1, deadline - Date.now());
  let step = "initialize";
  try {
    await client.connect(transport, { signal: ac.signal, timeout: remaining() });
    step = "tools/list";
    const tools = toListedTools(await collectPages(client, "tools/list", "tools", ac.signal, remaining));
    const caps = client.getServerCapabilities() ?? {};
    let prompts: unknown[] = [];
    let resources: unknown[] = [];
    // Prompts and resources are read when advertised; a failure there does not hide the tool list.
    if (caps.prompts) prompts = await collectPages(client, "prompts/list", "prompts", ac.signal, remaining).catch(() => []);
    if (caps.resources) resources = await collectPages(client, "resources/list", "resources", ac.signal, remaining).catch(() => []);
    return { tools, prompts, resources, sandboxed };
  } catch (e) {
    return { tools: [], prompts: [], resources: [], sandboxed, incompleteReason: reasonFor(e, step, timedOut, timeoutMs, http) };
  } finally {
    clearTimeout(timer);
    await Promise.race([client.close().catch(() => undefined), sleep(6000)]);
  }
}

async function listStdio(params: StdioServerParameters, sandboxed: boolean, timeoutMs: number): Promise<Listing> {
  const transport = new StdioClientTransport({ ...params, stderr: "pipe" });
  // Drain stderr so a chatty server cannot block; its text is never shown.
  transport.stderr?.on("data", () => undefined);
  return listWith(transport, sandboxed, timeoutMs, new AbortController(), null);
}

/** fetch for vetting: records statuses, follows only same-origin redirects, and never sends headers elsewhere. */
function guardedFetch(origin: string, state: HttpState, signal: AbortSignal) {
  return async (input: string | URL, init?: RequestInit): Promise<Response> => {
    let url = new URL(typeof input === "string" ? input : input.href);
    for (let hop = 0; ; hop++) {
      if (url.origin !== origin) throw new RedirectError("cross-origin request");
      const res = await fetch(url, { ...init, redirect: "manual", signal: init?.signal ? AbortSignal.any([init.signal, signal]) : signal });
      state.lastStatus = res.status;
      if (res.status === 401 || res.status === 403) state.authRequired = true;
      const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
      if (!location) return res;
      if (hop >= 5) throw new RedirectError("too many redirects");
      url = new URL(location, url);
    }
  };
}

async function listHttp(server: DiscoveredServer, timeoutMs: number): Promise<Listing> {
  const none = (reason: string): Listing => ({ tools: [], prompts: [], resources: [], sandboxed: false, incompleteReason: reason });
  if (!server.url) return none("no url configured");
  let url: URL;
  try {
    url = new URL(server.url);
  } catch {
    return none("the configured url is not valid");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return none("the configured url is not http or https");
  const state: HttpState = { lastStatus: 0, authRequired: false };
  const ac = new AbortController();
  const fetchFn = guardedFetch(url.origin, state, ac.signal);
  const requestInit: RequestInit = { headers: { ...(server.headers ?? {}) } };
  const transport =
    server.type === "sse"
      ? new SSEClientTransport(url, { requestInit, fetch: fetchFn })
      : new StreamableHTTPClientTransport(url, {
          requestInit,
          fetch: fetchFn,
          reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1000, maxReconnectionDelay: 1000, reconnectionDelayGrowFactor: 1 },
        });
  return listWith(transport, false, timeoutMs, ac, state);
}

/** Read a server's tools, prompts and resources with the mechanics of section 9.2 (shared by vet and drift). */
export async function listServer(server: DiscoveredServer, opts: { allowUnsandboxed?: boolean; timeoutMs?: number } = {}): Promise<Listing> {
  const timeoutMs = opts.timeoutMs ?? VET_TIMEOUT_MS;
  const none = (reason: string, sandboxed = false): Listing => ({ tools: [], prompts: [], resources: [], sandboxed, incompleteReason: reason });
  if (server.transport === "http") return listHttp(server, timeoutMs);
  if (!server.command) return none("no command configured");
  if (opts.allowUnsandboxed) {
    // An explicit human choice (CLI --allow-unsandboxed): run the configured command directly.
    return listStdio({ command: server.command, args: server.args ?? [], env: { ...(server.env ?? {}) }, cwd: process.cwd() }, false, timeoutMs);
  }
  if (!(await dockerAvailable())) return none("Docker is not available; a human can pass --allow-unsandboxed to the CLI to run the server directly");
  const plan = sandboxPlan(server);
  if ("error" in plan) return none(plan.error);
  // Pull before the 30-second clock starts, so a slow first download does not count as a slow server.
  if (!(await ensureImage(plan.image))) return none("could not pull the sandbox image");
  const name = vetContainerName();
  try {
    return await listStdio({ command: "docker", args: vetDockerArgs(name, plan), env: { ...dockerClientEnv(), ...plan.envValues } }, true, timeoutMs);
  } finally {
    await removeContainer(name);
  }
}

// ---------------------------------------------------------------- checks

const BROAD_NAMES = new Set(["context", "notes", "conversation", "history", "summary", "metadata", "extra", "debug", "details", "memo"]);
const POWERFUL_WORDS = ["exec", "shell", "run_command", "terminal", "write_file", "delete", "remove", "send_email", "transfer", "payment"];
const INVISIBLE = /[​-‏‪-‮⁦-⁩]/;
const LONG = 2000;
const MAX_NODES = 100_000;

/** U+200B–U+200F, U+202A–U+202E, U+2066–U+2069 anywhere, or U+FEFF anywhere but the first character. */
export function hasInvisibleCharacters(text: string): boolean {
  return INVISIBLE.test(text) || text.indexOf("﻿", 1) >= 0;
}

/** First offending position, for evidence. */
function invisibleIndex(text: string): number {
  const m = INVISIBLE.exec(text);
  const bom = text.indexOf("﻿", 1);
  if (m && (bom < 0 || m.index < bom)) return m.index;
  return bom;
}

export function isPowerfulTool(tool: ListedTool): boolean {
  const text = `${tool.name}\n${tool.description ?? ""}`.toLowerCase();
  return POWERFUL_WORDS.some((w) => text.includes(w));
}

export function powerfulTools(tools: readonly ListedTool[]): Set<string> {
  return new Set(tools.filter(isPowerfulTool).map((t) => t.name));
}

interface TextItem {
  /** Tool name when the text belongs to a tool. */
  tool?: string;
  /** Human-readable location, e.g. 'parameter "options.mode" description'. */
  where: string;
  field: "name" | "description";
  text: string;
}

/** Every string under a "description" key, and every property name, anywhere in a JSON schema. */
function schemaTexts(schema: unknown, tool: string | undefined, prefix: string): TextItem[] {
  const out: TextItem[] = [];
  let nodes = 0;
  const visit = (node: unknown, path: string[], depth: number) => {
    if (++nodes > MAX_NODES || depth > 64) return;
    if (Array.isArray(node)) {
      for (const v of node) visit(v, path, depth + 1);
      return;
    }
    if (!isObj(node)) return;
    for (const [k, v] of Object.entries(node)) {
      if (k === "description" && typeof v === "string") {
        out.push({ tool, where: path.length ? `${prefix}parameter "${path.join(".")}" description` : `${prefix}input schema description`, field: "description", text: v });
      } else if ((k === "properties" || k === "patternProperties") && isObj(v)) {
        for (const [pname, pschema] of Object.entries(v)) {
          out.push({ tool, where: `${prefix}parameter name "${[...path, pname].join(".")}"`, field: "name", text: pname });
          visit(pschema, [...path, pname], depth + 1);
        }
      } else {
        visit(v, path, depth + 1);
      }
    }
  };
  visit(schema, [], 0);
  return out;
}

function collectTexts(tools: readonly ListedTool[], prompts: readonly unknown[], resources: readonly unknown[]): TextItem[] {
  const out: TextItem[] = [];
  for (const t of tools) {
    out.push({ tool: t.name, where: "tool name", field: "name", text: t.name });
    if (t.description !== undefined) out.push({ tool: t.name, where: "tool description", field: "description", text: t.description });
    out.push(...schemaTexts(t.inputSchema, t.name, ""));
  }
  for (const p of prompts) {
    if (!isObj(p)) continue;
    const name = typeof p.name === "string" ? p.name : "";
    const label = `prompt "${name}"`;
    if (name) out.push({ where: `${label} name`, field: "name", text: name });
    if (typeof p.description === "string") out.push({ where: `${label} description`, field: "description", text: p.description });
    if (Array.isArray(p.arguments)) {
      for (const a of p.arguments) {
        if (!isObj(a)) continue;
        const an = typeof a.name === "string" ? a.name : "";
        if (an) out.push({ where: `${label} argument name`, field: "name", text: an });
        if (typeof a.description === "string") out.push({ where: `${label} argument "${an}" description`, field: "description", text: a.description });
      }
    }
  }
  for (const r of resources) {
    if (!isObj(r)) continue;
    const name = typeof r.name === "string" ? r.name : "";
    const label = `resource "${name}"`;
    if (name) out.push({ where: `${label} name`, field: "name", text: name });
    if (typeof r.description === "string") out.push({ where: `${label} description`, field: "description", text: r.description });
  }
  return out;
}

function isStringSchema(s: unknown, depth = 0): boolean {
  if (!isObj(s) || depth > 8) return false;
  if (s.type === "string") return true;
  if (Array.isArray(s.type) && s.type.includes("string")) return true;
  for (const k of ["anyOf", "oneOf"]) {
    const alts = s[k];
    if (Array.isArray(alts) && alts.some((a) => isStringSchema(a, depth + 1) && !isConstrained(a))) return true;
  }
  return false;
}

/** An enum, a const, or maxLength ≤ 500 bounds a string parameter. */
function isConstrained(s: unknown): boolean {
  if (!isObj(s)) return false;
  if (Array.isArray(s.enum) && s.enum.length > 0) return true;
  if (Object.hasOwn(s, "const")) return true;
  return typeof s.maxLength === "number" && s.maxLength <= 500;
}

/** Properties at any depth of a JSON schema: [dotted path, schema]. */
function schemaProperties(schema: unknown): [string[], unknown][] {
  const out: [string[], unknown][] = [];
  let nodes = 0;
  const visit = (node: unknown, path: string[], depth: number) => {
    if (++nodes > MAX_NODES || depth > 64) return;
    if (Array.isArray(node)) {
      for (const v of node) visit(v, path, depth + 1);
      return;
    }
    if (!isObj(node)) return;
    for (const [k, v] of Object.entries(node)) {
      if (k === "properties" && isObj(v)) {
        for (const [pname, pschema] of Object.entries(v)) {
          out.push([[...path, pname], pschema]);
          visit(pschema, [...path, pname], depth + 1);
        }
      } else if (k !== "description" && k !== "enum" && k !== "const" && k !== "default" && k !== "examples") {
        visit(v, path, depth + 1);
      }
    }
  };
  visit(schema, [], 0);
  return out;
}

function quoteSnippet(text: string, at: number): string {
  const start = Math.max(0, at - 60);
  return `${start > 0 ? "…" : ""}${text.slice(start, at + 80)}`;
}

/** The vet checks of section 9.2 step 4. `otherManaged` maps other managed servers to their tool names. */
export function vetChecks(tools: readonly ListedTool[], prompts: readonly unknown[], resources: readonly unknown[], otherManaged: ReadonlyMap<string, readonly string[]> = new Map()): VetFinding[] {
  const findings: VetFinding[] = [];
  const add = (checkId: string, severity: Severity, tool: string | undefined, ev: string) => {
    const f: VetFinding = { checkId, severity, evidence: vetEvidence(ev) };
    if (tool !== undefined) f.tool = displayName(tool);
    findings.push(f);
  };
  for (const item of collectTexts(tools, prompts, resources)) {
    if (item.field === "description") {
      const matches = detectInstructions(item.text);
      if (matches.length) add("vet/hidden-instructions", "high", item.tool, `${item.where}: ${matches.map((m) => `${m.category} "${m.match}"`).join("; ")}`);
      if ([...item.text].length > LONG) add("vet/long-description", "low", item.tool, `${item.where} is ${[...item.text].length} characters: ${item.text.slice(0, 120)}`);
    }
    if (hasInvisibleCharacters(item.text)) add("vet/invisible-characters", "high", item.tool, `${item.where}: ${quoteSnippet(item.text, invisibleIndex(item.text))}`);
  }
  const owners = new Map<string, string[]>();
  for (const [server, names] of otherManaged) for (const n of names) owners.set(n, [...(owners.get(n) ?? []), server]);
  for (const t of tools) {
    for (const [path, schema] of schemaProperties(t.inputSchema)) {
      const pname = path[path.length - 1]!;
      if (!BROAD_NAMES.has(pname.toLowerCase())) continue;
      if (!isStringSchema(schema) || isConstrained(schema)) continue;
      add("vet/broad-input", "medium", t.name, `string parameter "${path.join(".")}" has no enum and no maxLength ≤ 500`);
    }
    const others = owners.get(t.name);
    if (others?.length) add("vet/name-collision", "medium", t.name, `tool "${t.name}" is also offered by managed server ${others.map((o) => `"${o}"`).join(", ")}`);
    if (isPowerfulTool(t)) {
      const text = `${t.name}\n${t.description ?? ""}`.toLowerCase();
      const words = POWERFUL_WORDS.filter((w) => text.includes(w));
      add("vet/powerful-tool", "low", t.name, `tool "${t.name}" mentions ${words.join(", ")}`);
    }
  }
  return sortVetFindings(dedupe(findings));
}

function dedupe(fs: VetFinding[]): VetFinding[] {
  const seen = new Set<string>();
  return fs.filter((f) => {
    const k = `${f.checkId}\n${f.tool ?? ""}\n${f.evidence}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function sortVetFindings(fs: VetFinding[]): VetFinding[] {
  const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  return [...fs].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || cmp(a.checkId, b.checkId) || cmp(a.tool ?? "", b.tool ?? "") || cmp(a.evidence, b.evidence));
}

/** Section 9.2 step 5. */
export function verdictOf(findings: readonly VetFinding[], incomplete: boolean): VetReport["verdict"] {
  if (incomplete) return "incomplete";
  if (findings.some((f) => f.severity === "high" || f.severity === "critical")) return "high-risk";
  if (findings.some((f) => f.severity === "medium")) return "review";
  return "ok";
}

/** Section 9.2 step 6: "sha256:" + sha256 of canonical JSON of {name, description, inputSchema}. */
export function toolHash(tool: ListedTool): string {
  return `sha256:${sha256Hex(canonicalJson({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema }))}`;
}

export function toolHashesOf(tools: readonly ListedTool[]): Record<string, string> {
  const out = Object.create(null) as Record<string, string>;
  for (const t of [...tools].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) out[t.name] = toolHash(t);
  return out;
}

function defaultOtherManaged(server: string): Map<string, string[]> {
  try {
    return managedToolsExcept(loadServers(), server);
  } catch {
    return new Map();
  }
}

/** Build the report for a listing (shared by vet, drift and approve). */
export function reportFor(server: DiscoveredServer, listing: Listing, otherManaged: ReadonlyMap<string, readonly string[]>): VetOutcome {
  const incomplete = listing.incompleteReason !== undefined;
  const findings = incomplete ? [] : vetChecks(listing.tools, listing.prompts, listing.resources, otherManaged);
  const report: VetReport = {
    server: server.name,
    source: server.source,
    transport: server.transport,
    sandboxed: listing.sandboxed,
    toolCount: listing.tools.length,
    verdict: verdictOf(findings, incomplete),
    findings,
  };
  if (incomplete) report.incompleteReason = listing.incompleteReason;
  return { report, tools: listing.tools, toolHashes: incomplete ? {} : toolHashesOf(listing.tools), prompts: listing.prompts, resources: listing.resources };
}

/** Vet one server (section 9.2). Without allowUnsandboxed a stdio server runs only inside Docker, else "incomplete". */
export async function vetServer(server: DiscoveredServer, opts?: { allowUnsandboxed?: boolean; timeoutMs?: number; otherManagedTools?: Map<string, string[]> }): Promise<VetOutcome> {
  const listing = await listServer(server, { allowUnsandboxed: opts?.allowUnsandboxed === true, timeoutMs: opts?.timeoutMs });
  return reportFor(server, listing, opts?.otherManagedTools ?? defaultOtherManaged(server.name));
}
