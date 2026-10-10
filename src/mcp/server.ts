// SECOR MCP server (spec section 11.2): exactly eight tools, and no tool that starts Probe (spec 9A.7).
//
// - Every result is deep-redacted (invariant 4) and returned as structuredContent plus the same JSON as a text block.
// - Results with fields named `evidence` also carry the evidence notice (invariant 12).
// - No tool writes a policy file (invariant 6). Ship runs write .secor/runs, latest.json and history.jsonl;
//   open_dashboard writes ~/.secor/dashboard.json; connect_vet writes nothing.
// - Tool descriptions say what each tool does in one sentence and give the model no instructions.
//
// Project root: ship_check's `path` (relative to the default root) becomes the current project for the tools that
// read results (ship_results, ship_finding, ship_verify), connect_status, connect_vet and open_dashboard. The default
// root is $CLAUDE_PROJECT_DIR, which Claude Code sets for MCP servers, else the working directory.

import { statSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { discoverServers, findServer } from "../connect/discover.js";
import { readLedger } from "../connect/ledger.js";
import { connectPosture } from "../connect/posture.js";
import { closeLocalDashboards, openDashboard } from "../dashboard/launch.js";
import { usableRun } from "../dashboard/summary.js";
import { redact, redactDeep } from "../engine/redact.js";
import { readLatest, readRun } from "../engine/report.js";
import { allRules } from "../engine/rules/index.js";
import { secorVersion } from "../ship/version.js";
import { type RunResult, SEVERITIES, type Severity } from "../types.js";
import { type JobRunOptions, JobStore, type ShipRunner } from "./jobs.js";
import { FINDING_ID_RE, PAGE_SIZE_MAX, RUN_ID_RE, findingResult, resultsPage, summarizeLedger, vetResult } from "./results.js";
import { mergeVerifyCoverage } from "./verify.js";
import { type VetServerFn, loadVetServer, vetSandboxedOnly } from "./vetting.js";

const DAY = 86_400_000;

export const TOOL_NAMES = [
  "ship_check",
  "ship_results",
  "ship_finding",
  "ship_verify",
  "connect_status",
  "connect_vet",
  "ledger_summary",
  "open_dashboard",
] as const;

export interface SecorMcpOptions {
  /** Default project root. Default: $CLAUDE_PROJECT_DIR, else the working directory. */
  root?: string;
  /** Options for every Ship run a tool starts (tests: offline, a mock network, a fixed rule set). */
  ship?: JobRunOptions;
  /** Ship runner (default runShip). */
  runner?: ShipRunner;
  /** Vetting implementation. Default: vetServer from src/connect/vet.ts; null means vetting is unavailable. */
  vetServer?: VetServerFn | null;
  dashboard?: {
    /** Open the browser (default true) or a function that opens the URL. */
    open?: boolean | ((url: string) => void);
    idleMs?: number;
    driftCheck?: false | (() => Promise<void>);
  };
  now?: () => Date;
}

export interface SecorMcp {
  server: McpServer;
  jobs: JobStore;
  /** The project the result tools currently read. */
  currentRoot(): string;
  /** Close dashboards this process started. */
  close(): Promise<void>;
}

/** An error whose message is shown to the caller (after redaction). */
export class ToolError extends Error {}

function ok(value: object): CallToolResult {
  const safe = redactDeep(value) as Record<string, unknown>;
  return { structuredContent: safe, content: [{ type: "text", text: JSON.stringify(safe) }] };
}

function fail(message: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text: redact(message) }] };
}

/** Wrap a tool body: results are redacted, and errors become redacted error results (the SDK would echo them raw). */
function tool<A>(fn: (args: A) => object | Promise<object>): (args: A) => Promise<CallToolResult> {
  return async (args: A) => {
    try {
      return ok(await fn(args));
    } catch (e) {
      if (e instanceof ToolError) return fail(e.message);
      return fail(`SECOR internal error: ${e instanceof Error ? e.message : String(e)}`);
    }
  };
}

const PackEnum = z.enum(["api", "mcp", "web"]);
const SeverityEnum = z.enum(SEVERITIES as [Severity, ...Severity[]]);
const FindingId = z.string().regex(FINDING_ID_RE, "expected a finding ID such as api-missing-auth-3f9a1c2b7d4e");

export function createSecorMcp(opts: SecorMcpOptions = {}): SecorMcp {
  const baseRoot = resolve(opts.root ?? process.env.CLAUDE_PROJECT_DIR ?? process.cwd());
  let current = baseRoot;
  const now = opts.now ?? (() => new Date());
  const jobs = new JobStore(opts.runner, opts.ship ?? {});
  const ruleTitles = (): Map<string, string> => new Map((opts.ship?.rules ?? allRules()).map((r) => [r.id, r.title]));
  const server = new McpServer({ name: "secor", version: secorVersion() });

  /** A run read back from <root>/.secor (the latest one without runId), checked for the fields the tools read. */
  const loadRun = (root: string, runId?: string): RunResult | null => {
    const raw = runId ? readRun(root, runId) : readLatest(root);
    if (raw === null) return null;
    const run = usableRun(raw);
    if (!run) throw new ToolError(`${runId ? `Run ${runId}` : "The latest run"} in ${root}/.secor is not in the expected format.`);
    return run;
  };

  const latestRun = (): RunResult => {
    const run = loadRun(current);
    if (!run) throw new ToolError(`No completed check for ${current} yet; ship_check starts one.`);
    return run;
  };

  server.registerTool(
    "ship_check",
    {
      description: "Starts a SECOR Ship check of a project as a background job and returns its job ID.",
      inputSchema: {
        path: z.string().min(1).max(4096).optional().describe("Project directory, absolute or relative to the project root; default the project root."),
        packs: z.array(PackEnum).min(1).max(3).optional().describe("Packs to run besides core; default from secor.config.yaml."),
      },
    },
    tool(({ path, packs }: { path?: string; packs?: ("api" | "mcp" | "web")[] }) => {
      const root = path ? resolve(baseRoot, path) : baseRoot;
      let isDir = false;
      try {
        isDir = statSync(root).isDirectory();
      } catch {
        isDir = false;
      }
      if (!isDir) throw new ToolError(`Not a directory: ${root}`);
      current = root;
      const job = jobs.start(root, packs ? { opts: { packs: [...new Set(packs)] } } : {});
      return { jobId: job.id, status: "running" };
    }),
  );

  server.registerTool(
    "ship_results",
    {
      description:
        "Returns the status, score summary and one page of open findings for a Ship check job, or for the latest completed check when no job ID is given.",
      inputSchema: {
        jobId: z.string().regex(RUN_ID_RE, "expected a job ID such as 20261010T120000Z").optional().describe("Job ID from ship_check or ship_verify; default the latest completed run."),
        severity: z.array(SeverityEnum).min(1).max(4).optional().describe("Only list findings with these severities."),
        includeAdvisory: z.boolean().optional().describe("Also list advisory findings and findings from experimental rules (default true)."),
        page: z.number().int().min(1).optional().describe("Page number, starting at 1."),
        pageSize: z.number().int().min(1).max(PAGE_SIZE_MAX).optional().describe("Findings per page (default 20, max 50)."),
      },
    },
    tool((a: { jobId?: string; severity?: Severity[]; includeAdvisory?: boolean; page?: number; pageSize?: number }) => {
      const q = { severity: a.severity, includeAdvisory: a.includeAdvisory, page: a.page, pageSize: a.pageSize };
      const notDone = (status: "running" | "failed", error?: string) => ({ status, ...(error ? { error } : {}), page: a.page ?? 1, totalPages: 0 });
      if (a.jobId) {
        const job = jobs.get(a.jobId);
        if (job) {
          if (job.status === "running") return notDone("running");
          if (job.status === "failed") return notDone("failed", job.error ?? "The run failed.");
          const run = loadRun(job.root, job.id);
          if (!run) return notDone("failed", "The result file of this run is missing.");
          return resultsPage(run, q);
        }
        const run = loadRun(current, a.jobId);
        if (!run) throw new ToolError(`Unknown jobId ${a.jobId}: it is not a job of this session and ${current}/.secor/runs has no run with that ID.`);
        return resultsPage(run, q);
      }
      const run = loadRun(current);
      if (run) return resultsPage(run, q);
      if (jobs.runningFor(current)) return notDone("running");
      throw new ToolError(`No completed check for ${current} yet; ship_check starts one.`);
    }),
  );

  server.registerTool(
    "ship_finding",
    {
      description: "Returns one finding from the latest Ship check with its evidence, explanation and proposed fix.",
      inputSchema: { findingId: FindingId.describe("Finding ID from ship_results.") },
    },
    tool(({ findingId }: { findingId: string }) => {
      const run = latestRun();
      const f = run.findings.find((x) => x.id === findingId);
      if (!f) throw new ToolError(`Finding ${findingId} is not in the latest run (${run.runId}).`);
      return findingResult(f);
    }),
  );

  server.registerTool(
    "ship_verify",
    {
      description:
        "Starts a Ship check that re-runs only the rules behind the given findings, carries the other findings over, and records the result as a new run.",
      inputSchema: { findingIds: z.array(FindingId).min(1).max(200).describe("IDs of findings in the latest run.") },
    },
    tool(({ findingIds }: { findingIds: string[] }) => {
      const run = latestRun();
      const byId = new Map(run.findings.map((f) => [f.id, f]));
      const ids = [...new Set(findingIds)];
      const unknown = ids.filter((id) => !byId.has(id));
      if (unknown.length) throw new ToolError(`Not in the latest run (${run.runId}): ${unknown.join(", ")}.`);
      const picked = ids.map((id) => byId.get(id)!);
      const probe = picked.filter((f) => f.probe === true || f.ruleId.startsWith("probe/") || f.source?.name === "probe");
      if (probe.length) {
        throw new ToolError(`Probe findings are verified by the developer with secor probe --verify <findingId>, not by ship_verify: ${probe.map((f) => f.id).join(", ")}.`);
      }
      const titles = ruleTitles();
      const rules = [...new Set(picked.map((f) => f.ruleId))].sort();
      const missing = rules.filter((r) => !titles.has(r));
      if (missing.length) throw new ToolError(`These rules are not in this SECOR version, so their findings cannot be re-checked: ${missing.join(", ")}.`);
      // The plan is read when the job starts, so a verify queued behind other jobs builds on the newest run. All
      // packs are enabled so each re-run rule runs whatever packs that run used; onlyRules limits the run to these
      // rules. Coverage is merged with that run's coverage (see verify.ts).
      const root = current;
      const rerun = rules.map((id) => ({ id, title: titles.get(id)! }));
      const job = jobs.start(root, () => {
        const base = usableRun(readLatest(root)) ?? run;
        return {
          opts: { onlyRules: rules, carryOver: base.findings, packs: ["api", "mcp", "web"] },
          finalize: (verified) => mergeVerifyCoverage(base, verified, rerun),
        };
      });
      return { jobId: job.id, status: "running" };
    }),
  );

  server.registerTool(
    "connect_status",
    { description: "Returns the Claude Code hooks status and the posture of every MCP server found in the editor configs." },
    tool(() => {
      const p = connectPosture(current, now());
      return {
        hooks: p.hooks,
        servers: p.servers.map((s) => ({
          name: s.name,
          source: s.source,
          managed: s.managed,
          transport: s.transport,
          sandbox: s.sandbox,
          vetVerdict: s.vetVerdict,
          changed: s.changed,
          score: s.score,
        })),
      };
    }),
  );

  server.registerTool(
    "connect_vet",
    {
      description:
        "Reads an MCP server's tool list inside a sandbox and returns its vet report, without running the server unsandboxed or changing any SECOR files.",
      inputSchema: {
        server: z.string().min(1).max(200).describe("Server name as configured in the editor config."),
        source: z.string().min(1).max(4096).optional().describe("Config source, needed when the name is defined differently in several places."),
      },
    },
    tool(async ({ server: name, source }: { server: string; source?: string }) => {
      const all = discoverServers(current);
      const found = findServer(all, name, source);
      if (!found.server) {
        const sources = [...new Set(all.filter((s) => s.name === name).map((s) => s.source))];
        if (!source && sources.length > 1) throw new ToolError(`"${name}" is defined differently in several places; pass source as one of: ${sources.join(", ")}.`);
        throw new ToolError(found.error ?? `No MCP server named "${name}" was found in editor configs.`);
      }
      const vet = opts.vetServer !== undefined ? opts.vetServer : await loadVetServer();
      return vetResult(await vetSandboxedOnly(found.server, vet));
    }),
  );

  server.registerTool(
    "ledger_summary",
    {
      description: "Returns decision totals overall and per server, and the most recent ask, block and warn decisions, from the SECOR hook ledger.",
      inputSchema: {
        server: z.string().min(1).max(200).optional().describe("Only entries for this server."),
        sinceDays: z.number().int().min(1).max(90).optional().describe("Days of ledger to include (default 7, max 90)."),
      },
    },
    tool(({ server: name, sinceDays }: { server?: string; sinceDays?: number }) => {
      const entries = readLedger((sinceDays ?? 7) * DAY, now()).filter((e) => !name || e.server === name);
      return summarizeLedger(entries);
    }),
  );

  server.registerTool(
    "open_dashboard",
    { description: "Starts or reuses the local read-only SECOR dashboard for the project and returns its URL." },
    tool(async () => {
      const d = opts.dashboard ?? {};
      const r = await openDashboard({
        root: current,
        open: d.open ?? true,
        ...(d.idleMs !== undefined ? { idleMs: d.idleMs } : {}),
        ...(d.driftCheck !== undefined ? { driftCheck: d.driftCheck } : {}),
      });
      return { url: r.url };
    }),
  );

  return {
    server,
    jobs,
    currentRoot: () => current,
    close: () => closeLocalDashboards(),
  };
}
