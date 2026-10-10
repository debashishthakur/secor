// Probe run orchestration (spec 9A). Verify the target, obtain consent, send only the non-destructive
// checks, merge the results into a NEW run so they flow into latest.json and the dashboard.

import {
  checkAnonTableRead,
  checkCookieFlags,
  checkCorsReflection,
  checkExposedArtifact,
  checkIdor,
  checkOpenEndpoint,
  checkPrivilegeField,
  checkSecurityHeaders,
  checkTlsRedirect,
  concreteRequestPath,
} from "./checks.js";
import { sortFindings } from "../engine/finding.js";
import { newRunId, readLatest, writeRun } from "../engine/report.js";
import { computeScore } from "../engine/score.js";
import type { Coverage, NotCheckedEntry, RunResult } from "../types.js";
import { loadAccounts, type TestAccounts } from "./accounts.js";
import { appendConsentRecord, type ConsentIO, obtainConsent } from "./consent.js";
import { ProbeClient, type RawResponse } from "./http.js";
import { CONFIRMS, mergeProbeFindings } from "./merge.js";
import { classifyTarget, resolveAndClassify, type Resolver, nodeResolver } from "./scope-guard.js";
import { readSupabaseProject } from "./supabase.js";
import { PROBE_CHECK_IDS, type ProbeCheckId, type ProbeFinding, type VerifiedTarget } from "./types.js";
import { verifyTarget } from "./verify.js";

export class ProbeError extends Error {}

export interface RunProbeOptions {
  projectRoot: string;
  target: string;
  iOwnThisTarget: boolean;
  verifyMethod?: "token" | "dns" | "host-api";
  accountsPath?: string;
  only?: ProbeCheckId[];
  verifyFindingId?: string;
  write?: boolean;
  // Injectables (tests / CLI wiring).
  resolver?: Resolver;
  io: ConsentIO;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  clientOpts?: { maxConcurrency?: number; maxPerSecond?: number; timeoutMs?: number; bodyCapBytes?: number; now?: () => number; sleep?: (ms: number) => Promise<void> };
}

export interface RunProbeResult {
  result: RunResult;
  target: VerifiedTarget;
  probeFindings: ProbeFinding[];
  merged: number;
  added: number;
  requests: { method: string; url: string }[];
  notChecked: NotCheckedEntry[];
}

function dedupeNotChecked(entries: NotCheckedEntry[]): NotCheckedEntry[] {
  const seen = new Set<string>();
  const out: NotCheckedEntry[] = [];
  for (const n of entries) {
    const key = `${n.area}\u0000${n.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(n);
  }
  return out;
}

/** The check that confirms a given finding (for --verify). */
export function checkForFinding(ruleId: string): ProbeCheckId | null {
  if (ruleId.startsWith("probe/")) {
    const id = ruleId.slice("probe/".length) as ProbeCheckId;
    return PROBE_CHECK_IDS.includes(id) ? id : null;
  }
  for (const id of PROBE_CHECK_IDS) if (CONFIRMS[id] === ruleId) return id;
  return null;
}

export async function runProbe(opts: RunProbeOptions): Promise<RunProbeResult> {
  const now = opts.now ?? (() => new Date());
  const resolver = opts.resolver ?? nodeResolver;
  const env = opts.env ?? process.env;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const started = now();

  const latest = readLatest(opts.projectRoot);
  if (!latest) throw new ProbeError("no Ship run found in .secor/latest.json; run `secor ship` first");

  // Which checks to run.
  let selected = new Set<ProbeCheckId>(opts.only && opts.only.length ? opts.only : PROBE_CHECK_IDS);
  if (opts.verifyFindingId) {
    const f = latest.findings.find((x) => x.id === opts.verifyFindingId);
    if (!f) throw new ProbeError(`finding ${opts.verifyFindingId} is not in the latest run`);
    const check = checkForFinding(f.ruleId);
    if (!check) throw new ProbeError(`finding ${opts.verifyFindingId} (${f.ruleId}) has no Probe check to re-run`);
    selected = new Set([check]);
  }

  // Ownership check (may throw ProbeRefusal).
  const target = await verifyTarget(opts.target, {
    ...(opts.verifyMethod ? { method: opts.verifyMethod } : {}),
    resolver,
    env,
    fetchImpl,
    io: opts.io,
    now: () => now().getTime(),
  });

  // Accounts for authenticated checks.
  let accounts: TestAccounts | null = null;
  if (opts.accountsPath) accounts = loadAccounts(opts.accountsPath);

  const notChecked: NotCheckedEntry[] = [];
  const supa = readSupabaseProject(opts.projectRoot);

  // Print exactly what will be sent and require confirmation (may throw ProbeRefusal).
  const plan = buildPlan(selected, target, latest.inventory, accounts, supa.tables.length);
  await obtainConsent(opts.io, { host: target.host, iOwnThisTarget: opts.iOwnThisTarget, plan });

  // Consent log (local only).
  appendConsentRecord(opts.target, target.method, started, env);

  const client = new ProbeClient(target, resolver, opts.clientOpts ?? {});
  const allResponses: RawResponse[] = [];
  const probeFindings: ProbeFinding[] = [];

  // Root GET: feeds security-headers, exposed-artifact (HTML) and cookie-flags.
  let rootRes: RawResponse | null = null;
  if (selected.has("security-headers") || selected.has("exposed-artifact") || selected.has("cookie-flags")) {
    try {
      rootRes = await client.request("GET", "/");
      allResponses.push(rootRes);
    } catch {
      rootRes = null;
    }
  }

  if (selected.has("open-endpoint")) {
    const r = await checkOpenEndpoint(client, latest.inventory);
    probeFindings.push(...r.findings);
    allResponses.push(...r.responses);
  }

  if (selected.has("security-headers")) {
    if (rootRes) probeFindings.push(...checkSecurityHeaders(rootRes));
    else notChecked.push({ area: "Probe: security-headers", reason: "the target root did not respond" });
  }

  if (selected.has("tls-redirect")) {
    if (target.kind === "public") probeFindings.push(...(await checkTlsRedirect(target, resolver)));
    else notChecked.push({ area: "Probe: tls-redirect", reason: "runs on public targets only" });
  }

  if (selected.has("cors-reflection")) {
    const r = await checkCorsReflection(client);
    probeFindings.push(...r.findings);
    allResponses.push(...r.responses);
  }

  if (selected.has("exposed-artifact")) {
    const r = await checkExposedArtifact(client, rootRes?.body ?? "");
    probeFindings.push(...r.findings);
    allResponses.push(...r.responses);
  }

  if (selected.has("anon-table-read")) {
    await runAnonTableRead({ target, supa, resolver, clientOpts: opts.clientOpts, mainClient: client, probeFindings, allResponses, notChecked });
  }

  if (selected.has("idor") || selected.has("privilege-field")) {
    if (!accounts) {
      if (selected.has("idor")) notChecked.push({ area: "Probe: idor", reason: "no --accounts file with two test accounts" });
      if (selected.has("privilege-field")) notChecked.push({ area: "Probe: privilege-field", reason: "no --accounts file with two test accounts" });
    } else {
      if (selected.has("idor")) {
        const r = await checkIdor(client, accounts, latest.inventory);
        probeFindings.push(...r.findings);
        allResponses.push(...r.responses);
      }
      if (selected.has("privilege-field")) {
        const r = await checkPrivilegeField(client, accounts, latest.inventory);
        probeFindings.push(...r.findings);
        allResponses.push(...r.responses);
      }
    }
  }

  if (selected.has("cookie-flags")) {
    probeFindings.push(...checkCookieFlags(allResponses));
  }

  // Merge into the latest findings and write a new run.
  const merge = mergeProbeFindings(latest.findings, probeFindings);
  const findings = sortFindings(merge.findings);
  const coverage: Coverage = {
    applicable: latest.coverage.applicable,
    ran: latest.coverage.ran,
    percent: latest.coverage.percent,
    notChecked: dedupeNotChecked([...latest.coverage.notChecked, ...notChecked]),
  };
  const score = computeScore(findings, latest.units, coverage.percent, latest.score.connect);

  const result: RunResult = {
    runId: newRunId(opts.projectRoot, started),
    startedAt: started.toISOString(),
    finishedAt: now().toISOString(),
    secorVersion: latest.secorVersion,
    rulesVersion: latest.rulesVersion,
    project: latest.project,
    units: latest.units,
    inventory: latest.inventory,
    findings,
    coverage,
    score,
  };

  const written = opts.write === false ? result : writeRun(opts.projectRoot, result);
  return { result: written, target, probeFindings, merged: merge.merged, added: merge.added, requests: client.requests, notChecked };
}

interface AnonArgs {
  target: VerifiedTarget;
  supa: ReturnType<typeof readSupabaseProject>;
  resolver: Resolver;
  clientOpts: RunProbeOptions["clientOpts"];
  mainClient: ProbeClient;
  probeFindings: ProbeFinding[];
  allResponses: RawResponse[];
  notChecked: NotCheckedEntry[];
}

async function runAnonTableRead(a: AnonArgs): Promise<void> {
  if (!a.supa.url || !a.supa.anonKey) {
    a.notChecked.push({ area: "Probe: anon-table-read", reason: "no public Supabase URL and anon key found in the project" });
    return;
  }
  if (a.supa.tables.length === 0) {
    a.notChecked.push({ area: "Probe: anon-table-read", reason: "no public tables found in supabase/migrations" });
    return;
  }
  const notTarget = () => a.notChecked.push({ area: "Probe: anon-table-read", reason: "Supabase project URL is not the authorized target" });

  // Decide which client to use: the main target (same origin) or a separate, same-guard private target.
  let client: ProbeClient;
  try {
    const parsed = classifyTarget(a.supa.url);
    if (parsed.url.origin === a.target.origin) {
      client = a.mainClient;
    } else {
      // A different host: it must itself be loopback/private and pass the same guard, else it is not the target.
      const pin = await resolveAndClassify(parsed.host, a.resolver);
      if (pin.kind !== "private") {
        notTarget();
        return;
      }
      const supaTarget: VerifiedTarget = {
        url: a.supa.url,
        origin: parsed.url.origin,
        host: parsed.host,
        protocol: parsed.url.protocol as "http:" | "https:",
        port: parsed.url.port ? parseInt(parsed.url.port, 10) : parsed.url.protocol === "https:" ? 443 : 80,
        kind: "private",
        method: "local",
        pinnedIp: pin.ip,
        pinnedFamily: pin.family,
      };
      client = new ProbeClient(supaTarget, a.resolver, a.clientOpts ?? {});
    }
  } catch {
    // Refusal (metadata/denylist), DNS failure, or anything else: not a confirmable local target.
    notTarget();
    return;
  }
  const r = await checkAnonTableRead(client, a.supa.tables, a.supa.anonKey);
  a.probeFindings.push(...r.findings);
  a.allResponses.push(...r.responses);
}

function buildPlan(selected: Set<ProbeCheckId>, target: VerifiedTarget, inventory: RunResult["inventory"], accounts: TestAccounts | null, tableCount: number): string[] {
  const lines: string[] = [];
  lines.push(`target: ${target.origin}  (verified: ${target.method}, ${target.kind})`);
  if (selected.has("open-endpoint")) {
    const paths = inventory.filter((e) => e.service === "api" && e.kind === "http_route" && !e.declaredPublic && (e.method === "GET" || e.method === "*" || e.method === undefined)).map((e) => concreteRequestPath(e.path));
    lines.push(`GET ${paths.length} API endpoint(s) with no session (open-endpoint)${paths.length ? `: ${paths.slice(0, 10).join(", ")}${paths.length > 10 ? ", …" : ""}` : ""}`);
  }
  if (selected.has("security-headers") || selected.has("cookie-flags")) lines.push(`GET / (security-headers, cookie-flags)`);
  if (selected.has("tls-redirect") && target.kind === "public") lines.push(`GET http://${target.host}/ (tls-redirect)`);
  if (selected.has("cors-reflection")) lines.push(`GET / and OPTIONS / with Origin: https://secor-probe.example (cors-reflection)`);
  if (selected.has("exposed-artifact")) lines.push(`GET /.env, /.git/HEAD, /.git/config, /config.json, /.ds_store + HTML source maps (exposed-artifact)`);
  if (selected.has("anon-table-read") && tableCount) lines.push(`GET /rest/v1/<table>?select=*&limit=1 for ${tableCount} table(s) with the public anon key (anon-table-read)`);
  if (selected.has("idor") && accounts) lines.push(`GET a collection then an item as two test accounts (idor)`);
  if (selected.has("privilege-field") && accounts) lines.push(`GET admin-gated endpoints as a non-admin test account (privilege-field)`);
  lines.push(`No POST/PUT/PATCH/DELETE requests are ever sent.`);
  return lines;
}

/** verify-target only: run the ownership check and cache it (spec 9A.7). */
export async function verifyTargetOnly(opts: {
  target: string;
  verifyMethod?: "token" | "dns" | "host-api";
  resolver?: Resolver;
  io: ConsentIO;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}): Promise<VerifiedTarget> {
  const now = opts.now ?? (() => new Date());
  return verifyTarget(opts.target, {
    ...(opts.verifyMethod ? { method: opts.verifyMethod } : {}),
    resolver: opts.resolver ?? nodeResolver,
    env: opts.env ?? process.env,
    fetchImpl: opts.fetchImpl ?? fetch,
    io: opts.io,
    now: () => now().getTime(),
  });
}
