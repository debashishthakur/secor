// Per-run consent (spec 9A.2): the interactive gates (ownership assertion, staging warning, printed plan
// + confirmation) and the append-only local consent log. There is no unattended mode.

import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { appendLine } from "../engine/util/fsx.js";
import { secorHome } from "../engine/util/paths.js";
import { RULES_VERSION } from "../types.js";
import { looksLikeStaging } from "./staging.js";
import { ProbeRefusal, type VerifyMethod } from "./types.js";

/** Pluggable terminal I/O so the gates are testable without a real TTY. */
export interface ConsentIO {
  isTTY: boolean;
  print(msg: string): void;
  /** Ask a question and return the typed line. undefined when no prompting is possible (non-TTY). */
  question?(prompt: string): Promise<string>;
}

export interface ConsentInput {
  host: string;
  /** --i-own-this-target was passed. */
  iOwnThisTarget: boolean;
  /** Lines describing exactly what will be sent. */
  plan: string[];
}

/**
 * Enforce the per-run consent gates in order. Throws ProbeRefusal if consent is not given. Because the
 * pre-request confirmation needs a human at a prompt, a non-TTY stdin is always refused.
 */
export async function obtainConsent(io: ConsentIO, input: ConsentInput): Promise<void> {
  const canAsk = io.isTTY && typeof io.question === "function";
  // 1. Ownership assertion: the flag, or typing the exact host.
  if (!input.iOwnThisTarget) {
    if (!canAsk) {
      throw new ProbeRefusal("no-consent", "Probe needs --i-own-this-target or an interactive terminal to confirm ownership; it never runs unattended");
    }
    const typed = (await io.question!(`Type the target host (${input.host}) to confirm you own and authorise it: `)).trim();
    if (typed !== input.host) throw new ProbeRefusal("ownership-not-confirmed", `typed "${typed}" does not match the target host ${input.host}`);
  }
  // 2. Staging warning: extra confirmation when the host does not look like staging.
  if (!looksLikeStaging(input.host)) {
    if (!canAsk) throw new ProbeRefusal("not-staging-unattended", `${input.host} does not look like staging and Probe cannot ask for confirmation without a terminal`);
    io.print(`WARNING: ${input.host} does not look like a staging/preview host. Never run Probe against production.`);
    const ans = (await io.question!(`Type "yes, not production" to continue: `)).trim().toLowerCase();
    if (ans !== "yes, not production") throw new ProbeRefusal("not-staging", "extra confirmation not given for a non-staging host");
  }
  // 3. Print exactly what will be sent and require confirmation before the first request.
  io.print("Probe will send only these non-destructive requests (no POST/PUT/PATCH/DELETE):");
  for (const line of input.plan) io.print(`  ${line}`);
  if (!canAsk) throw new ProbeRefusal("no-confirmation-unattended", "stdin is not a TTY; Probe requires an interactive confirmation before the first request and never runs unattended");
  const go = (await io.question!("Send these requests now? [y/N] ")).trim().toLowerCase();
  if (go !== "y" && go !== "yes") throw new ProbeRefusal("declined", "confirmation not given");
}

/** Operator for the consent log: `git config user.name`, else $USER / $USERNAME, else "unknown". */
export function detectOperator(env: NodeJS.ProcessEnv = process.env): string {
  for (const bin of ["/Library/Developer/CommandLineTools/usr/bin/git", "git"]) {
    try {
      const res = spawnSync(bin, ["config", "user.name"], { encoding: "utf8", timeout: 5000 });
      const name = (res.stdout ?? "").trim();
      if (res.status === 0 && name) return name;
    } catch {
      // try next
    }
  }
  return env.USER || env.USERNAME || "unknown";
}

export interface ConsentRecord {
  target: string;
  method: VerifyMethod;
  timestamp: string;
  operator: string;
  rulesVersion: string;
}

/** Append the per-run authorization record to ~/.secor/probe-runs.jsonl (local consent log, never networked). */
export function appendConsentRecord(target: string, method: VerifyMethod, now: Date = new Date(), env: NodeJS.ProcessEnv = process.env): ConsentRecord {
  const record: ConsentRecord = { target, method, timestamp: now.toISOString(), operator: detectOperator(env), rulesVersion: RULES_VERSION };
  appendLine(join(secorHome(), "probe-runs.jsonl"), JSON.stringify(record), 0o600);
  return record;
}
