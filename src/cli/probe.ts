// `secor probe` (spec sections 9A.7, 11.1). Opt-in dynamic checks against ONE developer-owned, verified
// staging/local target. This file loads the Probe module only via dynamic import inside the actions, so
// nothing is pulled in unless the human runs `secor probe`. Exit codes: 0 completed, 2 error / refused.

import { createInterface, type Interface } from "node:readline/promises";
import { resolve } from "node:path";
import type { Command } from "commander";
import type { ConsentIO } from "../probe/index.js";
import { redactDeep } from "../engine/redact.js";
import type { RunResult } from "../types.js";
import { CliError, printJson, severityLabel } from "./ui.js";

function makeCliIO(): { io: ConsentIO; close: () => void } {
  const isTTY = !!process.stdin.isTTY && !!process.stdout.isTTY;
  let rl: Interface | null = null;
  const io: ConsentIO = {
    isTTY,
    print: (m: string) => process.stdout.write(`${m}\n`),
    ...(isTTY
      ? {
          question: (prompt: string) => {
            rl ??= createInterface({ input: process.stdin, output: process.stdout });
            return rl.question(prompt);
          },
        }
      : {}),
  };
  return { io, close: () => rl?.close() };
}

function printProbeResult(result: RunResult, info: { merged: number; added: number; requests: number; method: string; notChecked: { area: string; reason: string }[] }): void {
  const probeFindings = result.findings.filter((f) => f.probe);
  const lines: string[] = [];
  lines.push(`Probe sent ${info.requests} request(s) to the verified target (${info.method}).`);
  lines.push(`Confirmed ${info.merged} static finding(s) live; added ${info.added} probe-only finding(s).`);
  if (probeFindings.length) {
    lines.push("");
    lines.push("Probe findings:");
    for (const f of probeFindings) lines.push(`  ${severityLabel(f.severity)}  ${f.title}  ${f.location.file}:${f.location.line}`);
  }
  const probeGaps = info.notChecked.filter((n) => n.area.startsWith("Probe:"));
  if (probeGaps.length) {
    lines.push("");
    lines.push("Not checked:");
    for (const n of probeGaps) lines.push(`  ${n.area.replace(/^Probe: /, "")} — ${n.reason}`);
  }
  lines.push("");
  lines.push("A silent Probe run is not proof of safety; it means these checks found nothing. It says nothing about production.");
  process.stdout.write(`${lines.join("\n")}\n`);
}

function parseOnly(v: string | undefined, valid: readonly string[]): string[] | undefined {
  if (!v) return undefined;
  const list = v.split(",").map((s) => s.trim()).filter(Boolean);
  for (const id of list) if (!valid.includes(id)) throw new CliError(`unknown check "${id}" (choose from: ${valid.join(", ")})`);
  return list;
}

export function registerProbeCommand(program: Command): void {
  const probe = program
    .command("probe")
    .description("opt-in dynamic checks against ONE target you own and have verified (off by default; never run by the model, a hook, the gate or CI)")
    .option("--target <url>", "the staging/local target you own (never production)")
    .option("--i-own-this-target", "confirm you own and authorise this target")
    .option("--verify-method <m>", "ownership proof for a public target: token | dns | host-api")
    .option("--accounts <file>", "JSON file with two test accounts' session headers/cookies (enables idor/privilege-field)")
    .option("--only <checkIds>", "run only these checks (comma-separated)")
    .option("--verify <findingId>", "re-run only this finding's check against the same target")
    .option("--json", "print the RunResult JSON")
    .action(async (o: { target?: string; iOwnThisTarget?: boolean; verifyMethod?: string; accounts?: string; only?: string; verify?: string; json?: boolean }) => {
      const probeMod = await import("../probe/index.js");
      const { runProbe, ProbeError, ProbeRefusal, PROBE_CHECK_IDS } = probeMod;
      if (!o.target) throw new CliError("--target <url> is required");
      if (o.verifyMethod && !["token", "dns", "host-api"].includes(o.verifyMethod)) throw new CliError("--verify-method must be token, dns or host-api");
      const only = parseOnly(o.only, PROBE_CHECK_IDS) as import("../probe/index.js").ProbeCheckId[] | undefined;
      const { io, close } = makeCliIO();
      try {
        const run = await runProbe({
          projectRoot: resolve(process.cwd()),
          target: o.target,
          iOwnThisTarget: !!o.iOwnThisTarget,
          ...(o.verifyMethod ? { verifyMethod: o.verifyMethod as "token" | "dns" | "host-api" } : {}),
          ...(o.accounts ? { accountsPath: resolve(o.accounts) } : {}),
          ...(only ? { only } : {}),
          ...(o.verify ? { verifyFindingId: o.verify } : {}),
          io,
        });
        if (o.json) printJson(redactDeep(run.result));
        else printProbeResult(run.result, { merged: run.merged, added: run.added, requests: run.requests.length, method: run.target.method, notChecked: run.notChecked });
        process.exitCode = 0;
      } catch (e) {
        if (e instanceof ProbeRefusal) throw new CliError(`refused (${e.code}): ${e.message}`, 2);
        if (e instanceof ProbeError) throw new CliError(e.message, 2);
        throw e;
      } finally {
        close();
      }
    });

  probe
    .command("verify-target")
    .description("run the ownership check alone and cache the result")
    .option("--target <url>", "the target to verify")
    .option("--verify-method <m>", "token | dns | host-api")
    .action(async (o: { target?: string; verifyMethod?: string }, cmd: Command) => {
      const probeMod = await import("../probe/index.js");
      const { verifyTargetOnly, ProbeRefusal } = probeMod;
      // `--target` / `--verify-method` are also declared on the parent `probe` command, which consumes
      // them first; fall back to the parent's values so `secor probe verify-target --target <url>` works.
      const parent = cmd.parent?.opts() as { target?: string; verifyMethod?: string } | undefined;
      const target = o.target ?? parent?.target;
      const verifyMethod = o.verifyMethod ?? parent?.verifyMethod;
      if (!target) throw new CliError("--target <url> is required");
      if (verifyMethod && !["token", "dns", "host-api"].includes(verifyMethod)) throw new CliError("--verify-method must be token, dns or host-api");
      const { io, close } = makeCliIO();
      try {
        const target2 = await verifyTargetOnly({
          target,
          ...(verifyMethod ? { verifyMethod: verifyMethod as "token" | "dns" | "host-api" } : {}),
          io,
        });
        process.stdout.write(`Verified ${target2.origin} (${target2.kind}, method: ${target2.method}). Cached for 24h.\n`);
        process.exitCode = 0;
      } catch (e) {
        if (e instanceof ProbeRefusal) throw new CliError(`refused (${e.code}): ${e.message}`, 2);
        throw e;
      } finally {
        close();
      }
    });
}
