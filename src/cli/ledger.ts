// `secor ledger [--server <name>] [--since <Nd>] [--json]` (spec sections 9.6 and 11.1): totals per server and the
// 20 most recent ask / block / warn entries. The ledger holds metadata only; output is still redacted.

import type { Command } from "commander";
import type { LedgerSummary } from "../connect/ledger.js";
import { CliError, printJson } from "./ui.js";

/** "7d" → 7. */
export function parseSince(v: string): number {
  const m = /^(\d{1,4})d$/.exec(v.trim());
  if (!m || Number(m[1]) < 1) throw new CliError(`--since must be a number of days such as 7d (got "${v}")`);
  return Number(m[1]);
}

export function formatLedgerSummary(s: LedgerSummary): string {
  const lines = [`SECOR ledger · last ${s.sinceDays} day${s.sinceDays === 1 ? "" : "s"}${s.server !== undefined ? ` · server ${s.server}` : ""}`];
  if (s.perServer.length === 0) {
    lines.push("No hook decisions recorded in this period.");
    return lines.join("\n");
  }
  const width = Math.max(8, ...s.perServer.map((p) => (p.server || "(unknown)").length)) + 2;
  const row = (name: string, t: { pass: number; ask: number; block: number; warn: number; error: number }) =>
    `${name.padEnd(width)}${String(t.pass).padStart(6)}${String(t.ask).padStart(6)}${String(t.block).padStart(7)}${String(t.warn).padStart(6)}${String(t.error).padStart(7)}`;
  lines.push(`${"server".padEnd(width)}${"pass".padStart(6)}${"ask".padStart(6)}${"block".padStart(7)}${"warn".padStart(6)}${"error".padStart(7)}`);
  for (const p of s.perServer) lines.push(row(p.server || "(unknown)", p));
  if (s.perServer.length > 1) lines.push(row("total", s.totals));
  lines.push("");
  if (s.recent.length === 0) lines.push("No ask, block or warn decisions in this period.");
  else {
    lines.push(`Most recent ask / block / warn (${s.recent.length}, newest first):`);
    for (const e of s.recent) {
      const reasons = e.reasons.map((r) => r.code).join(", ");
      lines.push(`  ${e.ts.replace("T", " ").replace(/\.\d+Z$/, "Z")}  ${e.decision.padEnd(5)}  ${e.phase.padEnd(4)}  ${e.server || "(unknown)"}.${e.tool}  ${reasons}`);
    }
  }
  return lines.join("\n");
}

export function registerLedgerCommand(program: Command): void {
  program
    .command("ledger")
    .description("show hook decisions: totals per server and the 20 most recent ask, block and warn entries")
    .option("--server <name>", "only this server")
    .option("--since <Nd>", "how many days back (default 7d)", "7d")
    .option("--json", "print the summary as JSON")
    .action(async (o: { server?: string; since: string; json?: boolean }) => {
      const days = parseSince(o.since);
      const [{ ledgerSummary }, { redact, redactDeep }] = await Promise.all([import("../connect/ledger.js"), import("../engine/redact.js")]);
      const summary = ledgerSummary({ ...(o.server !== undefined ? { server: o.server } : {}), sinceDays: days });
      if (o.json) printJson(redactDeep(summary));
      else process.stdout.write(`${redact(formatLedgerSummary(summary))}\n`);
    });
}
