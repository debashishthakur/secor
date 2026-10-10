// Connect commands (spec section 11.1): list, add, vet, drift, approve, install-hooks, uninstall-hooks.
// Modules that load the MCP SDK are imported inside the actions, so other commands start fast.
// `add` and `approve` change policy state and are interactive: they refuse to run when stdin is not a terminal,
// because only a human may approve a server (invariant 6).

import type { Command } from "commander";
import { EVIDENCE_NOTICE } from "../types.js";
import type { PromptIO } from "../connect/add.js";
import { CliError, printJson } from "./ui.js";

export const NOT_A_TERMINAL = "run this in a terminal; an AI agent must ask the user";

/** Throw (exit 2) unless stdin is an interactive terminal. */
export function requireTerminal(command: string, stdin: { isTTY?: boolean } = process.stdin): void {
  if (!stdin.isTTY) throw new CliError(`secor connect ${command} is interactive: ${NOT_A_TERMINAL} to run it.`, 2);
}

async function terminalIO(): Promise<PromptIO & { close(): void }> {
  const { createInterface } = await import("node:readline/promises");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return {
    ask: (q: string) => rl.question(q),
    print: (t: string) => {
      process.stdout.write(`${t}\n`);
    },
    close: () => rl.close(),
  };
}

function pad(s: string, n: number): string {
  return s.length >= n ? `${s}  ` : s.padEnd(n + 2);
}

/** `secor connect list` text: discovered servers, managed or not, plus managed servers no longer in any config. */
export async function connectListText(projectRoot: string): Promise<string> {
  const [{ connectPosture }, { loadServers }, { displayName, safeText }, { redact }] = await Promise.all([
    import("../connect/posture.js"),
    import("../connect/servers.js"),
    import("../connect/text.js"),
    import("../engine/redact.js"),
  ]);
  const posture = connectPosture(projectRoot);
  let managed: Record<string, { source: string; transport: string; sandbox: string; vet: { verdict: string } | null; changed: boolean }> = {};
  try {
    managed = loadServers().servers;
  } catch {
    managed = {};
  }
  const rows: string[][] = [["server", "managed", "transport", "sandbox", "vet", "changed", "source"]];
  for (const s of posture.servers) {
    rows.push([displayName(s.name, 40), s.managed ? "managed" : "unmanaged", s.transport, s.sandbox, s.vetVerdict ?? "not vetted", s.changed ? "yes" : "no", safeText(s.source)]);
  }
  const seen = new Set(posture.servers.map((s) => s.name));
  for (const name of Object.keys(managed).sort()) {
    if (seen.has(name)) continue;
    const m = managed[name]!;
    rows.push([displayName(name, 40), "managed", m.transport, m.sandbox, m.vet?.verdict ?? "not vetted", m.changed ? "yes" : "no", `${safeText(m.source)} (not found in editor configs)`]);
  }
  const lines: string[] = [];
  if (rows.length === 1) lines.push("No MCP servers found in editor configs (Claude Code, Cursor, Claude Desktop, VS Code).");
  else {
    const widths = rows[0]!.map((_, i) => Math.min(40, Math.max(...rows.map((r) => r[i]!.length))));
    for (const r of rows) lines.push(r.map((c, i) => (i === r.length - 1 ? c : pad(c, widths[i]!))).join("").trimEnd());
  }
  lines.push("", `Hooks: ${posture.hooks}`);
  if (posture.servers.some((s) => !s.managed)) lines.push("Unmanaged servers can be added by a human with: secor connect add <server>");
  return redact(lines.join("\n"));
}

export function registerConnectCommands(program: Command): void {
  const connect = program.command("connect").description("discover, vet, scope and watch the MCP servers you connect");

  connect
    .command("list")
    .description("list discovered MCP servers: managed or unmanaged, source, transport, sandbox, vet verdict")
    .action(async () => {
      process.stdout.write(`${await connectListText(process.cwd())}\n`);
    });

  connect
    .command("add <name>")
    .description("vet a server, choose its scope and record it as managed (interactive)")
    .option("--source <source>", "which config entry to use when the name is defined in several places")
    .option("--allow-unsandboxed", "run a stdio server directly on this machine to vet it (explicit human choice)")
    .option("--apply-sandbox", "back up the editor config and change this entry to run in Docker")
    .action(async (name: string, o: { source?: string; allowUnsandboxed?: boolean; applySandbox?: boolean }) => {
      requireTerminal("add");
      const { connectAdd } = await import("../connect/add.js");
      const io = await terminalIO();
      try {
        process.exitCode = await connectAdd({ name, source: o.source, allowUnsandboxed: !!o.allowUnsandboxed, applySandbox: !!o.applySandbox, projectRoot: process.cwd() }, io);
      } finally {
        io.close();
      }
    });

  connect
    .command("vet <name>")
    .description("read a server's tool list and check it for risky patterns (writes nothing)")
    .option("--source <source>", "which config entry to use when the name is defined in several places")
    .option("--allow-unsandboxed", "run a stdio server directly on this machine to vet it (explicit human choice)")
    .option("--json", "print the VetReport JSON")
    .action(async (name: string, o: { source?: string; allowUnsandboxed?: boolean; json?: boolean }) => {
      const [{ discoverServers, findServer }, { vetServer }, { formatVetReport }, { redactDeep, redact }, { displayName }] = await Promise.all([
        import("../connect/discover.js"),
        import("../connect/vet.js"),
        import("../connect/add.js"),
        import("../engine/redact.js"),
        import("../connect/text.js"),
      ]);
      const found = findServer(discoverServers(process.cwd()), name, o.source);
      if (!found.server) throw new CliError(found.error ?? "server not found");
      if (o.allowUnsandboxed && found.server.transport === "stdio") process.stderr.write(`Running ${displayName(name)} directly on this machine (not sandboxed), as you allowed.\n`);
      const outcome = await vetServer(found.server, { allowUnsandboxed: !!o.allowUnsandboxed });
      if (o.json) printJson(redactDeep({ ...outcome.report, notice: EVIDENCE_NOTICE }));
      else process.stdout.write(`${redact(formatVetReport(outcome.report))}\n`);
    });

  connect
    .command("drift")
    .description("re-list every managed server's tools and flag added, removed or changed tools")
    .option("--allow-unsandboxed", "run stdio servers directly on this machine (explicit human choice)")
    .action(async (o: { allowUnsandboxed?: boolean }) => {
      const [{ runDrift }, { displayName, safeText }, { redact }] = await Promise.all([import("../connect/drift.js"), import("../connect/text.js"), import("../engine/redact.js")]);
      const results = await runDrift({ allowUnsandboxed: !!o.allowUnsandboxed });
      const lines: string[] = [];
      if (results.length === 0) lines.push("No managed servers. A human adds one with: secor connect add <server>");
      for (const r of results) {
        const name = displayName(r.server, 40);
        if (r.status === "not-found") lines.push(`${name}  not found in its recorded config; not checked`);
        else if (r.status === "incomplete") lines.push(`${name}  not checked: ${safeText(r.incompleteReason ?? "incomplete")}`);
        else {
          const what = r.changes.length ? `changed: ${r.changes.map((c) => `${c.change} ${displayName(c.tool, 60)}`).join(", ")}` : "no changes";
          lines.push(`${name}  ${what} · vet ${r.verdict}${r.awaitingApproval ? ` · awaiting approval: a human runs secor connect approve ${name}` : ""}`);
          for (const f of r.findings) {
            lines.push(`    ${f.severity.padEnd(6)} ${f.checkId}${f.tool !== undefined ? `  tool ${f.tool}` : ""}`);
            lines.push(`           evidence: ${f.evidence}`);
          }
        }
      }
      if (results.some((r) => r.findings.length)) lines.push(EVIDENCE_NOTICE);
      process.stdout.write(`${redact(lines.join("\n"))}\n`);
    });

  connect
    .command("approve <name>")
    .description("re-list a managed server's tools and approve the current definitions (interactive)")
    .option("--source <source>", "approve the definition from this config entry instead of the recorded one")
    .option("--allow-unsandboxed", "run a stdio server directly on this machine to list it (explicit human choice)")
    .action(async (name: string, o: { source?: string; allowUnsandboxed?: boolean }) => {
      requireTerminal("approve");
      const { connectApprove } = await import("../connect/add.js");
      const io = await terminalIO();
      try {
        process.exitCode = await connectApprove({ name, source: o.source, allowUnsandboxed: !!o.allowUnsandboxed, projectRoot: process.cwd() }, io);
      } finally {
        io.close();
      }
    });

  connect
    .command("install-hooks")
    .description("add SECOR's Claude Code hooks to ~/.claude/settings.json (or .claude/settings.json with --scope project)")
    .option("--scope <scope>", "user | project", "user")
    .action(async (o: { scope: string }) => {
      if (o.scope !== "user" && o.scope !== "project") throw new CliError("--scope must be user or project");
      const { installHooks } = await import("../connect/install.js");
      let r;
      try {
        r = installHooks(o.scope, process.cwd());
      } catch (e) {
        throw new CliError((e as Error).message);
      }
      if (!r.changed) process.stdout.write(`SECOR hooks are already installed in ${r.path}.\n`);
      else process.stdout.write(`Installed SECOR hooks in ${r.path}${r.backup ? ` (backup: ${r.backup})` : ""}.\nThe hooks run "secor" from your PATH (npm install -g secor).\n`);
    });

  connect
    .command("uninstall-hooks")
    .description("remove only SECOR's hooks from Claude Code settings files")
    .option("--scope <scope>", "user | project (default: both)")
    .action(async (o: { scope?: string }) => {
      if (o.scope !== undefined && o.scope !== "user" && o.scope !== "project") throw new CliError("--scope must be user or project");
      const { uninstallHooks } = await import("../connect/install.js");
      let results;
      try {
        results = uninstallHooks(process.cwd(), o.scope as "user" | "project" | undefined);
      } catch (e) {
        throw new CliError((e as Error).message);
      }
      const changed = results.filter((r) => r.changed);
      if (!changed.length) process.stdout.write("No SECOR hooks found in Claude Code settings files.\n");
      for (const r of changed) process.stdout.write(`Removed SECOR hooks from ${r.path} (backup: ${r.backup}).\n`);
    });
}
