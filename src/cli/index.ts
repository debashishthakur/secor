// SECOR CLI entry (spec section 11.1). Each command group lives in its own file and is imported on demand,
// so `secor hook ...` (run on every MCP tool call) loads only what it needs.

import { resolve } from "node:path";

async function main(argv: string[]): Promise<number> {
  // Fast path for hooks: no commander, no engine. Always exits 0 (spec 9.4).
  if (argv[2] === "hook") {
    const { runHookCommand } = await import("./hook.js");
    return runHookCommand(argv[3] ?? "");
  }

  const { Command, CommanderError } = await import("commander");
  const { secorVersion } = await import("../ship/version.js");
  const { CliError } = await import("./ui.js");

  const program = new Command("secor")
    .description("Security Context Orchestrator: checks what you ship, guards what you connect.")
    .version(secorVersion(), "--version")
    .option("--cwd <dir>", "run as if started in <dir>")
    .showHelpAfterError()
    .exitOverride();

  program.hook("preAction", (cmd) => {
    const cwd = cmd.optsWithGlobals().cwd as string | undefined;
    if (cwd) process.chdir(resolve(cwd));
  });

  const { registerShipCommands } = await import("./ship.js");
  const { registerConnectCommands } = await import("./connect.js");
  const { registerOtherCommands } = await import("./other.js");
  registerShipCommands(program);
  registerConnectCommands(program);
  registerOtherCommands(program);

  try {
    await program.parseAsync(argv);
    return typeof process.exitCode === "number" ? process.exitCode : 0;
  } catch (e) {
    if (e instanceof CommanderError) {
      if (e.code === "commander.helpDisplayed" || e.code === "commander.version" || e.code === "commander.help") return 0;
      return 2;
    }
    if (e instanceof CliError) {
      process.stderr.write(`secor: ${e.message}\n`);
      return e.exitCode;
    }
    const { redact } = await import("../engine/redact.js");
    process.stderr.write(`secor: ${redact(e instanceof Error ? e.message : String(e))}\n`);
    if (process.env.SECOR_DEBUG && e instanceof Error) process.stderr.write(`${redact(e.stack ?? "")}\n`);
    return 2;
  }
}

main(process.argv).then(
  (code) => {
    process.exitCode = code;
  },
  () => {
    process.exitCode = 2;
  },
);
