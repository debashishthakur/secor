// `secor mcp` (spec section 11.1): runs the MCP server on stdio. The server module is loaded only for this command.

import type { Command } from "commander";

export function registerMcpCommand(program: Command): void {
  program
    .command("mcp")
    .description("run the MCP server on stdio")
    .action(async () => {
      const { runStdioServer } = await import("../mcp/stdio.js");
      await runStdioServer();
      // The client is gone: do not keep the process alive for a check or drift check nobody will read.
      process.exit(0);
    });
}
