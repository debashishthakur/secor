// `secor mcp`: the SECOR MCP server on stdio (spec section 11.2). stdout carries only protocol messages, so any
// console output is sent to stderr. Returns when the client goes away (stdin ends) or on SIGINT / SIGTERM, after
// closing any dashboard this process started.

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { redact } from "../engine/redact.js";
import { createSecorMcp } from "./server.js";

export async function runStdioServer(): Promise<void> {
  const toStderr = (...args: unknown[]): void => console.error(...args);
  console.log = toStderr;
  console.info = toStderr;
  console.debug = toStderr;
  process.on("unhandledRejection", (e) => {
    process.stderr.write(`secor mcp: ${redact(e instanceof Error ? e.message : String(e))}\n`);
  });

  const app = createSecorMcp();
  app.server.server.onerror = (e) => process.stderr.write(`secor mcp: ${redact(e.message)}\n`);
  const stopped = new Promise<void>((done) => {
    process.stdin.once("end", done);
    process.stdin.once("close", done);
    process.once("SIGINT", done);
    process.once("SIGTERM", done);
    app.server.server.onclose = done;
  });
  await app.server.connect(new StdioServerTransport());
  await stopped;
  await app.close();
}
