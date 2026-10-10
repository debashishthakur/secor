// `secor mcp` end to end (spec 11.1 / 11.2): the bundled CLI speaks MCP over stdio with nothing else on stdout,
// uses $CLAUDE_PROJECT_DIR as the project, and exits 0 when the client goes away.

import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { beforeAll, describe, expect, it } from "vitest";
import { TOOL_NAMES } from "../../src/mcp/server.js";
import { buildCli } from "../helpers/build-cli.js";
import { fake } from "./synthetic.js";

let cli: string;
let home: string;
let project: string;

beforeAll(async () => {
  cli = await buildCli("mcp-e2e");
  home = mkdtempSync(join(tmpdir(), "secor-mcp-e2e-home-"));
  project = mkdtempSync(join(tmpdir(), "secor-mcp-e2e-proj-"));
  writeFileSync(join(project, "package.json"), JSON.stringify({ name: "e2e" }));
  writeFileSync(join(project, ".mcp.json"), JSON.stringify({ mcpServers: { [`docs-${fake("GITHUB")}`]: { command: "definitely-not-installed", args: [] }, secor: { command: "secor", args: ["mcp"] } } }));
}, 120_000);

function env(): Record<string, string> {
  return { PATH: process.env.PATH ?? "", HOME: home, SECOR_HOME: join(home, ".secor"), CLAUDE_PROJECT_DIR: project };
}

describe("secor mcp", () => {
  it("serves the eight tools over stdio and redacts results", async () => {
    const transport = new StdioClientTransport({ command: process.execPath, args: [cli, "mcp"], cwd: tmpdir(), env: env(), stderr: "pipe" });
    const client = new Client({ name: "secor-e2e", version: "1.0.0" });
    await client.connect(transport);
    try {
      expect(client.getServerVersion()?.name).toBe("secor");
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort());
      const status = await client.callTool({ name: "connect_status", arguments: {} });
      expect(status.isError).toBeFalsy();
      const servers = (status.structuredContent as { servers: { name: string }[] }).servers;
      // The project comes from CLAUDE_PROJECT_DIR (cwd is elsewhere); SECOR's own entry is not listed.
      expect(servers).toHaveLength(1);
      expect(servers[0]?.name).toBe(`docs-ghp_…${fake("GITHUB").slice(-4)}`);
      expect(JSON.stringify(status)).not.toContain(fake("GITHUB"));
    } finally {
      await client.close();
    }
  });

  it("writes nothing to stdout on its own and exits 0 when stdin closes", async () => {
    const child = spawn(process.execPath, [cli, "mcp"], { cwd: project, env: env(), stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
    await new Promise((r) => setTimeout(r, 300));
    child.stdin.end();
    expect(await exited).toBe(0);
    expect(out).toBe("");
  });
});
