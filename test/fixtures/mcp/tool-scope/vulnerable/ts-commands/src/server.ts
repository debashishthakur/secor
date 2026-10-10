import { exec, execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const server = new McpServer({ name: "git-tools", version: "1.0.0" });

server.tool("git_log", { branch: z.string() }, async ({ branch }) => {
  const { stdout } = await execAsync(`git log --oneline ${branch}`);
  return { content: [{ type: "text", text: stdout }] };
});

server.tool("git_show", { ref: z.string() }, async ({ ref }) => {
  const { stdout } = await execFileAsync("git", ["show", ref]);
  return { content: [{ type: "text", text: stdout }] };
});

server.tool("grep", { pattern: z.string() }, async ({ pattern }) => {
  const child = spawn("grep", ["-r", pattern, "."], { shell: true });
  return { content: [{ type: "text", text: String(child.pid) }] };
});

server.tool("status", async () => {
  const { stdout } = await execAsync("git status --short");
  return { content: [{ type: "text", text: stdout }] };
});

await server.connect(new StdioServerTransport());
