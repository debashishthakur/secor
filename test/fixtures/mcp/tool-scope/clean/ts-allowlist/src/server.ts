import { exec, execFile } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);
const ALLOWED_COMMANDS = ["status", "log", "diff"];

const server = new McpServer({ name: "git-tools", version: "1.0.0" });

server.tool("git", { command: z.string() }, async ({ command }) => {
  if (!ALLOWED_COMMANDS.includes(command)) throw new Error(`command not allowed: ${command}`);
  const { stdout } = await execFileAsync("git", [command]);
  return { content: [{ type: "text", text: stdout }] };
});

server.tool("branches", { scope: z.enum(["local", "remote"]) }, async ({ scope }) => {
  const { stdout } = await execFileAsync("git", scope === "remote" ? ["branch", "-r"] : ["branch"]);
  return { content: [{ type: "text", text: stdout }] };
});

server.tool("status", async () => {
  const { stdout } = await execAsync("git status --short");
  return { content: [{ type: "text", text: stdout }] };
});

await server.connect(new StdioServerTransport());
