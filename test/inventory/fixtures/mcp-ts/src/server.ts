import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("read_file", { description: "Read a file", inputSchema: { path: z.string() } }, async ({ path }) => ({ content: [{ type: "text", text: path }] }));
server.tool("echo", { text: z.string() }, async (args) => ({ content: [{ type: "text", text: args.text }] }));
server.registerResource("config", "config://app", { description: "cfg" }, async (uri) => ({ contents: [] }));
server.registerPrompt("summarise", { description: "s" }, () => ({ messages: [] }));
const id = Buffer.from("x").toString("base64url");
await server.connect(new StdioServerTransport());
