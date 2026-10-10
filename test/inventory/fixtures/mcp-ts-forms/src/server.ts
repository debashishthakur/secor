import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "forms", version: "1.0.0" });
server.tool("ping", async (extra) => ({ content: [] }));
server.tool("ping2", "Ping with a description", async (extra) => ({ content: [] }));
server.tool("annotated", { readOnlyHint: true }, async (extra) => ({ content: [] }));
server.tool("read", "Read a note", { path: z.string() }, async ({ path }) => ({ content: [] }));
server.registerTool("status", { description: "status" }, async (extra) => ({ content: [] }));
server.registerTool("fetch", { description: "fetch", inputSchema: { url: z.string() } }, async ({ url }) => ({ content: [] }));
