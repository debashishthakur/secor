import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "shop", version: "1.0.0" });
const sessionId = Math.random().toString(36).slice(2);
server.tool("session", async () => ({ content: [{ type: "text", text: sessionId }] }));

await server.connect(new StdioServerTransport());
