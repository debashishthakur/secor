import { randomBytes } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const server = new McpServer({ name: "shop", version: "1.0.0" });
server.tool("ping", async () => ({ content: [{ type: "text", text: "pong" }] }));

function newSessionId(): string {
  return randomBytes(32).toString("hex");
}

const app = express();
app.use(express.json());

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.post("/mcp-stateful", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: newSessionId });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, "127.0.0.1");
