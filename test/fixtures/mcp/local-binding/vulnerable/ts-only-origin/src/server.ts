import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const server = new McpServer({ name: "desktop-notes", version: "1.0.0" });
server.tool("ping", async () => ({ content: [{ type: "text", text: "pong" }] }));

const app = express();
app.use(express.json());

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableDnsRebindingProtection: false,
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, "127.0.0.1");
