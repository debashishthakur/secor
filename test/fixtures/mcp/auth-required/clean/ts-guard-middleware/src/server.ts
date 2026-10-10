import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { authenticate } from "./auth.js";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("list_notes", async () => ({ content: [{ type: "text", text: "no notes" }] }));

const app = express();
app.use(express.json());

app.post("/mcp", authenticate, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(8080);
