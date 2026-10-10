import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "status", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "status", description: "Service status", inputSchema: { type: "object", properties: {} } }],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  switch (request.params.name) {
    case "status":
      return { content: [{ type: "text", text: "all systems normal" }] };
    default:
      throw new Error(`unknown tool ${request.params.name}`);
  }
});

const app = express();
const transports: Record<string, SSEServerTransport> = {};

app.get("/sse", async (_req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  transports[transport.sessionId] = transport;
  await server.connect(transport);
});

app.post("/messages", async (req, res) => {
  const transport = transports[String(req.query.sessionId)];
  if (!transport) return res.status(400).send("unknown session");
  await transport.handlePostMessage(req, res);
});

app.listen(3000);
