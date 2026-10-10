import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const server = new McpServer({ name: "shop", version: "1.0.0" });
server.tool("ping", async () => ({ content: [{ type: "text", text: "pong" }] }));

const transports: Record<string, StreamableHTTPServerTransport> = {};
const app = express();
app.use(express.json());

app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let transport = sessionId ? transports[sessionId] : undefined;
  if (!transport) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => Math.random().toString(36).slice(2),
      onsessioninitialized: (id) => {
        transports[id] = transport!;
      },
    });
    await server.connect(transport);
  }
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, "127.0.0.1");
