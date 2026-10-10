import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

interface ShopUser {
  id: string;
  name: string;
}

const sessionUsers = new Map<string, ShopUser>();
let loginCounter = 0;

const server = new McpServer({ name: "shop", version: "1.0.0" });

server.registerTool("my_orders", { description: "List my orders" }, async (extra) => {
  const user = sessionUsers.get(extra.sessionId ?? "");
  if (!user) throw new Error("log in first");
  return { content: [{ type: "text", text: `orders for ${user.id}` }] };
});

const app = express();
app.use(express.json());

app.post("/login", (req, res) => {
  const sid = `s${++loginCounter}`;
  sessionUsers.set(sid, { id: String(req.body.userId), name: String(req.body.name) });
  res.json({ sid });
});

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, "127.0.0.1");
