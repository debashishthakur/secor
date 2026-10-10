import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { z } from "zod";
import { verifier } from "./verifier.js";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("list_notes", { folder: z.string() }, async ({ folder }) => ({
  content: [{ type: "text", text: `notes in ${folder}` }],
}));

const app = express();
app.use(express.json());

app.post("/mcp", requireBearerAuth({ verifier, requiredScopes: ["notes:read"] }), async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(8080);
