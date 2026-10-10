import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { z } from "zod";
import { verifier } from "./verifier.js";

const server = new McpServer({ name: "github-proxy", version: "1.0.0" });

server.registerTool(
  "list_repos",
  { description: "List an organisation's repositories", inputSchema: { org: z.string() } },
  async ({ org }, extra) => {
    const res = await fetch(`https://api.github.com/orgs/${org}/repos`, {
      headers: { Authorization: `Bearer ${extra.authInfo?.token}`, Accept: "application/vnd.github+json" },
    });
    return { content: [{ type: "text", text: await res.text() }] };
  },
);

const app = express();
app.use(express.json());
app.post("/mcp", requireBearerAuth({ verifier }), async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.listen(8080, "127.0.0.1");
