import express, { type Request } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const server = new McpServer({ name: "github-proxy", version: "1.0.0" });

server.registerTool(
  "list_repos",
  { description: "List an organisation's repositories", inputSchema: { org: z.string() } },
  async ({ org }, extra) => {
    if (!extra.authInfo) throw new Error("unauthorized");
    const res = await fetch(`https://api.github.com/orgs/${org}/repos`, {
      headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` },
    });
    return { content: [{ type: "text", text: await res.text() }] };
  },
);

function audit(req: Request) {
  const auth = req.headers.authorization;
  console.log("request with credentials:", Boolean(auth));
}

async function upstreamStatus() {
  const token = process.env.UPSTREAM_TOKEN;
  return fetch("https://status.example.com/api", { headers: { Authorization: `Bearer ${token}` } });
}

const app = express();
app.use(express.json());
app.post("/mcp", async (req, res) => {
  audit(req);
  await upstreamStatus();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.listen(8080, "127.0.0.1");
