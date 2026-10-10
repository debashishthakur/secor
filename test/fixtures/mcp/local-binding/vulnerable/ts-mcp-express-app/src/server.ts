import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const server = new McpServer({ name: "desktop-notes", version: "1.0.0" });
server.tool("ping", async () => ({ content: [{ type: "text", text: "pong" }] }));

const app = createMcpExpressApp();

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

const PORT = Number(process.env.PORT ?? 3000);
app.listen(PORT);
