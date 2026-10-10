import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "github-proxy", version: "1.0.0" });

server.registerTool("whoami", { description: "Show the current user" }, async (extra) => {
  const res = await fetch("https://api.github.com/user", { headers: { Authorization: `Bearer ${extra.authInfo?.token}` } });
  return { content: [{ type: "text", text: await res.text() }] };
});

await server.connect(new StdioServerTransport());
