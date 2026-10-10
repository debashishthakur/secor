import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";

const anthropic = new Anthropic();
const server = new McpServer({ name: "summarizer", version: "1.0.0" });

server.tool("summarize", { text: z.string() }, async ({ text }) => {
  const msg = await anthropic.messages.create({ model: "claude-x", max_tokens: 500, messages: [{ role: "user", content: text }] });
  return { content: [{ type: "text", text: JSON.stringify(msg.content) }] };
});

await server.connect(new StdioServerTransport());
