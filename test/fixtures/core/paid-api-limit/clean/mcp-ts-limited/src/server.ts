import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import OpenAI from "openai";
import { z } from "zod";
import { toolLimiter } from "./limits.js";

const openai = new OpenAI();
const server = new McpServer({ name: "summarizer", version: "1.0.0" });

server.tool("summarize", { text: z.string() }, async ({ text }) => {
  await toolLimiter.limit("summarize");
  const r = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: text }] });
  return { content: [{ type: "text", text: r.choices[0]?.message.content ?? "" }] };
});

await server.connect(new StdioServerTransport());
