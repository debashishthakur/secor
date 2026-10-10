// Shared helper for SECOR's demo MCP servers (spec 14.2): a low-level SDK server over stdio that lists exactly the
// raw tool, prompt and resource definitions it is given (no schema rewriting), with optional pagination.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

function page(items, cursor, pageSize, key) {
  if (!pageSize) return { [key]: items };
  const start = cursor ? Number(cursor) : 0;
  const out = { [key]: items.slice(start, start + pageSize) };
  if (start + pageSize < items.length) out.nextCursor = String(start + pageSize);
  return out;
}

/** A plain object-typed input schema. */
export function schema(properties = {}, required = []) {
  return { type: "object", properties, required };
}

export async function serve({ name, tools = [], prompts, resources, pageSize, hangOnList = false }) {
  const capabilities = { tools: {} };
  if (prompts) capabilities.prompts = {};
  if (resources) capabilities.resources = {};
  const server = new Server({ name, version: "1.0.0" }, { capabilities });
  server.setRequestHandler(ListToolsRequestSchema, async (req) => {
    if (hangOnList) return new Promise(() => {});
    return page(tools, req.params?.cursor, pageSize, "tools");
  });
  if (prompts) server.setRequestHandler(ListPromptsRequestSchema, async (req) => page(prompts, req.params?.cursor, pageSize, "prompts"));
  if (resources) server.setRequestHandler(ListResourcesRequestSchema, async (req) => page(resources, req.params?.cursor, pageSize, "resources"));
  server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text", text: "demo" }] }));
  const transport = new StdioServerTransport();
  transport.onclose = () => process.exit(0);
  process.stdin.on("end", () => process.exit(0));
  await server.connect(transport);
}
