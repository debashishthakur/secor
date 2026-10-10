import { readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const server = new Server({ name: "files", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "read_file", description: "Read a file", inputSchema: { type: "object", properties: { file: { type: "string" } } } },
    { name: "echo", description: "Echo text", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  switch (request.params.name) {
    case "echo":
      return { content: [{ type: "text", text: String(request.params.arguments?.text ?? "") }] };
    case "read_file": {
      const file = String(request.params.arguments?.file ?? "");
      return { content: [{ type: "text", text: readFileSync(file, "utf8") }] };
    }
    default:
      throw new Error(`unknown tool ${request.params.name}`);
  }
});

await server.connect(new StdioServerTransport());
