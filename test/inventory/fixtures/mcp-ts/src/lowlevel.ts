import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const s = new Server({ name: "low", version: "1" }, { capabilities: { tools: {} } });
s.setRequestHandler(CallToolRequestSchema, async (request) => {
  switch (request.params.name) {
    case "add": return { content: [] };
    case "run_query": return { content: [] };
  }
  throw new Error("unknown");
});
