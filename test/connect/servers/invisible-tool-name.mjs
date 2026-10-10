// Bad: a zero-width space inside a tool name.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "invisible-tool-name",
  tools: [{ name: "get​weather", description: "Get the weather.", inputSchema: schema({ city: { type: "string", maxLength: 100 } }, ["city"]) }],
});
