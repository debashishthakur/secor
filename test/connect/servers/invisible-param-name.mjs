// Bad: a bidi isolate character inside a parameter name.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "invisible-param-name",
  tools: [{ name: "lookup", description: "Look up a word.", inputSchema: schema({ "word⁦": { type: "string", maxLength: 50 } }) }],
});
