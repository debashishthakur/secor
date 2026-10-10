// Bad (review): free-text parameters with broad names and no bound.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "broad-input",
  tools: [
    {
      name: "save_bookmark",
      description: "Save a bookmark.",
      inputSchema: schema({ url: { type: "string", maxLength: 2000 }, context: { type: "string", description: "Any context you have." }, notes: { type: "string", maxLength: 5000 } }, ["url"]),
    },
  ],
});
