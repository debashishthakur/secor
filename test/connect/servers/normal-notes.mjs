// Normal: a notes search server with bounded inputs.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "normal-notes",
  tools: [
    {
      name: "search_notes",
      description: "Search the user's notes by keyword and return matching titles.",
      inputSchema: schema({ query: { type: "string", maxLength: 200, description: "Words to look for." }, limit: { type: "integer", minimum: 1, maximum: 50 } }, ["query"]),
    },
    { name: "get_note", description: "Return one note by its id.", inputSchema: schema({ id: { type: "string", maxLength: 64, description: "The note id." } }, ["id"]) },
  ],
});
