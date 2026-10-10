// Bad (low): a description longer than 2000 characters.
import { schema, serve } from "./_lib.mjs";

const sentence = "Returns the opening hours of a library branch, with holiday exceptions listed separately. ";
await serve({
  name: "long-description",
  tools: [{ name: "library_hours", description: sentence.repeat(30), inputSchema: schema({ branch: { type: "string", maxLength: 80 } }, ["branch"]) }],
});
