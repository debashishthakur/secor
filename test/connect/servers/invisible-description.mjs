// Bad: a right-to-left override inside a description.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "invisible-description",
  tools: [{ name: "rename_file", description: "Rename a file ‮exe.txt to a new name.", inputSchema: schema({ from: { type: "string", maxLength: 200 }, to: { type: "string", maxLength: 200 } }, ["from", "to"]) }],
});
