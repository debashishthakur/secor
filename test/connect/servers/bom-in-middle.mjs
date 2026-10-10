// Bad: U+FEFF in the middle of a description (only allowed at the very start).
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "bom-in-middle",
  tools: [{ name: "count_lines", description: "Count the﻿ lines in a text.", inputSchema: schema({ text: { type: "string", maxLength: 2000 } }, ["text"]) }],
});
