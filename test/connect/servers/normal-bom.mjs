// Normal: a description that starts with U+FEFF (a byte-order mark at the start is allowed by vet).
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "normal-bom",
  tools: [{ name: "count_words", description: "﻿Count the words in a short text.", inputSchema: schema({ text: { type: "string", maxLength: 2000 } }, ["text"]) }],
});
