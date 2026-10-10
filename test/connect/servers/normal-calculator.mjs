// Normal: arithmetic only.
import { schema, serve } from "./_lib.mjs";

const pair = schema({ a: { type: "number", description: "First operand." }, b: { type: "number", description: "Second operand." } }, ["a", "b"]);
await serve({
  name: "normal-calculator",
  tools: [
    { name: "add", description: "Add two numbers.", inputSchema: pair },
    { name: "multiply", description: "Multiply two numbers.", inputSchema: pair },
  ],
});
