// Bad (review): an unbounded "metadata" string nested inside an object parameter.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "broad-input-nested",
  tools: [
    {
      name: "log_event",
      description: "Record an analytics event.",
      inputSchema: schema({ event: { type: "string", maxLength: 64 }, extra: { type: "object", properties: { metadata: { type: ["string", "null"] } } } }, ["event"]),
    },
  ],
});
