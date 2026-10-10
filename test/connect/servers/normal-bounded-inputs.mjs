// Normal: parameters with "broad" names that are bounded (maxLength <= 500, enum, const) or not strings.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "normal-bounded-inputs",
  tools: [
    {
      name: "file_ticket",
      description: "File a support ticket.",
      inputSchema: schema(
        {
          title: { type: "string", maxLength: 120 },
          context: { type: "string", maxLength: 500, description: "Short context for the ticket." },
          notes: { type: "string", enum: ["urgent", "normal", "low"] },
          summary: { type: "string", maxLength: 120 },
          metadata: { type: "object", properties: { team: { type: "string", maxLength: 40 } } },
          details: { anyOf: [{ type: "string", maxLength: 300 }, { type: "null" }] },
          debug: { type: "boolean" },
          memo: { type: "string", const: "n/a" },
        },
        ["title"],
      ),
    },
  ],
});
