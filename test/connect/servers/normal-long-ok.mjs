// Normal: a long description that stays under the 2000-character limit.
import { schema, serve } from "./_lib.mjs";

const sentence = "Converts a quantity between metric and imperial units and reports the rounding used. ";
const description = sentence.repeat(Math.floor(1990 / sentence.length));
await serve({
  name: "normal-long-ok",
  tools: [{ name: "convert_units", description, inputSchema: schema({ value: { type: "number" }, unit: { type: "string", enum: ["kg", "lb", "m", "ft"] } }, ["value", "unit"]) }],
});
