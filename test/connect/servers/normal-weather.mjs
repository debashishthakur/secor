// Normal: weather forecasts with enum-bounded options.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "normal-weather",
  tools: [
    {
      name: "get_forecast",
      description: "Get the weather forecast for a city.",
      inputSchema: schema({ city: { type: "string", maxLength: 100, description: "City name, for example Lisbon." }, days: { type: "integer", enum: [1, 3, 7] } }, ["city"]),
    },
    { name: "get_alerts", description: "List active weather alerts for a region code.", inputSchema: schema({ region: { type: "string", pattern: "^[A-Z]{2}$" } }, ["region"]) },
  ],
});
