// Normal: tools, prompts and resources, all plain.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "normal-prompts",
  tools: [{ name: "list_recipes", description: "List recipes that use an ingredient.", inputSchema: schema({ ingredient: { type: "string", maxLength: 80 } }, ["ingredient"]) }],
  prompts: [
    { name: "plan_dinner", description: "Suggest a dinner plan for the week.", arguments: [{ name: "diet", description: "Dietary preference, such as vegetarian.", required: false }] },
  ],
  resources: [{ uri: "recipes://index", name: "recipe_index", description: "Index of all recipes.", mimeType: "text/plain" }],
});
