// Broken: initializes but never answers tools/list (vet must time out and report "incomplete").
import { serve } from "./_lib.mjs";

await serve({ name: "hang-on-list", tools: [], hangOnList: true });
