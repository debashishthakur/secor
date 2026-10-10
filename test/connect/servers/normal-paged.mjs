// Normal: 25 lookup tools served 10 per page (tests that vetting follows nextCursor).
import { schema, serve } from "./_lib.mjs";

const tools = Array.from({ length: 25 }, (_, i) => ({
  name: `lookup_item_${String(i + 1).padStart(2, "0")}`,
  description: `Look up catalogue item group ${i + 1}.`,
  inputSchema: schema({ sku: { type: "string", maxLength: 32 } }, ["sku"]),
}));
await serve({ name: "normal-paged", tools, pageSize: 10 });
