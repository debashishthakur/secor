// The rule catalogue (spec section 8.5): 25 rules in four packs.

import { apiRules } from "./api/index.js";
import { coreRules } from "./core/index.js";
import { mcpRules } from "./mcp/index.js";
import type { Rule } from "./types.js";
import { webRules } from "./web/index.js";

export function allRules(): Rule[] {
  return [...coreRules, ...apiRules, ...mcpRules, ...webRules].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

export function ruleById(id: string): Rule | undefined {
  return allRules().find((r) => r.id === id);
}
