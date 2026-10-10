// mcp pack rules. Each rule lives in its own file in this folder and is listed here.

import type { Rule } from "../types.js";
import { authRequiredRule } from "./auth-required.js";
import { localBindingRule } from "./local-binding.js";
import { sessionHandlingRule } from "./session-handling.js";
import { tokenPassthroughRule } from "./token-passthrough.js";
import { toolScopeRule } from "./tool-scope.js";

export const mcpRules: Rule[] = [authRequiredRule, localBindingRule, sessionHandlingRule, tokenPassthroughRule, toolScopeRule];
