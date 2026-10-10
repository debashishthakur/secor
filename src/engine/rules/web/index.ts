// web pack rules. Each rule lives in its own file in this folder and is listed here.

import type { Rule } from "../types.js";
import { clientOnlyChecksRule } from "./client-only-checks.js";
import { clientSecretsRule } from "./client-secrets.js";
import { cookieFlagsRule } from "./cookie-flags.js";
import { databaseRulesRule } from "./database-rules.js";
import { productionDebugRule } from "./production-debug.js";
import { securityHeadersRule } from "./security-headers.js";

export const webRules: Rule[] = [clientSecretsRule, databaseRulesRule, clientOnlyChecksRule, cookieFlagsRule, securityHeadersRule, productionDebugRule];
