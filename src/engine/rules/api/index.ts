// api pack rules (spec section 8.5). Each rule lives in its own file in this folder and is listed here.

import type { Rule } from "../types.js";
import { corsCredentials } from "./cors-credentials.js";
import { massAssignment } from "./mass-assignment.js";
import { middlewareOnlyAuth } from "./middleware-only-auth.js";
import { missingAuth } from "./missing-auth.js";
import { missingOwnership } from "./missing-ownership.js";
import { overSharing } from "./over-sharing.js";
import { sqlInjectionRisk } from "./sql-injection-risk.js";
import { unvalidatedInput } from "./unvalidated-input.js";
import { webhookSignature } from "./webhook-signature.js";

export const apiRules: Rule[] = [
  corsCredentials,
  massAssignment,
  middlewareOnlyAuth,
  missingAuth,
  missingOwnership,
  overSharing,
  sqlInjectionRisk,
  unvalidatedInput,
  webhookSignature,
];
