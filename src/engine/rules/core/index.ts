// core pack rules. Each rule lives in its own file in this folder and is listed here.

import type { Rule } from "../types.js";
import { errorLeakage } from "./error-leakage.js";
import { hallucinatedPackage } from "./hallucinated-package.js";
import { paidApiLimit } from "./paid-api-limit.js";
import { secrets } from "./secrets.js";
import { vulnerableDependency } from "./vulnerable-dependency.js";

export const coreRules: Rule[] = [secrets, vulnerableDependency, hallucinatedPackage, errorLeakage, paidApiLimit];
