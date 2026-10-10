// Confidential (class `confidential`), spec section 9.5.5: text matching the user's
// `confidential.patterns`. Fingerprint flows from `confidential.paths` are handled by the pre-hook.

import type { DetectorMatch } from "./common.js";

export function compileConfidentialPatterns(patterns: readonly string[]): RegExp[] {
  return patterns.map((p) => new RegExp(p, "g"));
}

export function detectConfidential(text: string, patterns: readonly RegExp[]): DetectorMatch[] {
  const found: DetectorMatch[] = [];
  for (const re of patterns) {
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      found.push({ class: "confidential", kind: "pattern", label: "Confidential pattern", start: m.index, end: m.index + m[0].length, value: m[0], valueStart: 0 });
    }
  }
  return found.sort((a, b) => a.start - b.start);
}
