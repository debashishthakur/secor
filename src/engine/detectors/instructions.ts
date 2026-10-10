// Instructions detector (vetting and post-hook), spec section 9.5.4.
// Text is NFKC-normalised and stripped of invisible characters first, and single spaces in the
// spec patterns accept any run of whitespace, so trivial spacing tricks do not evade it.

export type InstructionCategory = "override" | "concealment" | "fake-markup" | "tool-precondition" | "sensitive-file" | "exfil-url";

export const INSTRUCTION_PATTERNS: { category: InstructionCategory; re: RegExp }[] = [
  { category: "override", re: /ignore\s+(?:(?:all|any)\s+)?(?:previous|prior|above)\s+(?:instructions|messages)/i },
  { category: "override", re: /disregard\s+(?:the\s+)?(?:system|previous)/i },
  { category: "concealment", re: /(?:do\s+not|don't|don’t)\s+(?:tell|inform|mention|show)(?:\s+this)?\s+(?:to\s+)?the\s+user/i },
  { category: "fake-markup", re: /<\s*\/?\s*(?:important|system|instructions?)\s*>/i },
  { category: "tool-precondition", re: /before\s+(?:using|calling|running)\s+(?:this|any)\s+tool/i },
  { category: "sensitive-file", re: /(?:read|open|cat|include)[^\n]{0,40}(?:\.ssh|id_rsa|\.env\b|\.aws|credentials|mcp\.json)/i },
  { category: "exfil-url", re: /(?:send|post|upload|forward)[^\n]{0,60}https?:\/\//i },
];

const INVISIBLE = /[​-‏‪-‮⁦-⁩﻿]/g;

export function normaliseForInstructions(text: string): string {
  return text.normalize("NFKC").replace(INVISIBLE, "");
}

export interface InstructionMatch {
  category: InstructionCategory;
  match: string;
}

export function detectInstructions(text: string): InstructionMatch[] {
  const norm = normaliseForInstructions(text);
  const out: InstructionMatch[] = [];
  for (const { category, re } of INSTRUCTION_PATTERNS) {
    const m = re.exec(norm);
    if (m && !out.some((o) => o.category === category)) out.push({ category, match: m[0] });
  }
  return out;
}
