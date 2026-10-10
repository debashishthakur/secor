// Making text from MCP servers safe to show (invariant 12): invisible and control characters are escaped as \u{…},
// then the text is redacted, flattened to one line and truncated by evidence().

import { evidence, redact } from "../engine/redact.js";

// Controls (except tab/newline/CR, which evidence() flattens), format characters (zero-width, bidi, tags),
// line/paragraph separators and variation selectors.
const HIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/gu;

export function escapeInvisible(text: string): string {
  return text.replace(HIDDEN, (ch) => {
    if (ch === "\n" || ch === "\r" || ch === "\t") return ch;
    return `\\u{${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}}`;
  });
}

/** Evidence for a vet finding: escaped, redacted, one line, at most 200 characters. */
export function vetEvidence(text: string): string {
  return evidence(escapeInvisible(text));
}

/** A server-provided name (tool, prompt, resource) shown in a non-evidence field or on the terminal. */
export function displayName(name: string, max = 120): string {
  return evidence(escapeInvisible(name), max);
}

/** Any terminal text built from server data: escaped and redacted (multi-line allowed). */
export function safeText(text: string): string {
  return redact(escapeInvisible(text));
}
