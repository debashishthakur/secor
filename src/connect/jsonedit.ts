// Minimal-change edits of JSON / JSONC editor configs (used by `secor connect add --apply-sandbox`).
// Only the value at one key path is replaced; every other byte of the file (comments, order, spacing) is kept.

export interface Span {
  start: number;
  end: number;
}

class JsoncScanner {
  i = 0;
  found: Span | null = null;
  constructor(
    readonly s: string,
    readonly target: readonly string[],
  ) {}

  fail(msg: string): never {
    throw new Error(`invalid JSON at offset ${this.i}: ${msg}`);
  }

  ws(): void {
    const s = this.s;
    for (;;) {
      const c = s[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "﻿") this.i++;
      else if (c === "/" && s[this.i + 1] === "/") {
        while (this.i < s.length && s[this.i] !== "\n") this.i++;
      } else if (c === "/" && s[this.i + 1] === "*") {
        const end = s.indexOf("*/", this.i + 2);
        if (end < 0) this.fail("unterminated comment");
        this.i = end + 2;
      } else return;
    }
  }

  str(): string {
    const start = this.i;
    if (this.s[this.i] !== '"') this.fail("expected string");
    this.i++;
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === "\\") this.i += 2;
      else if (c === '"') {
        this.i++;
        return JSON.parse(this.s.slice(start, this.i)) as string;
      } else if (c === "\n") this.fail("newline in string");
      else this.i++;
    }
    this.fail("unterminated string");
  }

  value(path: string[], depth: number): void {
    if (depth > 200) this.fail("nesting too deep");
    this.ws();
    const start = this.i;
    const c = this.s[this.i];
    if (c === "{") {
      this.i++;
      this.ws();
      while (this.s[this.i] !== "}") {
        const key = this.str();
        this.ws();
        if (this.s[this.i] !== ":") this.fail("expected ':'");
        this.i++;
        this.value([...path, key], depth + 1);
        this.ws();
        if (this.s[this.i] === ",") {
          this.i++;
          this.ws();
        } else if (this.s[this.i] !== "}") this.fail("expected ',' or '}'");
      }
      this.i++;
    } else if (c === "[") {
      this.i++;
      this.ws();
      let n = 0;
      while (this.s[this.i] !== "]") {
        this.value([...path, String(n++)], depth + 1);
        this.ws();
        if (this.s[this.i] === ",") {
          this.i++;
          this.ws();
        } else if (this.s[this.i] !== "]") this.fail("expected ',' or ']'");
      }
      this.i++;
    } else if (c === '"') {
      this.str();
    } else {
      const m = /^(?:true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(this.s.slice(this.i, this.i + 64));
      if (!m) this.fail("unexpected token");
      this.i += m[0].length;
    }
    // Last occurrence wins, as with JSON.parse and the editors when a key is duplicated.
    if (path.length === this.target.length && path.every((k, idx) => k === this.target[idx])) {
      this.found = { start, end: this.i };
    }
  }
}

/** Span of the value at `path` (object keys; array indexes as strings), or null when absent. Throws on invalid JSONC. */
export function findValueSpan(text: string, path: readonly string[]): Span | null {
  const sc = new JsoncScanner(text, path);
  sc.value([], 0);
  sc.ws();
  if (sc.i < text.length) sc.fail("trailing content");
  return sc.found;
}

function indentUnit(text: string): string {
  const m = /\n([ \t]+)\S/.exec(text);
  if (!m) return "  ";
  const ws = m[1]!;
  return ws.startsWith("\t") ? "\t" : " ".repeat(Math.min(ws.length, 8));
}

/** Replace the value at `path` with `value`, formatted to match the surrounding indentation. */
export function replaceJsonValue(text: string, path: readonly string[], value: unknown): string {
  const span = findValueSpan(text, path);
  if (!span) throw new Error(`key path not found: ${path.join(".")}`);
  const lineStart = text.lastIndexOf("\n", span.start - 1) + 1;
  const baseIndent = /^[ \t]*/.exec(text.slice(lineStart, span.start))![0];
  const body = JSON.stringify(value, null, indentUnit(text))
    .split("\n")
    .map((l, idx) => (idx === 0 ? l : baseIndent + l))
    .join("\n");
  return text.slice(0, span.start) + body + text.slice(span.end);
}
