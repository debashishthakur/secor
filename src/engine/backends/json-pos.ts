// A small JSON parser that keeps source offsets, for findings and patches that point into JSON files
// (database.rules.json, vercel.json, package.json). Tolerates // and /* */ comments and trailing commas.

export type JsonNode =
  | { kind: "object"; start: number; end: number; props: JsonProp[] }
  | { kind: "array"; start: number; end: number; items: JsonNode[] }
  | { kind: "string"; start: number; end: number; value: string }
  | { kind: "number"; start: number; end: number; value: number }
  | { kind: "boolean"; start: number; end: number; value: boolean }
  | { kind: "null"; start: number; end: number; value: null };

export interface JsonProp {
  key: string;
  keyStart: number;
  value: JsonNode;
}

class JsonError extends Error {}

/** Parse JSON (with comments and trailing commas) keeping offsets. Null when the text is not valid. */
export function parseJsonPos(text: string): JsonNode | null {
  let i = 0;
  const fail = (): never => {
    throw new JsonError(`invalid JSON at ${i}`);
  };
  const skip = () => {
    for (;;) {
      const c = text[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "﻿") i++;
      else if (c === "/" && text[i + 1] === "/") {
        while (i < text.length && text[i] !== "\n") i++;
      } else if (c === "/" && text[i + 1] === "*") {
        const close = text.indexOf("*/", i + 2);
        i = close < 0 ? text.length : close + 2;
      } else return;
    }
  };
  const str = (): string => {
    if (text[i] !== '"') fail();
    i++;
    let out = "";
    for (;;) {
      if (i >= text.length) fail();
      const c = text[i]!;
      if (c === '"') {
        i++;
        return out;
      }
      if (c === "\\") {
        const n = text[i + 1];
        const map: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (n === "u") {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
        if (n === undefined || !(n in map)) fail();
        out += map[n!];
        i += 2;
        continue;
      }
      if (c === "\n") fail();
      out += c;
      i++;
    }
  };
  const value = (depth: number): JsonNode => {
    if (depth > 200) fail();
    skip();
    const start = i;
    const c = text[i];
    if (c === "{") {
      i++;
      const props: JsonProp[] = [];
      skip();
      while (text[i] !== "}") {
        skip();
        const keyStart = i;
        const key = str();
        skip();
        if (text[i] !== ":") fail();
        i++;
        const v = value(depth + 1);
        props.push({ key, keyStart, value: v });
        skip();
        if (text[i] === ",") {
          i++;
          skip();
          continue;
        }
        if (text[i] !== "}") fail();
      }
      i++;
      return { kind: "object", start, end: i, props };
    }
    if (c === "[") {
      i++;
      const items: JsonNode[] = [];
      skip();
      while (text[i] !== "]") {
        items.push(value(depth + 1));
        skip();
        if (text[i] === ",") {
          i++;
          skip();
          continue;
        }
        if (text[i] !== "]") fail();
      }
      i++;
      return { kind: "array", start, end: i, items };
    }
    if (c === '"') {
      const v = str();
      return { kind: "string", start, end: i, value: v };
    }
    if (text.startsWith("true", i)) {
      i += 4;
      return { kind: "boolean", start, end: i, value: true };
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return { kind: "boolean", start, end: i, value: false };
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return { kind: "null", start, end: i, value: null };
    }
    const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i, i + 64));
    if (!m) fail();
    i += m![0].length;
    return { kind: "number", start, end: i, value: Number(m![0]) };
  };
  try {
    const root = value(0);
    skip();
    if (i < text.length) return null;
    return root;
  } catch (e) {
    if (e instanceof JsonError) return null;
    throw e;
  }
}

/** Property of an object node by key (last one wins, like JSON.parse). */
export function jsonProp(node: JsonNode | null | undefined, key: string): JsonProp | null {
  if (!node || node.kind !== "object") return null;
  let found: JsonProp | null = null;
  for (const p of node.props) if (p.key === key) found = p;
  return found;
}

/** 1-based line of a character offset. */
export function lineAt(text: string, offset: number): number {
  let n = 1;
  const end = Math.min(offset, text.length);
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}
