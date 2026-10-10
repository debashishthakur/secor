// Firebase security rules (spec 8.5, web/database-rules): a tolerant reader for firestore.rules /
// storage.rules (service / match / allow / function) and for Realtime Database database.rules.json.

import { type JsonNode, lineAt, parseJsonPos } from "./json-pos.js";

export interface AllowRule {
  /** Service name, e.g. "cloud.firestore" or "firebase.storage". */
  service: string;
  /** Enclosing match paths, outermost first. */
  paths: string[];
  methods: string[];
  /** Condition text after `if` (comments removed), or null for `allow x;` with no condition. */
  condition: string | null;
  /** Offset and 1-based line of the `allow` keyword. */
  start: number;
  line: number;
  /** Text of the whole allow statement. */
  text: string;
}

export interface RulesFunction {
  name: string;
  params: string[];
  /** The returned expression when the body is a single `return <expr>;`, else null. */
  returns: string | null;
}

export interface ParsedRules {
  allows: AllowRule[];
  functions: Map<string, RulesFunction>;
}

/** Replace comments with spaces (strings kept), so offsets and lines stay the same. */
export function stripRulesComments(src: string): string {
  const out = src.split("");
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      i = j + 1;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") out[i++] = " ";
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const close = src.indexOf("*/", i + 2);
      const end = close < 0 ? src.length : close + 2;
      for (; i < end; i++) if (out[i] !== "\n") out[i] = " ";
      continue;
    }
    i++;
  }
  return out.join("");
}

const WORD = /[A-Za-z_][A-Za-z0-9_]*/y;
const MATCH_PATH = /(?:\/(?:\{[^}\s]*\}|[^/\s{}]+))+\/?|\/(?=\s*\{)/y;

export function parseRulesFile(source: string): ParsedRules {
  const src = stripRulesComments(source);
  const allows: AllowRule[] = [];
  const functions = new Map<string, RulesFunction>();
  let i = 0;
  const n = src.length;
  const ws = () => {
    while (i < n && /\s/.test(src[i]!)) i++;
  };
  const word = (): string | null => {
    WORD.lastIndex = i;
    const m = WORD.exec(src);
    if (!m) return null;
    i += m[0].length;
    return m[0];
  };
  /** Skip a balanced region starting at an opening bracket; returns the index after the closing one. */
  const skipBalanced = (from: number): number => {
    const open = src[from]!;
    const close = open === "{" ? "}" : open === "(" ? ")" : "]";
    let depth = 0;
    let j = from;
    while (j < n) {
      const c = src[j]!;
      if (c === "'" || c === '"') {
        j++;
        while (j < n && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
        j++;
        continue;
      }
      if (c === open) depth++;
      else if (c === close) {
        depth--;
        if (depth === 0) return j + 1;
      }
      j++;
    }
    return n;
  };
  /** Read up to a top-level `;` (consumed) or an unbalanced `}` (not consumed). */
  const until = (): { text: string; end: number } => {
    const start = i;
    let depth = 0;
    while (i < n) {
      const c = src[i]!;
      if (c === "'" || c === '"') {
        i++;
        while (i < n && src[i] !== c && src[i] !== "\n") i += src[i] === "\\" ? 2 : 1;
        i++;
        continue;
      }
      if (c === "(" || c === "[" || c === "{") depth++;
      else if (c === ")" || c === "]") depth--;
      else if (c === "}") {
        if (depth === 0) return { text: src.slice(start, i), end: i };
        depth--;
      } else if (c === ";" && depth === 0) {
        const text = src.slice(start, i);
        i++;
        return { text, end: i - 1 };
      }
      i++;
    }
    return { text: src.slice(start, i), end: i };
  };

  const block = (paths: string[], service: string, depth: number): void => {
    while (i < n) {
      ws();
      if (i >= n) return;
      const c = src[i]!;
      if (c === "}") {
        i++;
        return;
      }
      if (c === "{") {
        i++;
        if (depth < 64) block(paths, service, depth + 1);
        continue;
      }
      const at = i;
      const w = word();
      if (w === null) {
        i++;
        continue;
      }
      if (w === "service") {
        ws();
        const nameStart = i;
        while (i < n && /[A-Za-z0-9_.]/.test(src[i]!)) i++;
        const name = src.slice(nameStart, i);
        ws();
        if (src[i] === "{") {
          i++;
          block([], name, depth + 1);
        }
        continue;
      }
      if (w === "match") {
        ws();
        MATCH_PATH.lastIndex = i;
        const m = MATCH_PATH.exec(src);
        const path = m ? m[0] : "";
        if (m) i += m[0].length;
        ws();
        if (src[i] === "{") {
          i++;
          if (depth < 64) block([...paths, path], service, depth + 1);
        }
        continue;
      }
      if (w === "allow") {
        const methods: string[] = [];
        for (;;) {
          ws();
          const mw = word();
          if (mw === null) break;
          methods.push(mw);
          ws();
          if (src[i] === ",") {
            i++;
            continue;
          }
          break;
        }
        ws();
        let condition: string | null = null;
        if (src[i] === ":") {
          i++;
          ws();
          const save = i;
          if (word() !== "if") i = save;
          condition = until().text.trim();
        } else if (src[i] === ";") {
          i++;
        }
        const text = src.slice(at, i).trim();
        allows.push({ service, paths, methods, condition, start: at, line: lineAt(source, at), text });
        continue;
      }
      if (w === "function") {
        ws();
        const name = word() ?? "";
        ws();
        let params: string[] = [];
        if (src[i] === "(") {
          const end = skipBalanced(i);
          params = src
            .slice(i + 1, end - 1)
            .split(",")
            .map((p) => p.trim())
            .filter(Boolean);
          i = end;
        }
        ws();
        if (src[i] === "{") {
          const end = skipBalanced(i);
          const body = src.slice(i + 1, end - 1).trim();
          const ret = /^return\s+([\s\S]*?);?\s*$/.exec(body);
          functions.set(name, { name, params, returns: ret ? ret[1]!.trim() : null });
          i = end;
        }
        continue;
      }
      if (w === "rules_version") {
        until();
        continue;
      }
      // Anything else (stray expressions): skip to the end of the statement.
      until();
    }
  };
  block([], "", 0);
  return { allows, functions };
}

/** Normalise an expression for literal comparison: no whitespace, no wrapping parentheses. */
export function normaliseCondition(expr: string): string {
  let s = expr.replace(/\s+/g, "");
  for (;;) {
    if (s.startsWith("(") && s.endsWith(")") && balancedInner(s.slice(1, -1))) s = s.slice(1, -1);
    else return s;
  }
}

function balancedInner(s: string): boolean {
  let depth = 0;
  for (const c of s) {
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth < 0) return false;
    }
  }
  return depth === 0;
}

/** Inline a condition that is a single call to a zero-argument function with a one-line `return`. */
export function inlineCondition(cond: string, functions: Map<string, RulesFunction>): string {
  let cur = cond;
  for (let depth = 0; depth < 4; depth++) {
    const m = /^([A-Za-z_]\w*)\(\)$/.exec(normaliseCondition(cur));
    const fn = m ? functions.get(m[1]!) : undefined;
    if (!fn || fn.returns === null || fn.params.length) return cur;
    cur = fn.returns;
  }
  return cur;
}

export type AllowVerdict = { kind: "open"; reason: string } | { kind: "auth-only" } | null;

/** Spec 8.5: critical for `if true`, no condition, or test mode; advisory for `request.auth != null` alone. */
export function classifyAllow(rule: AllowRule, functions: Map<string, RulesFunction>): AllowVerdict {
  if (rule.condition === null || rule.condition === "") return { kind: "open", reason: "no condition" };
  const cond = inlineCondition(rule.condition, functions);
  const norm = normaliseCondition(cond);
  if (norm === "true") return { kind: "open", reason: "condition is always true" };
  if (cond.replace(/\s+/g, "").includes("request.time<timestamp.date(")) return { kind: "open", reason: "test-mode rule with an expiry date" };
  if ((norm === "request.auth!=null" || norm === "null!=request.auth") && hasWildcardDocumentSegment(rule)) return { kind: "auth-only" };
  return null;
}

/** Full match path below the service root (`/databases/{db}/documents` or `/b/{bucket}/o`) has a `{wildcard}` segment. */
export function hasWildcardDocumentSegment(rule: AllowRule): boolean {
  const full = rule.paths.join("").replace(/\/{2,}/g, "/");
  const rest = full.replace(/^\/databases\/\{[^}]*\}\/documents/, "").replace(/^\/b\/\{[^}]*\}\/o/, "");
  return /\/\{[^}]*\}/.test(rest);
}

// ---------------------------------------------------------------- Realtime Database (database.rules.json)

export interface RtdbRule {
  /** Key path, e.g. "rules/users/$uid/.read". */
  path: string;
  key: ".read" | ".write";
  value: boolean | string;
  line: number;
  /** Source text of the `"key": value` pair. */
  text: string;
}

export function parseRtdbRules(source: string): RtdbRule[] | null {
  const root = parseJsonPos(source);
  if (!root) return null;
  const out: RtdbRule[] = [];
  const visit = (node: JsonNode, path: string[], depth: number) => {
    if (node.kind !== "object" || depth > 100) return;
    for (const p of node.props) {
      if ((p.key === ".read" || p.key === ".write") && (p.value.kind === "boolean" || p.value.kind === "string")) {
        out.push({ path: [...path, p.key].join("/"), key: p.key, value: p.value.value, line: lineAt(source, p.keyStart), text: source.slice(p.keyStart, p.value.end) });
      } else visit(p.value, [...path, p.key], depth + 1);
    }
  };
  visit(root, [], 0);
  return out;
}

export type RtdbVerdict = "open" | "auth-only" | null;

export function classifyRtdb(rule: RtdbRule): RtdbVerdict {
  if (rule.value === true) return "open";
  if (typeof rule.value !== "string") return null;
  const norm = normaliseCondition(rule.value);
  if (norm === "true") return "open";
  if (/^(?:auth!==?null|null!==?auth)$/.test(norm)) return "auth-only";
  return null;
}
