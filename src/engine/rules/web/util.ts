// Helpers shared by the web pack rules: service attribution, .env files, constant evaluation of
// JS expressions, and text edits for patches.

import { type Dirent, readdirSync } from "node:fs";
import { join } from "node:path";
import type { ServiceKind } from "../../../types.js";
import { args, callee, elements, exprPath, isCall, kids, objectProps, resolveLocal, stringValue, unwrap, walk } from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import { under, type UnitInfo } from "../../detect.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { type LineEdit, unifiedDiff } from "../../patch.js";
import { redact } from "../../redact.js";

// ---------------------------------------------------------------- service attribution

/** "web" unless the file sits only in an api unit (the deepest unit root containing it has no web unit). */
export function serviceFor(ctx: ProjectContext, file: string): Exclude<ServiceKind, "mcp"> {
  let best: string | null = null;
  for (const u of ctx.units) if (under(u.root, file) && (best === null || u.root.length > best.length)) best = u.root;
  if (best === null) return "web";
  const kinds = new Set(ctx.units.filter((u) => u.root === best).map((u) => u.kind));
  if (kinds.has("web")) return "web";
  if (kinds.has("api")) return "api";
  return "web";
}

export function unitRel(unit: UnitInfo, rel: string): string {
  return unit.root ? `${unit.root}/${rel}` : rel;
}

/** First of the candidate project-relative files that is listed. */
export function firstListed(ctx: ProjectContext, candidates: readonly string[]): string | null {
  for (const c of candidates) if (ctx.hasFile(c)) return c;
  return null;
}

/** Unit roots of the given kinds, plus the project root, without duplicates. */
export function rootsOf(ctx: ProjectContext, kinds: readonly ServiceKind[]): string[] {
  const out = new Set<string>([""]);
  for (const u of ctx.units) if (kinds.includes(u.kind)) out.add(u.root);
  return [...out].sort();
}

// ---------------------------------------------------------------- .env files

const ENV_TEMPLATES = /^\.env(?:\..*)?\.(?:example|sample|template|dist|defaults)$|^\.env\.(?:example|sample|template)(?:\..*)?$/i;

/**
 * `.env*` files directly in `dir` (read from disk: they are usually gitignored and so not listed),
 * excluding templates such as `.env.example`. Symlinks are skipped.
 */
export function envFiles(ctx: ProjectContext, dir: string): string[] {
  let entries: Dirent[];
  try {
    entries = readdirSync(join(ctx.root, dir), { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((e) => e.isFile() && !e.isSymbolicLink() && /^\.env(?:\..+)?$/.test(e.name) && !ENV_TEMPLATES.test(e.name))
    .map((e) => (dir ? `${dir}/${e.name}` : e.name))
    .sort();
}

export interface EnvEntry {
  key: string;
  value: string;
  /** Offsets of the whole entry (key through value) in the file. */
  start: number;
  end: number;
  line: number;
  /** Values in single quotes are not expanded by dotenv-expand. */
  quote: "'" | '"' | "`" | null;
}

/** dotenv-style parser: KEY=value, `export KEY=value`, quoted values (double quotes may span lines), # comments. */
export function parseEnv(text: string): EnvEntry[] {
  const out: EnvEntry[] = [];
  const re = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*/gm;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const start = m.index;
    const vStart = m.index + m[0].length;
    const q = text[vStart];
    let value: string;
    let end: number;
    let quote: EnvEntry["quote"] = null;
    if (q === '"' || q === "'" || q === "`") {
      quote = q;
      const close = text.indexOf(q, vStart + 1);
      let lineEnd = text.indexOf("\n", vStart);
      if (lineEnd < 0) lineEnd = text.length;
      // Only double-quoted values may span lines.
      const stop = close < 0 || (q !== '"' && close > lineEnd) ? lineEnd : close;
      value = text.slice(vStart + 1, stop);
      if (q === '"') value = value.replace(/\\n/g, "\n");
      end = Math.min(text.length, stop + 1);
    } else {
      let lineEnd = text.indexOf("\n", vStart);
      if (lineEnd < 0) lineEnd = text.length;
      value = text
        .slice(vStart, lineEnd)
        .replace(/\r$/, "")
        .replace(/\s+#.*$/, "")
        .trim();
      end = lineEnd;
    }
    out.push({ key: m[1]!, value, start, end, line: lineOfOffset(text, start), quote });
    re.lastIndex = Math.max(end, vStart);
  }
  return out;
}

/** Expand `$VAR` / `${VAR}` references (dotenv-expand) using `lookup`. Single-quoted values are literal. */
export function expandEnv(entry: EnvEntry, lookup: (key: string) => string | undefined): string | null {
  if (entry.quote === "'" || !/\$\{?[A-Za-z_]/.test(entry.value)) return null;
  let changed = false;
  const out = entry.value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (whole, a: string | undefined, def: string | undefined, b: string | undefined) => {
    const v = lookup((a ?? b)!);
    if (v === undefined) return def ?? whole;
    changed = true;
    return v;
  });
  return changed ? out : null;
}

export function lineOfOffset(text: string, offset: number): number {
  let n = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

/** Text of the line containing `offset`, with a window around very long (minified) lines. */
export function lineTextAt(text: string, offset: number, window = 80): string {
  const s = text.lastIndexOf("\n", offset - 1) + 1;
  let e = text.indexOf("\n", offset);
  if (e < 0) e = text.length;
  if (e - s <= 2 * window + 40) return text.slice(s, e).trim();
  return text.slice(Math.max(s, offset - window), Math.min(e, offset + window)).trim();
}

// ---------------------------------------------------------------- JS values

/** Follow identifiers to their same-file values (const x = …), unwrapping parentheses and casts. */
export function resolveValue(pf: ParsedFile, node: SyntaxNode | null, depth = 0): SyntaxNode | null {
  let cur = unwrap(node);
  for (let d = depth; cur && d < 6; d++) {
    if (cur.type !== "identifier") return cur;
    const v = resolveLocal(pf, cur.text, cur);
    if (!v || v.id === cur.id) return cur;
    cur = unwrap(v);
  }
  return cur;
}

/**
 * Best-effort constant string value: literals, templates whose substitutions are constants, `+`,
 * identifiers bound to constants, `[…].join(sep)`, and `.trim()` / `.replace(…)` (whitespace collapsed).
 */
export function evalString(pf: ParsedFile, node: SyntaxNode | null, depth = 0): string | null {
  if (depth > 8) return null;
  const n = resolveValue(pf, node);
  if (!n) return null;
  const lit = stringValue(n);
  if (lit !== null) return lit;
  if (n.type === "template_string") {
    let out = "";
    for (const c of n.namedChildren) {
      if (!c) continue;
      if (c.type === "string_fragment" || c.type === "escape_sequence") out += c.text;
      else if (c.type === "template_substitution") {
        const inner = kids(c)[0] ?? null;
        const v = evalString(pf, inner, depth + 1);
        if (v === null) return null;
        out += v;
      }
    }
    return out;
  }
  if (n.type === "binary_expression" && n.childForFieldName("operator")?.text === "+") {
    const l = evalString(pf, n.childForFieldName("left"), depth + 1);
    const r = evalString(pf, n.childForFieldName("right"), depth + 1);
    return l !== null && r !== null ? l + r : null;
  }
  if (isCall(n)) {
    const fn = callee(n);
    if (fn?.type === "member_expression") {
      const method = fn.childForFieldName("property")?.text ?? "";
      const recv = fn.childForFieldName("object");
      if (method === "join") {
        const arr = resolveValue(pf, recv);
        if (arr?.type !== "array") return null;
        const sep = args(n)[0] ? evalString(pf, args(n)[0]!, depth + 1) : ",";
        if (sep === null) return null;
        const parts = elements(arr).map((e) => evalString(pf, e, depth + 1));
        return parts.every((p) => p !== null) ? parts.join(sep) : null;
      }
      if (method === "trim" || method === "replace" || method === "replaceAll" || method === "trimEnd" || method === "trimStart") {
        const v = evalString(pf, recv, depth + 1);
        return v === null ? null : v.replace(/\s+/g, " ").trim();
      }
    }
  }
  return null;
}

/** Literal boolean of a JS node (after resolving identifiers), else null. */
export function evalBoolean(pf: ParsedFile, node: SyntaxNode | null): boolean | null {
  const n = resolveValue(pf, node);
  if (!n) return null;
  if (n.type === "true") return true;
  if (n.type === "false") return false;
  return null;
}

/** Object literal behind a node (directly, or via a same-file constant). */
export function resolveObject(pf: ParsedFile, node: SyntaxNode | null): SyntaxNode | null {
  const n = resolveValue(pf, node);
  return n && n.type === "object" ? n : null;
}

export function hasSpread(obj: SyntaxNode): boolean {
  return kids(obj).some((c) => c.type === "spread_element");
}

/** Python keyword-argument dict splat (`**opts`) or positional splat in a call. */
export function hasPySplat(call: SyntaxNode): boolean {
  return args(call).some((a) => a.type === "dictionary_splat" || a.type === "list_splat");
}

/** Quote character the file uses for strings (first string literal), default double quotes. */
export function quoteStyle(pf: ParsedFile): '"' | "'" {
  let q: '"' | "'" | null = null;
  walk(pf.root, (n) => {
    if (q) return false;
    if (n.type === "string") {
      const c = n.text[0];
      if (c === "'" || c === '"') q = c;
      return false;
    }
    return true;
  });
  return q ?? '"';
}

export function memberPathOf(n: SyntaxNode | null): string {
  return exprPath(unwrap(n));
}

export function propKeys(obj: SyntaxNode): string[] {
  return objectProps(obj).map((p) => p.key);
}

// ---------------------------------------------------------------- text edits

/**
 * Unified diff for a proposed fix. Context lines come from the project, so a diff that redaction would
 * change (a secret or personal data nearby) is retried with less context and dropped if it still would:
 * output paths deep-redact findings (invariant 4), which would corrupt the patch.
 */
export function makePatch(file: string, source: string, edits: LineEdit[]): string | undefined {
  for (const context of [3, 1, 0]) {
    const d = unifiedDiff(file, source, edits, context);
    if (!d) return undefined;
    if (redact(d) === d) return d;
  }
  return undefined;
}

/** One LineEdit replacing source[start, end) with `replacement`, expanded to whole lines. */
export function rangeEdit(source: string, start: number, end: number, replacement: string): LineEdit {
  const lineStart = source.lastIndexOf("\n", start - 1) + 1;
  let lineEnd = source.indexOf("\n", end);
  if (lineEnd < 0) lineEnd = source.length;
  const startLine = lineOfOffset(source, lineStart);
  const endLine = startLine + countNewlines(source.slice(lineStart, lineEnd));
  const newText = source.slice(lineStart, start) + replacement + source.slice(end, lineEnd);
  return { startLine, endLine, newLines: newText.split("\n") };
}

/** Insert whole lines after 1-based line `afterLine`. */
export function insertLines(afterLine: number, lines: string[]): LineEdit {
  return { startLine: afterLine + 1, endLine: afterLine, newLines: lines };
}

function countNewlines(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) n++;
  return n;
}

/** Leading whitespace of the line containing `offset`. */
export function indentAt(source: string, offset: number): string {
  const s = source.lastIndexOf("\n", offset - 1) + 1;
  return /^[ \t]*/.exec(source.slice(s))![0];
}

/** Indentation unit guessed from the file (two spaces, four spaces or a tab). */
export function indentUnit(source: string): string {
  const m = /\n([ \t]+)\S/.exec(source);
  if (!m) return "  ";
  if (m[1]!.startsWith("\t")) return "\t";
  return m[1]!.length >= 4 && m[1]!.length % 4 === 0 ? "    " : "  ";
}

export interface ObjectFlagEdit {
  /** Property to set: key and the source text of the value. */
  key: string;
  value: string;
  /** Existing property node whose value is replaced; null → append the property. */
  existing: SyntaxNode | null;
}

/**
 * New source text for a JS object literal with some properties replaced or appended. Keeps single-line
 * objects on one line; multi-line objects get one property per line with the existing indentation.
 */
export function editObjectText(source: string, obj: SyntaxNode, edits: ObjectFlagEdit[]): string | null {
  // Comments inside the object make the edit ambiguous (a comma could land in a comment).
  if (obj.namedChildren.some((c) => c?.type === "comment")) return null;
  const base = obj.startIndex;
  let text = source.slice(obj.startIndex, obj.endIndex);
  // Replacements, right to left.
  const repl = edits.filter((e) => e.existing).sort((a, b) => b.existing!.startIndex - a.existing!.startIndex);
  for (const e of repl) {
    const valueNode = e.existing!.type === "pair" ? e.existing!.childForFieldName("value") : e.existing!;
    if (!valueNode) continue;
    text = text.slice(0, valueNode.startIndex - base) + e.value + text.slice(valueNode.endIndex - base);
  }
  const add = edits.filter((e) => !e.existing).map((e) => `${e.key}: ${e.value}`);
  if (add.length === 0) return text;
  const inner = text.slice(1, -1);
  const multiline = inner.includes("\n");
  if (!inner.trim()) return `{ ${add.join(", ")} }`;
  if (!multiline) {
    const trimmed = inner.replace(/\s+$/, "");
    const hasTrailingComma = trimmed.endsWith(",");
    const body = hasTrailingComma ? trimmed.slice(0, -1) : trimmed;
    return `{${body}, ${add.join(", ")}${hasTrailingComma ? "," : ""} }`.replace(/^\{(?! )/, "{ ");
  }
  const props = kids(obj);
  const last = props[props.length - 1];
  const propIndent = last ? indentAt(source, last.startIndex) : `${indentAt(source, obj.startIndex)}  `;
  const closeIndent = indentAt(source, obj.endIndex - 1);
  const beforeClose = text.slice(0, text.length - 1).replace(/\s+$/, "");
  const hasTrailingComma = beforeClose.endsWith(",");
  const lines = add.map((a, i) => `${propIndent}${a}${i < add.length - 1 || hasTrailingComma ? "," : ""}`);
  return `${beforeClose}${hasTrailingComma ? "" : ","}\n${lines.join("\n")}\n${closeIndent}}`;
}
