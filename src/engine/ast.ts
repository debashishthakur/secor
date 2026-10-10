// Language-aware helpers over tree-sitter syntax trees (JavaScript/TypeScript/TSX and Python).
// Adapters and rules use these instead of touching node types directly where they can.

import { type ParsedFile, type SyntaxNode, isJsLang, memo } from "./parse.js";

// ---------------------------------------------------------------- basics

export function line(n: SyntaxNode): number {
  return n.startPosition.row + 1;
}

export function endLine(n: SyntaxNode): number {
  return n.endPosition.row + 1;
}

export function collapse(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

export function same(a: SyntaxNode | null | undefined, b: SyntaxNode | null | undefined): boolean {
  return !!a && !!b && a.id === b.id;
}

/** Named children without comments. */
export function kids(n: SyntaxNode): SyntaxNode[] {
  return n.namedChildren.filter((c): c is SyntaxNode => !!c && c.type !== "comment");
}

/** Pre-order walk. Return false from `visit` to skip a node's children. Iterative (deep trees are fine). */
export function walk(root: SyntaxNode, visit: (n: SyntaxNode) => boolean | void): void {
  const stack: SyntaxNode[] = [root];
  while (stack.length) {
    const n = stack.pop()!;
    if (visit(n) === false) continue;
    const children = n.namedChildren;
    for (let i = children.length - 1; i >= 0; i--) {
      const c = children[i];
      if (c) stack.push(c);
    }
  }
}

export function descendants(root: SyntaxNode, types: string | string[]): SyntaxNode[] {
  return root.descendantsOfType(types).filter((n): n is SyntaxNode => !!n);
}

export function closest(n: SyntaxNode, types: string | readonly string[]): SyntaxNode | null {
  const set = typeof types === "string" ? [types] : types;
  for (let p = n.parent; p; p = p.parent) if (set.includes(p.type)) return p;
  return null;
}

export function isInside(n: SyntaxNode, container: SyntaxNode): boolean {
  return n.startIndex >= container.startIndex && n.endIndex <= container.endIndex;
}

/** Strip wrappers that do not change the value: parentheses, await, TS `as`/`satisfies`/`!`. */
export function unwrap(n: SyntaxNode | null): SyntaxNode | null {
  let cur = n;
  while (cur) {
    if (["parenthesized_expression", "await_expression", "as_expression", "satisfies_expression", "non_null_expression", "await", "type_assertion"].includes(cur.type)) {
      cur = kids(cur)[0] ?? null;
      continue;
    }
    break;
  }
  return cur;
}

// ---------------------------------------------------------------- functions

export const JS_FUNCTION_TYPES = ["arrow_function", "function_declaration", "function_expression", "generator_function_declaration", "generator_function", "method_definition", "function"];
export const PY_FUNCTION_TYPES = ["function_definition", "lambda"];
const FUNCTION_TYPES = [...JS_FUNCTION_TYPES, ...PY_FUNCTION_TYPES];

export function isFunction(n: SyntaxNode | null): boolean {
  return !!n && FUNCTION_TYPES.includes(n.type);
}

export function enclosingFunction(n: SyntaxNode): SyntaxNode | null {
  return closest(n, FUNCTION_TYPES);
}

export function functionBody(fn: SyntaxNode): SyntaxNode | null {
  return fn.childForFieldName("body");
}

export function functionName(fn: SyntaxNode): string | null {
  const name = fn.childForFieldName("name");
  if (name) return name.text;
  const parent = fn.parent;
  if (parent?.type === "variable_declarator") return parent.childForFieldName("name")?.text ?? null;
  if (parent?.type === "pair") return parent.childForFieldName("key")?.text.replace(/^["']|["']$/g, "") ?? null;
  if (parent?.type === "assignment_expression") return parent.childForFieldName("left")?.text ?? null;
  return null;
}

export function isAsyncFunction(fn: SyntaxNode): boolean {
  for (const c of fn.children) {
    if (!c) continue;
    if (c.type === "async") return true;
    if (c.type === "(" || c.type === "{" || c.type === "parameters" || c.type === "formal_parameters") break;
  }
  return /^async\b/.test(fn.text);
}

/** Parameter nodes of a function (JS formal_parameters children, or the single `parameter`; Python parameters). */
export function params(fn: SyntaxNode): SyntaxNode[] {
  const single = fn.childForFieldName("parameter");
  if (single) return [single];
  const ps = fn.childForFieldName("parameters");
  return ps ? kids(ps) : [];
}

/** The binding pattern of a parameter (strips TS types, defaults, Python annotations). */
export function paramPattern(p: SyntaxNode): SyntaxNode {
  if (p.type === "required_parameter" || p.type === "optional_parameter") return p.childForFieldName("pattern") ?? p;
  if (p.type === "assignment_pattern") return p.childForFieldName("left") ?? p;
  if (p.type === "typed_parameter") return kids(p)[0] ?? p;
  if (p.type === "default_parameter" || p.type === "typed_default_parameter") return p.childForFieldName("name") ?? p;
  if (p.type === "list_splat_pattern" || p.type === "dictionary_splat_pattern" || p.type === "rest_pattern") return kids(p)[0] ?? p;
  return p;
}

/** All identifiers bound by a pattern (destructuring included). */
export function boundNames(pattern: SyntaxNode): string[] {
  const out: string[] = [];
  const visit = (n: SyntaxNode) => {
    switch (n.type) {
      case "identifier":
      case "shorthand_property_identifier_pattern":
        out.push(n.text);
        return;
      case "pair_pattern": {
        const v = n.childForFieldName("value");
        if (v) visit(v);
        return;
      }
      case "assignment_pattern":
      case "object_assignment_pattern": {
        const l = n.childForFieldName("left");
        if (l) visit(l);
        return;
      }
      default:
        for (const c of kids(n)) visit(c);
    }
  };
  visit(paramPattern(pattern));
  return out;
}

export function paramNames(fn: SyntaxNode): string[] {
  return params(fn).flatMap((p) => boundNames(p));
}

/** Python parameter: name, annotation node and default node. */
export function pyParam(p: SyntaxNode): { name: string; type: SyntaxNode | null; default: SyntaxNode | null } | null {
  switch (p.type) {
    case "identifier":
      return { name: p.text, type: null, default: null };
    case "typed_parameter":
      return { name: kids(p)[0]?.text ?? "", type: p.childForFieldName("type"), default: null };
    case "default_parameter":
      return { name: p.childForFieldName("name")?.text ?? "", type: null, default: p.childForFieldName("value") };
    case "typed_default_parameter":
      return { name: p.childForFieldName("name")?.text ?? "", type: p.childForFieldName("type"), default: p.childForFieldName("value") };
    default:
      return null;
  }
}

// ---------------------------------------------------------------- calls

export function isCall(n: SyntaxNode | null): boolean {
  return !!n && (n.type === "call_expression" || n.type === "call");
}

export function isNew(n: SyntaxNode | null): boolean {
  return !!n && n.type === "new_expression";
}

export function callee(n: SyntaxNode): SyntaxNode | null {
  if (n.type === "new_expression") return n.childForFieldName("constructor");
  return n.childForFieldName("function");
}

/**
 * Dotted path of an expression with call arguments dropped and optional chaining flattened:
 * `res.status(500).json` → "res.status().json", `openai?.chat.completions.create` → "openai.chat.completions.create",
 * `this.server.tool` → "this.server.tool". Subscripts become "[]".
 */
export function exprPath(n: SyntaxNode | null): string {
  if (!n) return "";
  switch (n.type) {
    case "identifier":
    case "property_identifier":
    case "private_property_identifier":
    case "shorthand_property_identifier":
    case "this":
    case "super":
      return n.text;
    case "member_expression":
      return `${exprPath(n.childForFieldName("object"))}.${n.childForFieldName("property")?.text ?? ""}`;
    case "attribute":
      return `${exprPath(n.childForFieldName("object"))}.${n.childForFieldName("attribute")?.text ?? ""}`;
    case "call_expression":
    case "call":
      return `${exprPath(n.childForFieldName("function"))}()`;
    case "new_expression":
      return `new ${exprPath(n.childForFieldName("constructor"))}()`;
    case "subscript_expression":
      return `${exprPath(n.childForFieldName("object"))}[]`;
    case "subscript":
      return `${exprPath(n.childForFieldName("value"))}[]`;
    case "parenthesized_expression":
    case "await_expression":
    case "await":
    case "non_null_expression":
    case "as_expression":
    case "satisfies_expression":
      return exprPath(kids(n)[0] ?? null);
    default:
      return n.text.replace(/\s+/g, "");
  }
}

/** Callee path of a call, e.g. "openai.chat.completions.create". */
export function calleePath(call: SyntaxNode): string {
  return exprPath(callee(call));
}

/** Last name segment of the callee: "create" for `openai.chat.completions.create(...)`. */
export function calleeName(call: SyntaxNode): string {
  const p = calleePath(call);
  const m = /([A-Za-z_$][\w$]*)(?:\(\))?$/.exec(p);
  return m ? m[1]! : p;
}

/** Positional and keyword argument nodes (comments excluded). */
export function args(call: SyntaxNode): SyntaxNode[] {
  const a = call.childForFieldName("arguments");
  return a ? kids(a) : [];
}

/** Positional arguments only (Python keyword arguments removed). */
export function positionalArgs(call: SyntaxNode): SyntaxNode[] {
  return args(call).filter((a) => a.type !== "keyword_argument");
}

/** Python keyword argument value by name. */
export function kwarg(call: SyntaxNode, name: string): SyntaxNode | null {
  for (const a of args(call)) if (a.type === "keyword_argument" && a.childForFieldName("name")?.text === name) return a.childForFieldName("value");
  return null;
}

/** All call nodes under `root`. With skipNestedFunctions, calls inside nested function bodies are skipped. */
export function callsIn(root: SyntaxNode, opts: { skipNestedFunctions?: boolean } = {}): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  walk(root, (n) => {
    if (opts.skipNestedFunctions && n.id !== root.id && isFunction(n)) return false;
    if (isCall(n) || isNew(n)) out.push(n);
    return true;
  });
  return out;
}

// ---------------------------------------------------------------- literals

/** Value of a string literal without interpolation, else null. JS: string, template without `${}`. Python: plain (non-f) strings. */
export function stringValue(n: SyntaxNode | null): string | null {
  const u = unwrap(n);
  if (!u) return null;
  if (u.type === "string") {
    if (u.descendantsOfType("interpolation").length) return null;
    const contentTypes = ["string_fragment", "string_content", "escape_sequence"];
    const parts = kids(u).filter((c) => contentTypes.includes(c.type));
    if (parts.length === 0) return "";
    return parts.map((c) => (c.type === "escape_sequence" ? unescape(c.text) : c.text)).join("");
  }
  if (u.type === "template_string") {
    if (u.descendantsOfType("template_substitution").length) return null;
    return u.text.slice(1, -1);
  }
  if (u.type === "concatenated_string") {
    const parts = kids(u).map((c) => stringValue(c));
    return parts.every((p) => p !== null) ? parts.join("") : null;
  }
  return null;
}

function unescape(seq: string): string {
  const map: Record<string, string> = { "\\n": "\n", "\\t": "\t", "\\r": "\r", "\\'": "'", '\\"': '"', "\\\\": "\\", "\\`": "`" };
  return map[seq] ?? seq.slice(1);
}

export function isStringLiteral(n: SyntaxNode | null): boolean {
  return stringValue(n) !== null;
}

/** A template literal with `${}` or a Python f-string with `{}`. */
export function isInterpolatedString(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  if (!u) return false;
  if (u.type === "template_string") return u.descendantsOfType("template_substitution").length > 0;
  if (u.type === "string") return u.descendantsOfType("interpolation").length > 0;
  return false;
}

export function isPyFString(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  return !!u && u.type === "string" && /^[rRbB]*[fF]/.test(u.text);
}

export function booleanValue(n: SyntaxNode | null): boolean | null {
  const u = unwrap(n);
  if (!u) return null;
  if (u.type === "true") return true;
  if (u.type === "false") return false;
  return null;
}

export function numberValue(n: SyntaxNode | null): number | null {
  const u = unwrap(n);
  if (!u || !["number", "integer", "float"].includes(u.type)) return null;
  const v = Number(u.text.replace(/_/g, ""));
  return Number.isFinite(v) ? v : null;
}

// ---------------------------------------------------------------- objects / dicts / arrays

export interface Prop {
  key: string;
  value: SyntaxNode;
  node: SyntaxNode;
}

/** Properties of a JS object literal or Python dict (shorthand `{ a }` gives key "a" with the identifier as value). */
export function objectProps(obj: SyntaxNode | null): Prop[] {
  const u = unwrap(obj);
  if (!u || (u.type !== "object" && u.type !== "dictionary")) return [];
  const out: Prop[] = [];
  for (const c of kids(u)) {
    if (c.type === "pair") {
      const k = c.childForFieldName("key");
      const v = c.childForFieldName("value");
      if (!k || !v) continue;
      const key = k.type === "string" ? (stringValue(k) ?? k.text) : k.text;
      out.push({ key, value: v, node: c });
    } else if (c.type === "shorthand_property_identifier") {
      out.push({ key: c.text, value: c, node: c });
    } else if (c.type === "method_definition") {
      const k = c.childForFieldName("name");
      if (k) out.push({ key: k.text, value: c, node: c });
    }
  }
  return out;
}

export function prop(obj: SyntaxNode | null, key: string): SyntaxNode | null {
  return objectProps(obj).find((p) => p.key === key)?.value ?? null;
}

/** Elements of an array / list / tuple / set literal. */
export function elements(n: SyntaxNode | null): SyntaxNode[] {
  const u = unwrap(n);
  if (!u || !["array", "list", "tuple", "set"].includes(u.type)) return [];
  return kids(u);
}

// ---------------------------------------------------------------- directives

/** True when the program or function body starts with the directive (e.g. "use server"). */
export function hasDirective(scope: SyntaxNode, directive: string): boolean {
  const body = scope.type === "program" ? scope : functionBody(scope);
  if (!body) return false;
  for (const stmt of kids(body)) {
    if (stmt.type !== "expression_statement") return false;
    const s = kids(stmt)[0];
    if (!s || s.type !== "string") return false;
    if (stringValue(s) === directive) return true;
  }
  return false;
}

// ---------------------------------------------------------------- imports

export interface ImportBinding {
  local: string;
  /** "default", "*", or the imported name. Python: the imported name, or "*" for `import x`. */
  imported: string;
  source: string;
  /** Python relative import level (number of leading dots). */
  level: number;
  node: SyntaxNode;
}

export function imports(pf: ParsedFile): ImportBinding[] {
  return memo(pf, "imports", () => (isJsLang(pf.lang) ? jsImports(pf.root) : pyImports(pf.root)));
}

function jsImports(root: SyntaxNode): ImportBinding[] {
  const out: ImportBinding[] = [];
  for (const imp of descendants(root, "import_statement")) {
    const source = stringValue(imp.childForFieldName("source")) ?? "";
    const clause = kids(imp).find((c) => c.type === "import_clause");
    if (!clause) continue;
    for (const c of kids(clause)) {
      if (c.type === "identifier") out.push({ local: c.text, imported: "default", source, level: 0, node: imp });
      else if (c.type === "namespace_import") {
        const id = kids(c)[0];
        if (id) out.push({ local: id.text, imported: "*", source, level: 0, node: imp });
      } else if (c.type === "named_imports") {
        for (const s of kids(c)) {
          if (s.type !== "import_specifier") continue;
          const name = s.childForFieldName("name")?.text ?? "";
          const alias = s.childForFieldName("alias")?.text ?? name;
          out.push({ local: alias, imported: name, source, level: 0, node: imp });
        }
      }
    }
  }
  // CommonJS: const x = require('m'); const { a, b: c } = require('m')
  for (const call of descendants(root, "call_expression")) {
    if (callee(call)?.text !== "require") continue;
    const source = stringValue(args(call)[0] ?? null);
    if (source === null) continue;
    const decl = call.parent?.type === "variable_declarator" ? call.parent : null;
    const name = decl?.childForFieldName("name");
    if (!name) continue;
    if (name.type === "identifier") out.push({ local: name.text, imported: "*", source, level: 0, node: call });
    else if (name.type === "object_pattern") {
      for (const c of kids(name)) {
        if (c.type === "shorthand_property_identifier_pattern") out.push({ local: c.text, imported: c.text, source, level: 0, node: call });
        else if (c.type === "pair_pattern") {
          const k = c.childForFieldName("key")?.text ?? "";
          const v = c.childForFieldName("value")?.text ?? k;
          out.push({ local: v, imported: k, source, level: 0, node: call });
        }
      }
    }
  }
  return out;
}

function pyImports(root: SyntaxNode): ImportBinding[] {
  const out: ImportBinding[] = [];
  for (const imp of descendants(root, "import_from_statement")) {
    const mod = imp.childForFieldName("module_name");
    let level = 0;
    let source = "";
    if (mod?.type === "relative_import") {
      level = (kids(mod).find((c) => c.type === "import_prefix")?.text.length ?? mod.text.match(/^\.+/)?.[0].length) || 0;
      source = kids(mod).find((c) => c.type === "dotted_name")?.text ?? "";
    } else if (mod) source = mod.text;
    for (const n of imp.childrenForFieldName("name")) {
      if (!n) continue;
      if (n.type === "aliased_import") {
        const name = n.childForFieldName("name")?.text ?? "";
        out.push({ local: n.childForFieldName("alias")?.text ?? name, imported: name, source, level, node: imp });
      } else out.push({ local: n.text, imported: n.text, source, level, node: imp });
    }
  }
  for (const imp of descendants(root, "import_statement")) {
    for (const n of imp.childrenForFieldName("name")) {
      if (!n) continue;
      if (n.type === "aliased_import") {
        const name = n.childForFieldName("name")?.text ?? "";
        out.push({ local: n.childForFieldName("alias")?.text ?? name, imported: "*", source: name, level: 0, node: imp });
      } else out.push({ local: n.text.split(".")[0]!, imported: "*", source: n.text, level: 0, node: imp });
    }
  }
  return out;
}

export function importOf(pf: ParsedFile, local: string): ImportBinding | null {
  return imports(pf).find((b) => b.local === local) ?? null;
}

/** Does the file import anything from a module matching `source` (string prefix or regex)? */
export function importsFrom(pf: ParsedFile, source: string | RegExp): ImportBinding[] {
  return imports(pf).filter((b) => (typeof source === "string" ? b.source === source || b.source.startsWith(`${source}/`) : source.test(b.source)));
}

// ---------------------------------------------------------------- declarations

export interface Declaration {
  name: string;
  /** Function node, or the initializer expression of a variable. */
  value: SyntaxNode;
  node: SyntaxNode;
  exported: boolean;
}

/** Top-level declarations: functions, classes, variables (JS) / functions, classes, assignments (Python). */
export function topLevel(pf: ParsedFile): Map<string, Declaration> {
  return memo(pf, "topLevel", () => {
    const out = new Map<string, Declaration>();
    const add = (name: string, value: SyntaxNode, node: SyntaxNode, exported: boolean) => {
      if (!out.has(name)) out.set(name, { name, value, node, exported });
    };
    const visitJs = (stmt: SyntaxNode, exported: boolean) => {
      switch (stmt.type) {
        case "export_statement": {
          const d = stmt.childForFieldName("declaration");
          if (d) visitJs(d, true);
          return;
        }
        case "function_declaration":
        case "generator_function_declaration":
        case "class_declaration": {
          const name = stmt.childForFieldName("name");
          if (name) add(name.text, stmt, stmt, exported);
          return;
        }
        case "lexical_declaration":
        case "variable_declaration":
          for (const d of kids(stmt)) {
            if (d.type !== "variable_declarator") continue;
            const name = d.childForFieldName("name");
            const value = d.childForFieldName("value");
            if (name?.type === "identifier" && value) add(name.text, value, d, exported);
          }
          return;
        default:
      }
    };
    if (isJsLang(pf.lang)) {
      for (const stmt of kids(pf.root)) visitJs(stmt, false);
    } else {
      for (const stmt of kids(pf.root)) {
        const def = stmt.type === "decorated_definition" ? stmt.childForFieldName("definition") : stmt;
        if (!def) continue;
        if (def.type === "function_definition" || def.type === "class_definition") {
          const name = def.childForFieldName("name");
          if (name) add(name.text, def, stmt, true);
        } else if (def.type === "expression_statement") {
          const a = kids(def)[0];
          if (a?.type === "assignment") {
            const left = a.childForFieldName("left");
            const right = a.childForFieldName("right");
            if (left?.type === "identifier" && right) add(left.text, right, a, true);
          }
        }
      }
    }
    return out;
  });
}

/** Exports of a JS module: name → value node. Handles `export function`, `export const`, `export { a as b }`, `export default`, CommonJS. */
export function exportsOf(pf: ParsedFile): Map<string, SyntaxNode> {
  return memo(pf, "exports", () => {
    const out = new Map<string, SyntaxNode>();
    if (!isJsLang(pf.lang)) {
      for (const [name, d] of topLevel(pf)) out.set(name, d.value);
      return out;
    }
    const decls = topLevel(pf);
    for (const d of decls.values()) if (d.exported) out.set(d.name, d.value);
    for (const stmt of kids(pf.root)) {
      if (stmt.type !== "export_statement") continue;
      // `export const { GET, POST } = handlers`: each destructured name maps to the right-hand expression.
      const decl = stmt.childForFieldName("declaration");
      if (decl && (decl.type === "lexical_declaration" || decl.type === "variable_declaration")) {
        for (const d of kids(decl)) {
          const name = d.type === "variable_declarator" ? d.childForFieldName("name") : null;
          const value = d.childForFieldName("value");
          if (name?.type === "object_pattern" && value) for (const n of boundNames(name)) if (!out.has(n)) out.set(n, value);
        }
      }
      const value = stmt.childForFieldName("value");
      if (value) {
        const resolved = value.type === "identifier" ? (decls.get(value.text)?.value ?? value) : value;
        out.set("default", resolved);
      }
      if (/^export\s+default\s+(async\s+)?function/.test(stmt.text)) {
        const d = stmt.childForFieldName("declaration");
        if (d) out.set("default", d);
      }
      const clause = kids(stmt).find((c) => c.type === "export_clause");
      if (clause) {
        for (const s of kids(clause)) {
          if (s.type !== "export_specifier") continue;
          const name = s.childForFieldName("name")?.text ?? "";
          const alias = s.childForFieldName("alias")?.text ?? name;
          const d = decls.get(name);
          out.set(alias, d?.value ?? s);
        }
      }
    }
    // CommonJS: module.exports = x; module.exports.a = x; exports.a = x
    for (const a of descendants(pf.root, "assignment_expression")) {
      const left = exprPath(a.childForFieldName("left"));
      const right = a.childForFieldName("right");
      if (!right) continue;
      const resolved = right.type === "identifier" ? (decls.get(right.text)?.value ?? right) : right;
      if (left === "module.exports") {
        out.set("default", resolved);
        for (const p of objectProps(right)) out.set(p.key, p.value.type === "identifier" ? (decls.get(p.value.text)?.value ?? p.value) : p.value);
      } else {
        const m = /^(?:module\.)?exports\.([A-Za-z_$][\w$]*)$/.exec(left);
        if (m) out.set(m[1]!, resolved);
      }
    }
    return out;
  });
}

/**
 * Resolve an identifier to its value in the same file: the nearest enclosing-scope declaration
 * (function, variable initializer, or Python assignment), else the top-level declaration.
 */
export function resolveLocal(pf: ParsedFile, name: string, from?: SyntaxNode): SyntaxNode | null {
  if (from) {
    for (let scope = enclosingFunction(from); scope; scope = enclosingFunction(scope)) {
      const body = functionBody(scope);
      if (!body) continue;
      const found = findDeclIn(body, name, from);
      if (found) return found;
    }
  }
  return topLevel(pf).get(name)?.value ?? null;
}

function findDeclIn(body: SyntaxNode, name: string, before: SyntaxNode): SyntaxNode | null {
  let found: SyntaxNode | null = null;
  walk(body, (n) => {
    if (n.id !== body.id && isFunction(n)) {
      if ((n.type === "function_declaration" || n.type === "function_definition") && n.childForFieldName("name")?.text === name) found = n;
      return false;
    }
    if (n.startIndex > before.startIndex) return false;
    if (n.type === "variable_declarator") {
      const nm = n.childForFieldName("name");
      if (nm?.type === "identifier" && nm.text === name) found = n.childForFieldName("value");
    } else if (n.type === "assignment") {
      const left = n.childForFieldName("left");
      if (left?.type === "identifier" && left.text === name) found = n.childForFieldName("right");
    }
    return true;
  });
  return found;
}

/** Follow an identifier to a function node in the same file (one hop through variables). */
export function resolveFunction(pf: ParsedFile, n: SyntaxNode | null, from?: SyntaxNode): SyntaxNode | null {
  const u = unwrap(n);
  if (!u) return null;
  if (isFunction(u)) return u;
  if (u.type === "identifier") {
    const v = resolveLocal(pf, u.text, from ?? u);
    if (v && isFunction(v)) return v;
  }
  return null;
}

// ---------------------------------------------------------------- identifiers and member paths

/** Identifier names referenced under `n`. */
export function identifiers(n: SyntaxNode): Set<string> {
  const out = new Set<string>();
  walk(n, (c) => {
    if (c.type === "identifier" || c.type === "shorthand_property_identifier") out.add(c.text);
    return true;
  });
  return out;
}

/** Member / attribute access paths under `n`, e.g. "req.body.name", "request.json()". Only maximal paths. */
export function memberPaths(n: SyntaxNode): string[] {
  const out: string[] = [];
  walk(n, (c) => {
    if (c.type === "member_expression" || c.type === "attribute" || c.type === "subscript_expression" || c.type === "subscript") {
      const parent = c.parent;
      const isPrefix =
        parent && (parent.type === "member_expression" || parent.type === "attribute") && same(parent.childForFieldName("object") ?? parent.childForFieldName("value"), c);
      if (!isPrefix) out.push(exprPath(c));
    }
    return true;
  });
  return out;
}

/** Does the subtree reference `name` as an identifier? */
export function references(n: SyntaxNode, name: string): boolean {
  let hit = false;
  walk(n, (c) => {
    if (hit) return false;
    if ((c.type === "identifier" || c.type === "shorthand_property_identifier") && c.text === name) hit = true;
    return !hit;
  });
  return hit;
}

/** Statements of a block in order (JS statement_block / Python block / program / module). */
export function statements(block: SyntaxNode | null): SyntaxNode[] {
  return block ? kids(block) : [];
}

/** Text of a node with whitespace collapsed (default finding anchor, spec 8.7). */
export function anchorText(n: SyntaxNode): string {
  return collapse(n.text);
}
