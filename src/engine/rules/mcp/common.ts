// Shared analysis for the mcp pack (spec section 8.5, MCP pack): MCP units and server constructions, a small
// intra-function taint tracker (tool input, the Authorization header), allowlists, sanitizers, host values and
// header checks. Everything here is syntactic and deterministic; decisions are recorded in DECISIONS.md.

import {
  args,
  callee,
  calleeName,
  calleePath,
  callsIn,
  descendants,
  exportsOf,
  exprPath,
  imports,
  importOf,
  isCall,
  isFunction,
  kids,
  numberValue,
  params,
  paramPattern,
  positionalArgs,
  resolveFunction,
  resolveLocal,
  same,
  stringValue,
  unwrap,
  walk,
} from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import type { LineEdit } from "../../patch.js";
import { resolveJsModule, resolvePyBinding } from "../../resolve.js";

// ---------------------------------------------------------------- units and servers

/** MCP units served over HTTP, optionally limited to one deployment kind. */
export function mcpHttpUnits(ctx: ProjectContext, deployment?: "local" | "remote"): UnitInfo[] {
  return ctx.unitsOf("mcp").filter((u) => !!u.mcp && u.mcp.transports.has("http") && (!deployment || u.mcp.deployment === deployment));
}

export interface Site {
  file: string;
  pf: ParsedFile;
  node: SyntaxNode;
}

const TS_SERVER_SOURCE = /^@modelcontextprotocol\/sdk\/server\//;
const PY_LOWLEVEL_SOURCE = /^mcp\.server(?:\.lowlevel(?:\.server)?)?$/;

/**
 * Server constructions in the unit's server files, in file order: `new McpServer(...)` / `new Server(...)` from the
 * TS SDK; `FastMCP(...)` / `MCPServer(...)` / a low-level `Server(...)` imported from the Python SDK.
 */
export function serverConstructions(ctx: ProjectContext, unit: UnitInfo): Site[] {
  const out: Site[] = [];
  for (const file of [...(unit.mcp?.serverFiles ?? [])].sort()) {
    const pf = ctx.parse(file);
    if (!pf) continue;
    const py = pf.lang === "python";
    walk(pf.root, (n) => {
      if (!py && n.type === "new_expression") {
        const name = exprPath(callee(n));
        if (name === "McpServer" || (name === "Server" && TS_SERVER_SOURCE.test(importOf(pf, "Server")?.source ?? ""))) out.push({ file, pf, node: n });
      } else if (py && n.type === "call") {
        const name = calleeName(n);
        if (name === "FastMCP" || name === "MCPServer") out.push({ file, pf, node: n });
        else if (calleePath(n) === "Server" && PY_LOWLEVEL_SOURCE.test(importOf(pf, "Server")?.source ?? "")) out.push({ file, pf, node: n });
      }
      return true;
    });
  }
  return out;
}

/** Which Python SDK a FastMCP / MCPServer construction comes from. */
export type PyFlavor = "mcp1" | "mcp2" | "fastmcp";

export function pyFlavor(pf: ParsedFile, call: SyntaxNode): PyFlavor {
  const path = calleePath(call);
  const head = path.split(".")[0] ?? path;
  const source = importOf(pf, head)?.source ?? "";
  if (/^fastmcp(?:\.|$)/.test(source) || path.startsWith("fastmcp.")) return "fastmcp";
  if (calleeName(call) === "MCPServer" || /^mcp\.server\.mcpserver/.test(source)) return "mcp2";
  return "mcp1";
}

/** A public `mcpServer` entry in secor.config.yaml names one of the unit's server files (spec 6.1). */
export function declaredPublicServer(ctx: ProjectContext, unit: UnitInfo): boolean {
  const files = new Set(unit.mcp?.serverFiles ?? []);
  return ctx.config.public.some((p) => "mcpServer" in p && files.has(p.mcpServer.replace(/^\.\//, "")));
}

/** Calls that hand an HTTP request to an MCP transport. */
export const TRANSPORT_HANDOFF = /(?:^|\.)(?:handleRequest|handlePostMessage)$/;

/** Text that marks a file as serving an MCP server over HTTP. */
export const SERVES_MCP_HTTP =
  /StreamableHTTPServerTransport|SSEServerTransport|handleRequest|handlePostMessage|streamable_http_app|sse_app|http_app|transport\s*=\s*["'](?:streamable-http|http|sse)["']|\.run\(\s*["'](?:streamable-http|http|sse)["']/;

// ---------------------------------------------------------------- generic helpers

export function isPy(pf: ParsedFile): boolean {
  return pf.lang === "python";
}

/** Function nodes directly nested in `scope` (not inside a deeper function). */
export function nestedFunctions(scope: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  walk(scope, (n) => {
    if (n.id !== scope.id && isFunction(n)) {
      out.push(n);
      return false;
    }
    return true;
  });
  return out;
}

/** Calls under `scope`, skipping nested functions. */
export function ownCalls(scope: SyntaxNode): SyntaxNode[] {
  return callsIn(scope, { skipNestedFunctions: true });
}

/** Leftmost identifier of a member / attribute / subscript chain. */
export function baseIdentifier(n: SyntaxNode | null): string | null {
  let cur = unwrap(n);
  while (cur) {
    if (cur.type === "identifier") return cur.text;
    if (cur.type === "member_expression" || cur.type === "attribute") cur = unwrap(cur.childForFieldName("object"));
    else if (cur.type === "subscript_expression") cur = unwrap(cur.childForFieldName("object"));
    else if (cur.type === "subscript") cur = unwrap(cur.childForFieldName("value"));
    else if (isCall(cur)) cur = unwrap(callee(cur));
    else return null;
  }
  return null;
}

/** An identifier node used as a value (not a property, attribute or keyword-argument name). */
export function isRefIdentifier(n: SyntaxNode): boolean {
  if (n.type === "shorthand_property_identifier") return true;
  if (n.type !== "identifier") return false;
  const p = n.parent;
  if (!p) return true;
  if (p.type === "attribute" && same(p.childForFieldName("attribute"), n)) return false;
  if (p.type === "keyword_argument" && same(p.childForFieldName("name"), n)) return false;
  return true;
}

/**
 * A same-file function called by `call` (one hop through variables), or the exported function of a relative
 * import (JS) / project module (Python).
 */
export function calledFunction(ctx: ProjectContext, pf: ParsedFile, call: SyntaxNode): { pf: ParsedFile; node: SyntaxNode } | null {
  const c = unwrap(callee(call));
  if (!c || c.type !== "identifier") return null;
  const local = resolveFunction(pf, c, call);
  if (local) return { pf, node: local };
  const imp = importOf(pf, c.text);
  if (!imp) return null;
  if (pf.lang === "python") {
    const target = resolvePyBinding(ctx, pf.file, imp.source, imp.imported, imp.level);
    const tpf = target ? ctx.parse(target.file) : null;
    if (!tpf || !target?.attr) return null;
    const v = exportsOf(tpf).get(target.attr);
    return v && isFunction(v) ? { pf: tpf, node: v } : null;
  }
  if (!imp.source.startsWith(".")) return null;
  const file = resolveJsModule(ctx, pf.file, imp.source);
  const tpf = file ? ctx.parse(file) : null;
  if (!tpf) return null;
  const v = exportsOf(tpf).get(imp.imported === "*" ? "default" : imp.imported);
  const fn = v ? resolveFunction(tpf, v) : null;
  return fn ? { pf: tpf, node: fn } : null;
}

/** Preferred string quote in a JS/TS file: the one most import specifiers use (default double). */
export function jsQuote(pf: ParsedFile): string {
  const single = (pf.source.match(/\bfrom\s+'/g) ?? []).length + (pf.source.match(/require\('/g) ?? []).length;
  const double = (pf.source.match(/\bfrom\s+"/g) ?? []).length + (pf.source.match(/require\("/g) ?? []).length;
  return single > double ? "'" : '"';
}

// ---------------------------------------------------------------- taint

export interface Binding {
  target: SyntaxNode;
  value: SyntaxNode;
}

const ITERATING_METHODS = new Set(["map", "forEach", "filter", "flatMap", "some", "every", "find", "findLast", "reduce", "then"]);

/** Variable bindings under `scope`: declarations, assignments, loop variables, `with ... as x`, walrus. */
export function bindingsIn(scope: SyntaxNode, deep: boolean): Binding[] {
  const out: Binding[] = [];
  const push = (t: SyntaxNode | null | undefined, v: SyntaxNode | null | undefined) => {
    if (t && v) out.push({ target: t, value: v });
  };
  walk(scope, (n) => {
    if (!deep && n.id !== scope.id && isFunction(n)) return false;
    const f = (name: string) => n.childForFieldName(name);
    switch (n.type) {
      case "variable_declarator":
        push(f("name"), f("value"));
        break;
      case "assignment_expression":
      case "augmented_assignment_expression":
      case "assignment":
      case "augmented_assignment":
      case "for_in_statement":
      case "for_statement":
      case "for_in_clause":
        push(f("left"), f("right"));
        break;
      case "named_expression":
        push(f("name"), f("value"));
        break;
      case "as_pattern": {
        const [value] = kids(n);
        push(f("alias"), value);
        break;
      }
      case "call_expression": {
        // items.map((x) => ...): the callback's parameters carry the receiver's values.
        const fn = callee(n);
        if (fn?.type === "member_expression" && ITERATING_METHODS.has(fn.childForFieldName("property")?.text ?? "")) {
          const recv = fn.childForFieldName("object");
          for (const a of args(n)) {
            const u = unwrap(a);
            if (u && isFunction(u)) for (const p of params(u)) push(p, recv);
          }
        }
        break;
      }
      default:
    }
    return true;
  });
  return out;
}

/** Names bound by an assignment target or parameter pattern. Member targets bind their base object (`h.x = v` → h). */
export function targetNames(target: SyntaxNode | null): string[] {
  if (!target) return [];
  const t = paramPattern(target);
  switch (t.type) {
    case "identifier":
    case "shorthand_property_identifier_pattern":
      return [t.text];
    case "member_expression":
    case "subscript_expression":
    case "subscript": {
      const base = baseIdentifier(t);
      return base && base !== "this" && base !== "self" ? [base] : [];
    }
    case "attribute":
      return [];
    case "pair_pattern":
      return targetNames(t.childForFieldName("value"));
    case "assignment_pattern":
    case "object_assignment_pattern":
      return targetNames(t.childForFieldName("left"));
    default:
      return kids(t).flatMap((k) => targetNames(k));
  }
}

/** Direct properties of an object destructuring pattern: key → bound names. */
export function objectPatternEntries(pattern: SyntaxNode): { key: string; names: string[] }[] {
  const out: { key: string; names: string[] }[] = [];
  for (const c of kids(pattern)) {
    if (c.type === "shorthand_property_identifier_pattern") out.push({ key: c.text, names: [c.text] });
    else if (c.type === "pair_pattern") {
      const k = c.childForFieldName("key");
      const key = k ? (stringValue(k) ?? k.text) : "";
      out.push({ key, names: targetNames(c.childForFieldName("value")) });
    } else if (c.type === "object_assignment_pattern") {
      const left = c.childForFieldName("left");
      if (left) out.push({ key: left.text, names: targetNames(left) });
    } else if (c.type === "rest_pattern") out.push({ key: "...", names: targetNames(c) });
  }
  return out;
}

export interface TaintOptions {
  /** Identifiers holding tainted data from the start (tool input parameters). */
  seeds?: Iterable<string>;
  /** Nodes that produce tainted data by themselves (an Authorization header read). */
  isSource?: (n: SyntaxNode) => boolean;
  /** `const { key } = <value>` that binds tainted data although `<value>` itself is not tainted. */
  sourceKey?: (key: string, value: SyntaxNode) => boolean;
  /** Subtrees whose value is not tainted even when they reference tainted names (sanitizers, allowlist lookups). */
  isClean?: (n: SyntaxNode, t: Taint) => boolean;
}

/** Flow-insensitive, name-based taint for one function. */
export class Taint {
  readonly names = new Set<string>();
  /** Names proven not to carry free-form input (allowlisted, enum or number typed). */
  readonly cleanNames = new Set<string>();
  /** Keys of seed objects (`args.key`, `arguments["key"]`) proven not to carry free-form input. */
  readonly cleanKeys = new Set<string>();
  readonly seeds: Set<string>;

  constructor(readonly opts: TaintOptions = {}) {
    this.seeds = new Set(opts.seeds ?? []);
    for (const s of this.seeds) this.names.add(s);
  }

  add(name: string): boolean {
    if (this.names.has(name)) return false;
    this.names.add(name);
    return true;
  }

  /** Does `n` carry tainted data? `alsoClean` marks extra subtrees as clean for this question only. */
  has(n: SyntaxNode | null | undefined, alsoClean?: (n: SyntaxNode) => boolean): boolean {
    if (!n) return false;
    let hit = false;
    walk(n, (c) => {
      if (hit) return false;
      if (this.isCleanNode(c) || alsoClean?.(c)) return false;
      if (this.opts.isSource?.(c)) {
        hit = true;
        return false;
      }
      if (isRefIdentifier(c) && this.names.has(c.text) && !this.cleanNames.has(c.text)) {
        hit = true;
        return false;
      }
      return true;
    });
    return hit;
  }

  /** Is `n` a direct reference to a seed object (`args`, `arguments`)? */
  isSeedRef(n: SyntaxNode | null): boolean {
    const u = unwrap(n);
    return !!u && u.type === "identifier" && this.seeds.has(u.text);
  }

  /** The key read from a seed object: `args.key`, `args["key"]`, `arguments.get("key")`. */
  seedKey(n: SyntaxNode | null): string | null {
    const u = unwrap(n);
    if (!u) return null;
    if (u.type === "member_expression" && this.isSeedRef(u.childForFieldName("object"))) return u.childForFieldName("property")?.text ?? null;
    if (u.type === "subscript_expression" && this.isSeedRef(u.childForFieldName("object"))) return stringValue(u.childForFieldName("index"));
    if (u.type === "subscript" && this.isSeedRef(u.childForFieldName("value"))) return stringValue(u.childForFieldName("subscript"));
    if (u.type === "call") {
      const fn = callee(u);
      if (fn?.type === "attribute" && fn.childForFieldName("attribute")?.text === "get" && this.isSeedRef(fn.childForFieldName("object"))) return stringValue(positionalArgs(u)[0] ?? null);
    }
    return null;
  }

  private isCleanNode(c: SyntaxNode): boolean {
    const key = this.seedKey(c);
    if (key !== null && this.cleanKeys.has(key)) return true;
    return this.opts.isClean?.(c, this) ?? false;
  }

  /** Propagate taint through bindings to a fixpoint. */
  propagate(bindings: readonly Binding[]): void {
    for (let round = 0; round < 8; round++) {
      let changed = false;
      for (const b of bindings) {
        const target = paramPattern(b.target);
        if (target.type === "object_pattern") {
          const value = unwrap(b.value);
          const fromSeed = this.isSeedRef(value);
          const tainted = this.has(b.value);
          for (const { key, names } of objectPatternEntries(target)) {
            const hit = (value && this.opts.sourceKey?.(key, value)) || (tainted && !(fromSeed && this.cleanKeys.has(key)));
            if (hit) for (const n of names) changed = this.add(n) || changed;
          }
          continue;
        }
        if (!this.has(b.value)) continue;
        for (const n of targetNames(b.target)) changed = this.add(n) || changed;
      }
      if (!changed) break;
    }
  }
}

// ---------------------------------------------------------------- the Authorization header

const AUTH_HEADER = /^authorization$/i;

/** A read of the incoming Authorization header or of the verified client token (spec: mcp/token-passthrough). */
export function isClientTokenSource(n: SyntaxNode): boolean {
  switch (n.type) {
    case "member_expression": {
      const p = exprPath(n);
      return /(?:^|\.)headers\.authorization$/i.test(p) || /(?:^|\.)authInfo\.token$/.test(p) || /^(?:req|request)\.auth\.token$/.test(p);
    }
    case "subscript_expression":
      return /(?:^|\.)headers$/i.test(exprPath(n.childForFieldName("object"))) && AUTH_HEADER.test(stringValue(n.childForFieldName("index")) ?? "");
    case "subscript":
      return /(?:^|\.)headers$/i.test(exprPath(n.childForFieldName("value"))) && AUTH_HEADER.test(stringValue(n.childForFieldName("subscript")) ?? "");
    case "call_expression": {
      const name = calleeName(n);
      if (name !== "get" && name !== "header" && name !== "getHeader") return false;
      return AUTH_HEADER.test(stringValue(args(n)[0] ?? null) ?? "");
    }
    case "call": {
      if (calleeName(n) === "get_access_token") return true;
      const fn = callee(n);
      if (fn?.type !== "attribute" || fn.childForFieldName("attribute")?.text !== "get") return false;
      if (!/(?:^|\.)headers$/i.test(exprPath(fn.childForFieldName("object")))) return false;
      return AUTH_HEADER.test(stringValue(positionalArgs(n)[0] ?? null) ?? "");
    }
    default:
      return false;
  }
}

/** `const { authorization } = req.headers` / `const { token } = extra.authInfo`. */
export function clientTokenKey(key: string, value: SyntaxNode): boolean {
  const p = exprPath(value);
  if (AUTH_HEADER.test(key) && /(?:^|\.)headers$/i.test(p)) return true;
  return key === "token" && /(?:^|\.)authInfo$/.test(p);
}

/** The whole incoming header set (`req.headers`, `request.headers`), which includes Authorization. */
export function isIncomingHeaderSet(n: SyntaxNode): boolean {
  if (n.type !== "member_expression" && n.type !== "attribute") return false;
  if (!/^(?:req|request|incoming\w*)\.headers$/i.test(exprPath(n))) return false;
  const p = n.parent;
  // Only the whole object, not a field of it.
  if (p && (p.type === "member_expression" || p.type === "attribute" || p.type === "subscript_expression" || p.type === "subscript")) {
    const obj = p.childForFieldName("object") ?? p.childForFieldName("value");
    if (same(obj, n)) return false;
  }
  return true;
}

// ---------------------------------------------------------------- allowlists and sanitizers

const UPPER_CONST = /^[A-Z][A-Z0-9_]*$/;

/** A collection whose members are fixed in code: a literal, `new Set([...])`, `frozenset({...})`, or an UPPER_CASE constant. */
export function isConstantCollection(pf: ParsedFile, n: SyntaxNode | null, from: SyntaxNode, depth = 0): boolean {
  const u = unwrap(n);
  if (!u || depth > 3) return false;
  if (["array", "list", "tuple", "set", "dictionary", "object"].includes(u.type)) return literalOnly(u);
  if (u.type === "new_expression") {
    const ctor = exprPath(callee(u));
    return (ctor === "Set" || ctor === "Map") && isConstantCollection(pf, args(u)[0] ?? null, from, depth + 1);
  }
  if (isCall(u)) {
    const path = calleePath(u);
    if (/^(?:frozenset|set|tuple|list|dict|Object\.keys|Object\.values|Object\.entries)$/.test(path)) return isConstantCollection(pf, positionalArgs(u)[0] ?? null, from, depth + 1);
    return false;
  }
  if (u.type === "identifier" || u.type === "member_expression" || u.type === "attribute") {
    const last = exprPath(u).split(".").pop() ?? "";
    if (UPPER_CONST.test(last)) return true;
    if (u.type === "identifier") {
      const v = resolveLocal(pf, u.text, from);
      if (v && v.id !== u.id) return isConstantCollection(pf, v, from, depth + 1);
    }
  }
  return false;
}

/** A literal whose members reference no variables except UPPER_CASE constants (keys and strings are fine). */
function literalOnly(n: SyntaxNode): boolean {
  let ok = true;
  walk(n, (c) => {
    if (!ok) return false;
    if (isFunction(c)) return false;
    if (isRefIdentifier(c) && !UPPER_CONST.test(c.text) && !/^(?:undefined|None|True|False|null)$/.test(c.text)) ok = false;
    return ok;
  });
  return ok;
}

/**
 * Record allowlist membership checks in `fn` on the taint: `ALLOWED.includes(x)`, `ALLOWED.has(x)`, `x in COMMANDS`,
 * Python `x in ALLOWED` / `x not in ALLOWED`. Identifiers become clean names; `args.key` reads become clean keys.
 */
export function recordAllowlists(pf: ParsedFile, fn: SyntaxNode, t: Taint): void {
  const mark = (subject: SyntaxNode | null) => {
    const u = unwrap(subject);
    if (!u) return;
    const key = t.seedKey(u);
    if (key !== null) t.cleanKeys.add(key);
    else if (u.type === "identifier") t.cleanNames.add(u.text);
  };
  walk(fn, (n) => {
    if (n.type === "call_expression") {
      const c = callee(n);
      const method = c?.type === "member_expression" ? (c.childForFieldName("property")?.text ?? "") : "";
      if ((method === "includes" || method === "has" || method === "indexOf") && isConstantCollection(pf, c!.childForFieldName("object"), n)) mark(args(n)[0] ?? null);
      if (calleePath(n) === "Object.hasOwn" && isConstantCollection(pf, args(n)[0] ?? null, n)) mark(args(n)[1] ?? null);
    } else if (n.type === "binary_expression" && n.childForFieldName("operator")?.text === "in") {
      if (isConstantCollection(pf, n.childForFieldName("right"), n)) mark(n.childForFieldName("left"));
    } else if (n.type === "comparison_operator") {
      const ops = n.children.filter((c): c is SyntaxNode => !!c && !c.isNamed).map((c) => c.type);
      const operands = kids(n);
      if (operands.length === 2 && (ops.includes("in") || ops.includes("not in")) && isConstantCollection(pf, operands[1]!, n)) mark(operands[0]!);
    }
    return true;
  });
}

/** Zod types in a TS tool's input schema that cannot carry a free-form string. */
const SAFE_ZOD = /^z\s*\.\s*(?:enum|literal|nativeEnum|number|boolean|bigint|int|coerce\s*\.\s*(?:number|boolean))\s*\(/;

/** Input keys of a TS tool registration whose schema is an enum, literal, number or boolean. */
export function safeSchemaKeysTs(registration: SyntaxNode, handler: SyntaxNode | null): Set<string> {
  const out = new Set<string>();
  for (const a of args(registration)) {
    if (handler && a.startIndex <= handler.startIndex && a.endIndex >= handler.endIndex) continue;
    walk(a, (n) => {
      if (n.type !== "pair") return true;
      const k = n.childForFieldName("key");
      const v = n.childForFieldName("value");
      if (k && v && SAFE_ZOD.test(v.text)) out.add(stringValue(k) ?? k.text);
      return true;
    });
  }
  return out;
}

const SAFE_PY_TYPE = /^(?:int|float|bool|Literal\[.*\]|Annotated\[\s*(?:int|float|bool|Literal\[.*\])\s*,.*\])$/s;

/** Python tool parameters typed as int / float / bool / Literal[...] / an Enum class defined in the file. */
export function safeTypedParamsPy(pf: ParsedFile, fn: SyntaxNode): Set<string> {
  const out = new Set<string>();
  for (const p of params(fn)) {
    const type = p.childForFieldName("type");
    const name = p.type === "typed_parameter" ? (kids(p)[0]?.text ?? "") : (p.childForFieldName("name")?.text ?? "");
    if (!type || !name) continue;
    const text = type.text.replace(/\s+/g, " ").trim();
    if (SAFE_PY_TYPE.test(text)) out.add(name);
    else if (/^\w+$/.test(text)) {
      const cls = descendants(pf.root, "class_definition").find((c) => c.childForFieldName("name")?.text === text);
      if (cls && /\bEnum\b|\bIntEnum\b|\bStrEnum\b/.test(cls.childForFieldName("superclasses")?.text ?? "")) out.add(name);
    }
  }
  return out;
}

/**
 * Expressions whose value cannot carry a path or command from the input: basename / secure_filename, numeric
 * conversions, and lookups in a constant map (`COMMANDS[name]`).
 */
export function isSanitized(pf: ParsedFile, n: SyntaxNode): boolean {
  if (isCall(n)) {
    const path = calleePath(n);
    const name = calleeName(n);
    if (name === "basename" || name === "secure_filename") return true;
    if (/^(?:Number|parseInt|parseFloat|int|float|bool|Boolean)$/.test(path)) return true;
    if (name === "get" && pf.lang === "python") {
      const fn = callee(n);
      if (fn?.type === "attribute" && isConstantCollection(pf, fn.childForFieldName("object"), n)) return true;
    }
    return false;
  }
  if (n.type === "subscript_expression") return isConstantCollection(pf, n.childForFieldName("object"), n);
  if (n.type === "subscript") return isConstantCollection(pf, n.childForFieldName("value"), n);
  if (n.type === "attribute") {
    // Path(x).name / PurePath(x).stem
    const attr = n.childForFieldName("attribute")?.text ?? "";
    const obj = unwrap(n.childForFieldName("object"));
    return (attr === "name" || attr === "stem") && !!obj && isCall(obj) && /(?:^|\.)(?:Pure)?(?:Posix|Windows)?Path$/.test(calleePath(obj));
  }
  return false;
}

/** Shell quoting that neutralises interpolated input (`shlex.quote(x)`, shell-quote's `quote([x])`). */
export function isShellQuoted(n: SyntaxNode): boolean {
  if (!isCall(n)) return false;
  return /^(?:shlex\.quote|pipes\.quote|shlex\.join|quote|shellQuote|shellescape|shellEscape|escapeShellArg)$/.test(calleePath(n));
}

// ---------------------------------------------------------------- credential and header checks

const CREDENTIAL_HEADER = /^(?:authorization|x-api-key|api-key|x-auth-token|x-access-token)$/i;
const DENY_TEXT = /\b40[13]\b|Unauthorized|Forbidden|PermissionError|AuthenticationError/;

/** Does `n` read a credential header (Authorization, X-API-Key...) or the verified auth info? */
function readsCredential(n: SyntaxNode): boolean {
  switch (n.type) {
    case "member_expression": {
      const p = exprPath(n);
      return /(?:^|\.)headers\.authorization$/i.test(p) || /(?:^|\.)authInfo$/.test(p);
    }
    case "subscript_expression":
      return /(?:^|\.)headers$/i.test(exprPath(n.childForFieldName("object"))) && CREDENTIAL_HEADER.test(stringValue(n.childForFieldName("index")) ?? "");
    case "subscript":
      return /(?:^|\.)headers$/i.test(exprPath(n.childForFieldName("value"))) && CREDENTIAL_HEADER.test(stringValue(n.childForFieldName("subscript")) ?? "");
    case "call_expression":
    case "call": {
      const name = calleeName(n);
      if (name !== "get" && name !== "header" && name !== "getHeader") return false;
      return CREDENTIAL_HEADER.test(stringValue(positionalArgs(n)[0] ?? null) ?? "");
    }
    default:
      return false;
  }
}

/** A function that reads a credential header and refuses the request (custom auth middleware or handler check). */
export function checksCredentials(fn: SyntaxNode): boolean {
  if (!DENY_TEXT.test(fn.text)) return false;
  let reads = false;
  walk(fn, (n) => {
    if (reads || n.type === "comment") return false;
    if (readsCredential(n)) reads = true;
    return !reads;
  });
  return reads;
}

const ORIGIN_OR_HOST = /^(?:origin|host)$/i;

/** Does `n` read the incoming Origin or Host header? */
export function readsOriginOrHost(n: SyntaxNode): boolean {
  switch (n.type) {
    case "member_expression":
      return /(?:^|\.)headers\.(?:origin|host)$/i.test(exprPath(n));
    case "subscript_expression":
      return /(?:^|\.)headers$/i.test(exprPath(n.childForFieldName("object"))) && ORIGIN_OR_HOST.test(stringValue(n.childForFieldName("index")) ?? "");
    case "subscript":
      return /(?:^|\.)headers$/i.test(exprPath(n.childForFieldName("value"))) && ORIGIN_OR_HOST.test(stringValue(n.childForFieldName("subscript")) ?? "");
    case "call_expression":
    case "call": {
      const name = calleeName(n);
      if (name !== "get" && name !== "header" && name !== "getHeader") return false;
      return ORIGIN_OR_HOST.test(stringValue(positionalArgs(n)[0] ?? null) ?? "");
    }
    default:
      return false;
  }
}

const COMPARING_CALLS = /^(?:includes|has|startsWith|endsWith|test|indexOf|match|some|every)$/;
const REJECT_TEXT = /\b(?:400|403|421)\b|Forbidden|Invalid (?:Host|Origin)|\braise\b|\bthrow\b/;

/**
 * A function that reads the Origin or Host header, compares it (`===`, `!==`, `includes`, `in`...) directly or through
 * a variable, and rejects the request. Building a URL from the Host header does not count.
 */
export function validatesOriginOrHost(fn: SyntaxNode): boolean {
  if (!REJECT_TEXT.test(fn.text)) return false;
  const holders = new Set<string>();
  walk(fn, (n) => {
    if (n.type === "variable_declarator" || n.type === "assignment") {
      const target = n.childForFieldName(n.type === "variable_declarator" ? "name" : "left");
      const value = n.childForFieldName(n.type === "variable_declarator" ? "value" : "right");
      if (target?.type === "identifier" && value && directHeaderRead(value)) holders.add(target.text);
    }
    return true;
  });
  const subject = (x: SyntaxNode | null): boolean => {
    let u = unwrap(x);
    // origin?.toLowerCase(), host.split(":")[0]
    while (u && (isCall(u) || u.type === "member_expression" || u.type === "attribute" || u.type === "subscript_expression" || u.type === "subscript")) {
      if (readsOriginOrHost(u)) return true;
      u = unwrap(isCall(u) ? callee(u) : (u.childForFieldName("object") ?? u.childForFieldName("value")));
    }
    return !!u && u.type === "identifier" && holders.has(u.text);
  };
  let found = false;
  walk(fn, (n) => {
    if (found) return false;
    if (n.type === "binary_expression" && ["===", "!==", "==", "!="].includes(n.childForFieldName("operator")?.text ?? "")) {
      found = subject(n.childForFieldName("left")) || subject(n.childForFieldName("right"));
    } else if (n.type === "comparison_operator") {
      found = kids(n).some((k) => subject(k));
    } else if (isCall(n) && COMPARING_CALLS.test(calleeName(n))) {
      const c = callee(n);
      const recv = c && (c.type === "member_expression" || c.type === "attribute") ? (c.childForFieldName("object") ?? null) : null;
      found = subject(recv) || args(n).some((a) => subject(a));
    }
    return !found;
  });
  return found;
}

/**
 * The value is the Origin/Host header itself, possibly normalised: `req.headers.origin?.toLowerCase()`,
 * `req.headers.host ?? ""`, `String(req.headers.origin)`, `request.headers.get("origin", "")`.
 * A header embedded in a larger value (`new URL(..., \`http://${req.headers.host}\`)`) is not.
 */
function directHeaderRead(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  if (!u) return false;
  if (readsOriginOrHost(u)) return true;
  if (u.type === "binary_expression" && ["??", "||"].includes(u.childForFieldName("operator")?.text ?? "")) {
    return directHeaderRead(u.childForFieldName("left")) || directHeaderRead(u.childForFieldName("right"));
  }
  if (u.type === "boolean_operator") return directHeaderRead(u.childForFieldName("left")) || directHeaderRead(u.childForFieldName("right"));
  if (isCall(u)) {
    if (/^(?:String|str)$/.test(calleePath(u))) return directHeaderRead(positionalArgs(u)[0] ?? null);
    const c = callee(u);
    return !!c && (c.type === "member_expression" || c.type === "attribute") && directHeaderRead(c.childForFieldName("object"));
  }
  if (u.type === "member_expression" || u.type === "attribute") return directHeaderRead(u.childForFieldName("object"));
  if (u.type === "subscript_expression" || u.type === "subscript") return directHeaderRead(u.childForFieldName("object") ?? u.childForFieldName("value"));
  return false;
}

// ---------------------------------------------------------------- host values

export type HostKind = "all" | "local" | "other" | "unknown";
export interface HostValue {
  kind: HostKind;
  /** The string literal holding "0.0.0.0" / "::" (for a patch), when there is one. */
  literal: SyntaxNode | null;
}

const ALL_INTERFACES = new Set(["0.0.0.0", "::", "[::]"]);
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

/** Classify a host expression: a literal, a resolvable constant, or a default inside `env ?? "0.0.0.0"`. */
export function classifyHost(pf: ParsedFile, n: SyntaxNode | null, depth = 0): HostValue {
  const u = unwrap(n);
  if (!u || depth > 3) return { kind: "unknown", literal: null };
  const s = stringValue(u);
  if (s !== null) {
    if (ALL_INTERFACES.has(s)) return { kind: "all", literal: u };
    if (LOOPBACK.has(s)) return { kind: "local", literal: null };
    return { kind: "other", literal: null };
  }
  if (u.type === "identifier") {
    const v = resolveLocal(pf, u.text, u);
    if (v && v.id !== u.id) return classifyHost(pf, v, depth + 1);
    return { kind: "unknown", literal: null };
  }
  // A default value: process.env.HOST ?? "0.0.0.0", os.environ.get("HOST", "0.0.0.0"), getenv(...).
  const literals = descendants(u, "string").filter((x) => stringValue(x) !== null);
  const all = literals.find((x) => ALL_INTERFACES.has(stringValue(x)!));
  if (all) return { kind: "all", literal: all };
  if (literals.some((x) => LOOPBACK.has(stringValue(x)!))) return { kind: "local", literal: null };
  return { kind: "unknown", literal: null };
}

/** Last top-level import statement of an ES module (null for CommonJS or no imports). */
export function lastEsImport(pf: ParsedFile): SyntaxNode | null {
  let last: SyntaxNode | null = null;
  for (const stmt of kids(pf.root)) if (stmt.type === "import_statement") last = stmt;
  return last;
}

/** Local name bound to `randomUUID` from node:crypto, or a crypto namespace (`crypto.randomUUID`). */
export function randomUuidCall(pf: ParsedFile): string | null {
  for (const b of imports(pf)) {
    if (!/^(?:node:)?crypto$/.test(b.source)) continue;
    if (b.imported === "randomUUID") return `${b.local}()`;
  }
  for (const b of imports(pf)) {
    if (!/^(?:node:)?crypto$/.test(b.source)) continue;
    if (b.imported === "*" || b.imported === "default") return `${b.local}.randomUUID()`;
  }
  return null;
}

/** Number literal value of an argument (or of a const it names). */
export function numericArg(pf: ParsedFile, n: SyntaxNode | null): number | null {
  const u = unwrap(n);
  if (!u) return null;
  const v = numberValue(u);
  if (v !== null) return v;
  if (u.type === "identifier") {
    const d = resolveLocal(pf, u.text, u);
    return d && d.id !== u.id ? numberValue(d) : null;
  }
  return null;
}

// ---------------------------------------------------------------- precise single-line edits

/**
 * Replace exactly `node` (which must sit on one line) with `replacement`. tree-sitter columns are UTF-16 offsets,
 * like JS string indices, so the edit targets this node even when the same text occurs earlier on the line.
 */
export function replaceNode(source: string, node: SyntaxNode, replacement: string): LineEdit | null {
  if (node.startPosition.row !== node.endPosition.row) return null;
  const row = node.startPosition.row;
  const text = source.split("\n")[row];
  const col = node.startPosition.column;
  if (text === undefined || text.slice(col, col + node.text.length) !== node.text) return null;
  return { startLine: row + 1, endLine: row + 1, newLines: [text.slice(0, col) + replacement + text.slice(col + node.text.length)] };
}

/** Insert `insertion` right after `node` on its (last) line. */
export function insertAfterNode(source: string, node: SyntaxNode, insertion: string): LineEdit | null {
  const row = node.endPosition.row;
  const text = source.split("\n")[row];
  const col = node.endPosition.column;
  if (text === undefined || col > text.length) return null;
  return { startLine: row + 1, endLine: row + 1, newLines: [text.slice(0, col) + insertion + text.slice(col)] };
}
