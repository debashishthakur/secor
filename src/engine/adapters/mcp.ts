// MCP adapters (spec section 8.2): TypeScript SDK registrations and Python FastMCP / MCPServer /
// low-level Server decorators. Tool handlers record which identifiers hold tool input.

import {
  args,
  boundNames,
  callee,
  calleeName,
  calleePath,
  descendants,
  objectProps,
  exprPath,
  functionBody,
  isCall,
  isFunction,
  kids,
  kwarg,
  paramNames,
  params,
  positionalArgs,
  prop,
  pyParam,
  resolveFunction,
  stringValue,
  unwrap,
  walk,
} from "../ast.js";
import type { ParsedFile, SyntaxNode } from "../parse.js";
import type { AdapterContext, RawEntry } from "./types.js";

const TS_REG = new Map<string, RawEntry["kind"]>([
  ["tool", "mcp_tool"],
  ["registerTool", "mcp_tool"],
  ["resource", "mcp_resource"],
  ["registerResource", "mcp_resource"],
  ["prompt", "mcp_prompt"],
  ["registerPrompt", "mcp_prompt"],
]);

export function mcpTsAdapter(a: AdapterContext): RawEntry[] {
  const { ctx, unit } = a;
  const out: RawEntry[] = [];
  for (const file of ctx.codeFiles(unit, "js")) {
    const text = ctx.read(file) ?? "";
    if (!/@modelcontextprotocol\/sdk|\.(?:registerTool|registerResource|registerPrompt|setRequestHandler)\s*\(/.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    walk(pf.root, (n) => {
      if (n.type !== "call_expression") return true;
      const fn = callee(n);
      if (fn?.type !== "member_expression") return true;
      const method = fn.childForFieldName("property")?.text ?? "";
      if (method === "setRequestHandler") {
        const schema = exprPath(args(n)[0] ?? null);
        if (/CallToolRequestSchema$/.test(schema)) out.push(...lowLevelTs(a, pf, n));
        return true;
      }
      const kind = TS_REG.get(method);
      if (!kind) return true;
      const all = args(n);
      const nameNode = all[0];
      const name = stringValue(nameNode ?? null);
      if (name === null) return true;
      const handlerArg = [...all].reverse().find((x) => isFunction(unwrap(x)) || unwrap(x)?.type === "identifier");
      const handler = handlerArg ? resolveFunction(pf, handlerArg, n) : null;
      out.push({
        kind,
        service: "mcp",
        framework: "mcp-ts",
        name,
        file,
        line: n.startPosition.row + 1,
        handlers: handler ? [{ file, pf, node: handler }] : [],
        middleware: [],
        registration: { file, pf, node: n },
        // Without an input schema the callback's first parameter is request metadata (`extra`), not tool input.
        inputNames: handler && (kind !== "mcp_tool" || hasInputSchema(method, all, handlerArg ?? null)) ? toolInputNames(handler) : [],
      });
      return true;
    });
  }
  return out;
}

const ANNOTATION_KEYS = new Set(["title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]);

/**
 * Does a TS SDK tool registration declare input? `registerTool(name, { inputSchema }, cb)`, or
 * `tool(name, [description], schema, [annotations], cb)` where schema is not a string and not an annotations-only object.
 */
export function hasInputSchema(method: string, all: SyntaxNode[], handlerArg: SyntaxNode | null): boolean {
  if (method === "registerTool") return prop(all[1] ?? null, "inputSchema") !== null;
  const between = all.slice(1).filter((x) => x !== handlerArg && !(handlerArg && x.id === handlerArg.id));
  return between.some((x) => {
    const u = unwrap(x);
    if (!u || stringValue(u) !== null) return false;
    if (u.type === "object") {
      const keys = objectProps(u).map((p) => p.key);
      return keys.length > 0 && !keys.every((k) => ANNOTATION_KEYS.has(k));
    }
    return true;
  });
}

/** Identifiers bound to tool input: destructured fields of the first parameter, or the parameter itself. */
export function toolInputNames(fn: SyntaxNode): string[] {
  const first = params(fn)[0];
  if (!first) return [];
  return boundNames(first);
}

function lowLevelTs(a: AdapterContext, pf: ParsedFile, call: SyntaxNode): RawEntry[] {
  const handlerArg = args(call)[1];
  const handler = handlerArg ? resolveFunction(pf, handlerArg, call) : null;
  const reqName = handler ? (paramNames(handler)[0] ?? "request") : "request";
  const names = new Set<string>();
  if (handler) {
    walk(handler, (n) => {
      if (n.type === "switch_statement" && /params\.name$|^name$/.test(exprPath(unwrap(n.childForFieldName("value"))))) {
        for (const c of descendants(n, "switch_case")) {
          const v = stringValue(c.childForFieldName("value"));
          if (v) names.add(v);
        }
      }
      if (n.type === "binary_expression" && ["===", "=="].includes(n.childForFieldName("operator")?.text ?? "")) {
        const l = n.childForFieldName("left");
        const r = n.childForFieldName("right");
        const isName = (x: SyntaxNode | null) => !!x && /params\.name$/.test(exprPath(unwrap(x)));
        const v = isName(l) ? stringValue(r) : isName(r) ? stringValue(l) : null;
        if (v) names.add(v);
      }
      return true;
    });
  }
  const list = names.size ? [...names].sort() : ["*"];
  return list.map((name) => ({
    kind: "mcp_tool" as const,
    service: "mcp" as const,
    framework: "mcp-ts" as const,
    name,
    file: pf.file,
    line: call.startPosition.row + 1,
    handlers: handler ? [{ file: pf.file, pf, node: handler }] : [],
    middleware: [],
    registration: { file: pf.file, pf, node: call },
    inputNames: [reqName],
  }));
}

const PY_DECORATORS = new Map<string, RawEntry["kind"]>([
  ["tool", "mcp_tool"],
  ["resource", "mcp_resource"],
  ["prompt", "mcp_prompt"],
  ["call_tool", "mcp_tool"],
]);

export function mcpPyAdapter(a: AdapterContext): RawEntry[] {
  const { ctx, unit } = a;
  const out: RawEntry[] = [];
  for (const file of ctx.codeFiles(unit, "py")) {
    const text = ctx.read(file) ?? "";
    if (!/\bmcp\b|fastmcp/i.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    const servers = serverNames(pf);
    if (servers.size === 0) continue;
    for (const def of pf.root.descendantsOfType("decorated_definition")) {
      if (!def) continue;
      const fn = def.childForFieldName("definition");
      if (!fn || fn.type !== "function_definition") continue;
      for (const d of kids(def).filter((k) => k.type === "decorator")) {
        const expr = kids(d)[0];
        if (!expr) continue;
        const target = isCall(expr) ? callee(expr) : expr;
        const path = exprPath(target);
        const m = /^(\w+)\.(tool|resource|prompt|call_tool)$/.exec(path);
        if (!m || !servers.has(m[1]!)) continue;
        const kind = PY_DECORATORS.get(m[2]!)!;
        const fnName = fn.childForFieldName("name")?.text ?? "";
        const explicit = isCall(expr) ? stringValue(kwarg(expr, "name")) : null;
        const inputNames = params(fn)
          .map((p) => pyParam(p))
          .filter((p): p is NonNullable<typeof p> => !!p && p.name !== "self" && !/\bContext\b/.test(p.type?.text ?? ""))
          .map((p) => p.name);
        if (m[2] === "call_tool") {
          out.push(...lowLevelPy(pf, d, fn, inputNames));
          continue;
        }
        out.push({
          kind,
          service: "mcp",
          framework: "mcp-py",
          name: explicit ?? fnName,
          file,
          line: d.startPosition.row + 1,
          handlers: [{ file, pf, node: fn }],
          middleware: [],
          registration: { file, pf, node: d },
          inputNames,
        });
      }
    }
    // fastmcp / mcp: server.add_tool(fn)
    walk(pf.root, (n) => {
      if (n.type !== "call") return true;
      const m = /^(\w+)\.add_tool$/.exec(calleePath(n));
      if (!m || !servers.has(m[1]!)) return true;
      const first = positionalArgs(n)[0];
      const fn = first ? resolveFunction(pf, first, n) : null;
      if (!fn) return true;
      out.push({
        kind: "mcp_tool",
        service: "mcp",
        framework: "mcp-py",
        name: stringValue(kwarg(n, "name")) ?? fn.childForFieldName("name")?.text ?? "tool",
        file,
        line: n.startPosition.row + 1,
        handlers: [{ file, pf, node: fn }],
        middleware: [],
        registration: { file, pf, node: n },
        inputNames: params(fn)
          .map((p) => pyParam(p)?.name ?? "")
          .filter((x) => x && x !== "ctx"),
      });
      return true;
    });
  }
  return out;
}

/** Variables assigned FastMCP(...), MCPServer(...) or a low-level Server(...). */
function serverNames(pf: ParsedFile): Set<string> {
  const out = new Set<string>();
  walk(pf.root, (n) => {
    if (n.type !== "assignment") return true;
    const left = n.childForFieldName("left");
    const right = unwrap(n.childForFieldName("right"));
    if (left?.type === "identifier" && right && isCall(right) && /^(?:FastMCP|MCPServer|Server)$/.test(calleeName(right))) out.add(left.text);
    return true;
  });
  return out;
}

function lowLevelPy(pf: ParsedFile, decorator: SyntaxNode, fn: SyntaxNode, inputNames: string[]): RawEntry[] {
  const nameParam = inputNames[0] ?? "name";
  const names = new Set<string>();
  const body = functionBody(fn);
  if (body) {
    walk(body, (n) => {
      if (n.type === "comparison_operator") {
        const parts = kids(n);
        if (parts.length === 2 && parts[0]!.text === nameParam) {
          const v = stringValue(parts[1]!);
          if (v) names.add(v);
        }
      }
      if (n.type === "case_clause") {
        const v = stringValue(kids(n)[0]?.descendantsOfType("string")[0] ?? null);
        if (v) names.add(v);
      }
      return true;
    });
  }
  const list = names.size ? [...names].sort() : ["*"];
  return list.map((name) => ({
    kind: "mcp_tool" as const,
    service: "mcp" as const,
    framework: "mcp-py" as const,
    name,
    file: pf.file,
    line: decorator.startPosition.row + 1,
    handlers: [{ file: pf.file, pf, node: fn }],
    middleware: [],
    registration: { file: pf.file, pf, node: decorator },
    inputNames: inputNames.slice(1),
  }));
}
