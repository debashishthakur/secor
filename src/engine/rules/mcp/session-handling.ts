// mcp/session-handling (spec section 8.5): session IDs that are not cryptographically random (high), and a user or
// account looked up by the MCP session ID and used as identity without token verification (high, advisory).

import {
  anchorText,
  args,
  callee,
  calleeName,
  calleePath,
  callsIn,
  descendants,
  endLine,
  enclosingFunction,
  exprPath,
  importOf,
  isCall,
  isFunction,
  kids,
  line,
  numberValue,
  positionalArgs,
  resolveFunction,
  resolveLocal,
  stringValue,
  unwrap,
  walk,
} from "../../ast.js";
import type { GuardMatcher } from "../../auth-guards.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import { guardMatcherFor, mcpServerAuth } from "../../inventory.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { type LineEdit, unifiedDiff } from "../../patch.js";
import { SOURCES, defineRule } from "../types.js";
import { jsQuote, lastEsImport, mcpHttpUnits, numericArg, randomUuidCall, replaceNode, targetNames } from "./common.js";

const WHY_WEAK = "Session IDs that are predictable can be guessed or replayed, letting another client attach to an existing MCP session.";
const WHY_IDENTITY =
  "The MCP session ID identifies a connection, not a user: anyone who learns it is treated as that user. Each request needs a verified token.";
const FIX = "Use a cryptographically random ID; authenticate every request with a token, not the session.";

type Verdict = "ok" | "weak" | "unknown";

export const sessionHandlingRule = defineRule({
  id: "mcp/session-handling",
  title: "Weak session IDs or sessions used as auth",
  pack: "mcp",
  maturity: "experimental",
  source: SOURCES.mcpSecurity,
  appliesTo: (ctx) => mcpHttpUnits(ctx).length > 0,
  check(ctx, emit) {
    const guards = guardMatcherFor(ctx);
    const seen = new Set<string>();
    for (const unit of mcpHttpUnits(ctx)) {
      const serverAuth = !!mcpServerAuth(ctx, unit);
      for (const file of ctx.codeFiles(unit)) {
        if (seen.has(file)) continue;
        seen.add(file);
        const text = ctx.read(file) ?? "";
        if (!/session|sid\b/i.test(text)) continue;
        const pf = ctx.parse(file);
        if (!pf) continue;
        const py = pf.lang === "python";
        for (const w of py ? pyWeakIds(pf) : jsWeakIds(pf)) {
          const patch = w.generator ? generatorPatch(ctx, pf, w.node, w.generator) : null;
          emit({
            severity: "high",
            service: "mcp",
            file,
            line: line(w.node),
            ...(endLine(w.node) !== line(w.node) ? { endLine: endLine(w.node) } : {}),
            anchor: anchorText(w.node),
            evidence: w.node.text,
            why: WHY_WEAK,
            fix: {
              summary: w.generator
                ? `${FIX} For the Streamable HTTP transport: sessionIdGenerator: () => randomUUID(), with import { randomUUID } from "node:crypto".`
                : FIX,
              ...(patch ? { patch } : {}),
            },
          });
        }
        if (serverAuth) continue;
        for (const n of sessionIdentityLookups(pf, unit, guards)) {
          emit({
            severity: "high",
            advisory: true,
            service: "mcp",
            file,
            line: line(n),
            anchor: anchorText(n),
            evidence: n.text,
            why: WHY_IDENTITY,
            fix: { summary: FIX },
          });
        }
      }
    }
  },
});

// ---------------------------------------------------------------- weak IDs: TypeScript

interface WeakId {
  /** Node reported (the sessionIdGenerator property or the assignment). */
  node: SyntaxNode;
  /** The generator value to replace, for `sessionIdGenerator` (patchable). */
  generator: SyntaxNode | null;
}

const JS_SESSION_NAME = /^(?:mcp)?session_?id$|^sid$/i;

function jsWeakIds(pf: ParsedFile): WeakId[] {
  const out: WeakId[] = [];
  walk(pf.root, (n) => {
    if (n.type === "pair" && n.childForFieldName("key")?.text.replace(/^["']|["']$/g, "") === "sessionIdGenerator") {
      const value = n.childForFieldName("value");
      if (value && judgeJsGenerator(pf, value, 0) === "weak") out.push({ node: n, generator: value });
    } else if (n.type === "shorthand_property_identifier" && n.text === "sessionIdGenerator" && n.parent?.type === "object") {
      if (judgeJsGenerator(pf, n, 0) === "weak") out.push({ node: n, generator: n });
    } else if (n.type === "variable_declarator" || n.type === "assignment_expression") {
      const target = n.childForFieldName(n.type === "variable_declarator" ? "name" : "left");
      const value = n.childForFieldName(n.type === "variable_declarator" ? "value" : "right");
      const name = exprPath(target).split(".").pop() ?? "";
      if (target && value && JS_SESSION_NAME.test(name) && judgeJsExpr(pf, value) === "weak") out.push({ node: n, generator: null });
    }
    return true;
  });
  return out;
}

/** sessionIdGenerator value: `undefined` (stateless), a function, or a reference to one. */
function judgeJsGenerator(pf: ParsedFile, node: SyntaxNode, depth: number): Verdict {
  const u = unwrap(node);
  if (!u || depth > 3) return "unknown";
  if (u.type === "undefined" || (u.type === "identifier" && u.text === "undefined")) return "ok";
  if (u.type === "identifier" || u.type === "shorthand_property_identifier") {
    const imp = importOf(pf, u.text);
    if (imp && imp.imported === "randomUUID") return "ok";
    const v = resolveLocal(pf, u.text, u);
    if (v && v.id !== u.id) return judgeJsGenerator(pf, v, depth + 1);
    return "unknown";
  }
  if (u.type === "member_expression") return /(?:^|\.)randomUUID$/.test(exprPath(u)) ? "ok" : "unknown";
  if (isFunction(u)) return judgeJsFunction(pf, u, depth);
  return "unknown";
}

function judgeJsFunction(pf: ParsedFile, fn: SyntaxNode, depth: number): Verdict {
  const calls = callsIn(fn);
  if (calls.some((c) => isStrongJs(pf, c))) return "ok";
  if (calls.some((c) => isWeakJs(pf, c)) || descendants(fn, "update_expression").length > 0 || returnsLiteralOnly(fn)) return "weak";
  if (depth < 2) {
    for (const c of calls) {
      const target = resolveFunction(pf, callee(c), c);
      if (!target || target.id === fn.id) continue;
      const v = judgeJsFunction(pf, target, depth + 1);
      if (v !== "unknown") return v;
    }
  }
  return "unknown";
}

/** A custom session ID expression: weak only with positive evidence (Math.random, Date.now, counters...). */
function judgeJsExpr(pf: ParsedFile, value: SyntaxNode): Verdict {
  const u = unwrap(value);
  if (!u) return "unknown";
  if (isFunction(u)) return "unknown";
  const calls = isCall(u) || u.type === "new_expression" ? [u, ...callsIn(u)] : callsIn(u);
  if (calls.some((c) => isStrongJs(pf, c))) return "ok";
  if (calls.some((c) => isWeakJs(pf, c)) || u.type === "update_expression" || descendants(u, "update_expression").length > 0) return "weak";
  return "unknown";
}

function isStrongJs(pf: ParsedFile, c: SyntaxNode): boolean {
  const name = calleeName(c);
  const path = calleePath(c);
  if (name === "randomUUID") return true;
  if (name === "randomBytes") {
    const n = numericArg(pf, args(c)[0] ?? null);
    return n === null || n >= 16;
  }
  if (name === "getRandomValues") {
    const arr = unwrap(args(c)[0] ?? null);
    const n = arr && arr.type === "new_expression" ? numericArg(pf, args(arr)[0] ?? null) : null;
    return n === null || n >= 16;
  }
  const head = path.split(".")[0] ?? path;
  const imp = importOf(pf, head);
  if (imp?.source === "uuid" && (imp.imported === "v4" || (imp.imported !== "v1" && name === "v4"))) return true;
  if (imp && /^nanoid(?:\/|$)/.test(imp.source) && /^(?:nanoid|customAlphabet)$/.test(imp.imported === "*" ? name : imp.imported)) return true;
  return false;
}

function isWeakJs(pf: ParsedFile, c: SyntaxNode): boolean {
  const path = calleePath(c);
  if (/^(?:Math\.random|Date\.now|performance\.now|process\.hrtime(?:\.bigint)?)$/.test(path)) return true;
  if (c.type === "new_expression" && path === "Date") return true;
  if (calleeName(c) === "randomBytes") {
    const n = numericArg(pf, args(c)[0] ?? null);
    return n !== null && n < 16;
  }
  const imp = importOf(pf, path.split(".")[0] ?? path);
  return imp?.source === "uuid" && imp.imported === "v1";
}

/** `() => "fixed"`, `() => 42`, or a body whose returns are all literals. */
function returnsLiteralOnly(fn: SyntaxNode): boolean {
  const body = fn.childForFieldName("body");
  if (!body) return false;
  const literal = (n: SyntaxNode | null) => {
    const u = unwrap(n);
    return !!u && (stringValue(u) !== null || numberValue(u) !== null);
  };
  if (body.type !== "statement_block") return literal(body);
  const returns = descendants(body, "return_statement").filter((r) => enclosingFunction(r)?.id === fn.id);
  return returns.length > 0 && returns.every((r) => literal(kids(r)[0] ?? null));
}

/** Patch the generator to `() => randomUUID()`, adding the node:crypto import when needed (ES modules only). */
function generatorPatch(ctx: ProjectContext, pf: ParsedFile, property: SyntaxNode, value: SyntaxNode): string | null {
  const original = ctx.read(pf.file);
  if (original === null) return null;
  if (value.startPosition.row !== value.endPosition.row) return null;
  const edits: LineEdit[] = [];
  let call = randomUuidCall(pf);
  if (!call) {
    const last = lastEsImport(pf);
    if (!last) return null;
    const q = jsQuote(pf);
    const after = last.endPosition.row + 1;
    edits.push({ startLine: after + 1, endLine: after, newLines: [`import { randomUUID } from ${q}node:crypto${q};`] });
    call = "randomUUID()";
  }
  const shorthand = property.type === "shorthand_property_identifier";
  const edit = shorthand ? replaceNode(original, property, `sessionIdGenerator: () => ${call}`) : replaceNode(original, value, `() => ${call}`);
  if (!edit) return null;
  edits.push(edit);
  try {
    return unifiedDiff(pf.file, original, edits) || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- weak IDs: Python

const PY_SESSION_NAME = /^(?:mcp_)?session_?id$|^sid$/i;
const PY_STRONG = /^(?:secrets\.\w+|token_(?:hex|urlsafe|bytes)|uuid\.uuid4|uuid4|os\.urandom|urandom)$/;
const PY_WEAK = /^(?:random\.\w+|uuid\.uuid1|uuid1|time\.time(?:_ns)?|time\.monotonic(?:_ns)?|time\.perf_counter(?:_ns)?|datetime\.(?:datetime\.)?(?:now|utcnow)|id|hash)$/;

function pyWeakIds(pf: ParsedFile): WeakId[] {
  const out: WeakId[] = [];
  walk(pf.root, (n) => {
    if (n.type === "assignment") {
      const left = n.childForFieldName("left");
      const right = n.childForFieldName("right");
      const name = exprPath(left).split(".").pop() ?? "";
      if (left && right && PY_SESSION_NAME.test(name) && judgePyExpr(pf, right) === "weak") out.push({ node: n, generator: null });
    } else if (n.type === "keyword_argument" && n.childForFieldName("name")?.text === "mcp_session_id") {
      const v = n.childForFieldName("value");
      if (v && judgePyExpr(pf, v) === "weak") out.push({ node: n, generator: null });
    }
    return true;
  });
  return out;
}

function pyQualified(pf: ParsedFile, c: SyntaxNode): string {
  const path = calleePath(c);
  const head = path.split(".")[0] ?? path;
  const imp = importOf(pf, head);
  if (imp && imp.imported !== "*" && path === head) return `${imp.source}.${imp.imported}`;
  return path;
}

function judgePyExpr(pf: ParsedFile, value: SyntaxNode): Verdict {
  const u = unwrap(value);
  if (!u) return "unknown";
  const calls = isCall(u) ? [u, ...callsIn(u)] : callsIn(u);
  const names = calls.map((c) => pyQualified(pf, c));
  if (names.some((q) => PY_STRONG.test(q) && !/^os\.urandom$|^urandom$/.test(q))) return "ok";
  const urandom = calls.find((c) => /^(?:os\.)?urandom$/.test(pyQualified(pf, c)));
  if (urandom) {
    const n = numericArg(pf, positionalArgs(urandom)[0] ?? null);
    return n !== null && n < 16 ? "weak" : "ok";
  }
  if (names.some((q) => PY_WEAK.test(q))) return "weak";
  return "unknown";
}

// ---------------------------------------------------------------- sessions used as identity

const IDENTITY_NAME = /^(?:current_?)?(?:user|account|owner|principal|identity|member|customer|tenant|caller|profile)(?:_?(?:id|info|record|data|name))?$/i;
const SESSION_REF = /mcp-session-id|\bsessionId\b|\bsession_id\b|\bsid\b/;
const VERIFIES_TOKEN = /\bauthInfo\b|\bget_access_token\b|\bverify\w*|\bjwt\.|\bjwtVerify\b|\bdecode_token\b|\bvalidate_token\b|\bintrospect\w*/;

/**
 * Declarations that bind a user / account from a lookup keyed by the MCP session ID (`users.get(req.headers
 * ["mcp-session-id"])`, `sessions[sessionId].user`, one hop through a session variable), in functions that do not
 * verify a token.
 */
function sessionIdentityLookups(pf: ParsedFile, unit: UnitInfo, guards: GuardMatcher): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  const framework = unit.framework;
  const sessionVars = new Set<string>();
  const decls: { node: SyntaxNode; target: SyntaxNode; value: SyntaxNode }[] = [];
  walk(pf.root, (n) => {
    if (n.type === "variable_declarator") {
      const t = n.childForFieldName("name");
      const v = n.childForFieldName("value");
      if (t && v) decls.push({ node: n, target: t, value: v });
    } else if (n.type === "assignment") {
      const t = n.childForFieldName("left");
      const v = n.childForFieldName("right");
      if (t && v) decls.push({ node: n, target: t, value: v });
    }
    return true;
  });
  const isLookup = (v: SyntaxNode) => {
    const u = unwrap(v);
    if (!u) return false;
    if (["subscript_expression", "subscript"].includes(u.type)) return true;
    return isCall(u) || descendants(u, ["subscript_expression", "subscript", "call_expression", "call"]).length > 0;
  };
  // Variables holding a session record looked up by the session ID (`const session = sessions.get(sessionId)`).
  for (const d of decls) {
    const names = targetNames(d.target);
    if (names.some((x) => IDENTITY_NAME.test(x))) continue;
    if (isLookup(d.value) && SESSION_REF.test(d.value.text) && !/^(?:transport|server|t)$/i.test(names[0] ?? "")) {
      for (const x of names) if (!JS_SESSION_NAME.test(x) && !PY_SESSION_NAME.test(x)) sessionVars.add(x);
    }
  }
  const sessionVarRef = (v: SyntaxNode) => {
    let hit = false;
    walk(v, (c) => {
      if (hit) return false;
      if (c.type === "identifier" && sessionVars.has(c.text)) hit = true;
      return !hit;
    });
    return hit;
  };
  for (const d of decls) {
    const names = targetNames(d.target);
    if (!names.some((x) => IDENTITY_NAME.test(x))) continue;
    const direct = isLookup(d.value) && SESSION_REF.test(d.value.text);
    if (!direct && !sessionVarRef(d.value)) continue;
    if (VERIFIES_TOKEN.test(d.value.text)) continue;
    const fn = enclosingFunction(d.node);
    const scope = fn ?? pf.root;
    if (VERIFIES_TOKEN.test(scope.text)) continue;
    if (callsIn(scope).some((c) => guards.guardCall(c, framework))) continue;
    out.push(d.node);
  }
  return out;
}
