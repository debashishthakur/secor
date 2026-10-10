// core/error-leakage (spec section 8.5): a response that sends the raw error object, its stack, String(err) or
// err.toString() (Express error middleware and catch blocks, Next.js NextResponse.json / Response.json), FastAPI
// returning traceback.format_exc(), and FastAPI(debug=True). err.message alone is not a finding.

import {
  anchorText,
  args,
  booleanValue,
  callee,
  calleeName,
  calleePath,
  descendants,
  enclosingFunction,
  exprPath,
  functionBody,
  importOf,
  isFunction,
  kids,
  kwarg,
  params,
  paramPattern,
  positionalArgs,
  unwrap,
  walk,
} from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { defineRule } from "../types.js";

const WHY = "Stack traces and raw error objects reveal file paths, library versions and query details that help an attacker plan the next step.";
const FIX = "Log the error server-side; return a generic message and an error ID.";

/** Conditions that make a branch environment-dependent (development-only error detail is not reported). */
const ENV_CONDITION = /NODE_ENV|APP_ENV|ENVIRONMENT|\bdev(?:elopment)?\b|\bis_?dev|\bDEBUG\b|\bdebug\b|\bis_?prod|production|['"]env['"]/i;
const RESPONSE_NAMES = /^(?:res|resp|response|reply)$/;
const EXPRESS_SINK = /^([A-Za-z_$][\w$]*)((?:\.[A-Za-z_$][\w$]*\(\))*)\.(?:json|send|jsonp|end)$/;
const TRACEBACK_FUNCS = new Set(["format_exc", "format_exception", "format_tb"]);

type Report = (pf: ParsedFile, node: SyntaxNode) => void;

/** Is the node inside a branch whose condition depends on the environment (development-only detail)? */
function envGuarded(node: SyntaxNode): boolean {
  for (let p = node.parent; p; p = p.parent) {
    let cond: SyntaxNode | null = null;
    if (p.type === "if_statement" || p.type === "elif_clause" || p.type === "ternary_expression") cond = p.childForFieldName("condition");
    else if (p.type === "conditional_expression") cond = kids(p)[1] ?? null; // Python: a if cond else b
    else if (p.type === "binary_expression" && ["&&", "||"].includes(p.childForFieldName("operator")?.text ?? "")) cond = p.childForFieldName("left");
    else if (p.type === "boolean_operator") cond = p.childForFieldName("left");
    if (cond && ENV_CONDITION.test(cond.text)) return true;
  }
  return false;
}

// ---------------------------------------------------------------- JavaScript / TypeScript

/** Does `expr` (a response body) carry the error `err` beyond its message? Returns the leaking node. */
export function leaksError(expr: SyntaxNode | null, err: string, depth = 0): SyntaxNode | null {
  const u = unwrap(expr);
  if (!u || depth > 8) return null;
  switch (u.type) {
    case "identifier":
      return u.text === err ? u : null;
    case "member_expression": {
      const p = exprPath(u);
      return p === `${err}.stack` || p.startsWith(`${err}.stack.`) ? u : null;
    }
    case "call_expression": {
      const path = calleePath(u);
      if (path === `${err}.toString` || path.startsWith(`${err}.stack.`)) return u;
      if (path === "String" || path === "util.inspect" || path === "inspect") return leaksError(args(u)[0] ?? null, err, depth + 1) ? u : null;
      return null;
    }
    case "object":
      for (const c of kids(u)) {
        if (c.type === "shorthand_property_identifier" && c.text === err) return c;
        if (c.type === "pair" && leaksError(c.childForFieldName("value"), err, depth + 1)) return c;
      }
      return null;
    case "array":
      return kids(u).find((e) => leaksError(e, err, depth + 1)) ?? null;
    case "template_string":
      return kids(u).find((s) => s.type === "template_substitution" && leaksError(kids(s)[0] ?? null, err, depth + 1)) ?? null;
    case "binary_expression":
      if (u.childForFieldName("operator")?.text !== "+") return null;
      return leaksError(u.childForFieldName("left"), err, depth + 1) || leaksError(u.childForFieldName("right"), err, depth + 1) ? u : null;
    case "ternary_expression": {
      if (ENV_CONDITION.test(u.childForFieldName("condition")?.text ?? "")) return null;
      return leaksError(u.childForFieldName("consequence"), err, depth + 1) || leaksError(u.childForFieldName("alternative"), err, depth + 1) ? u : null;
    }
    default:
      return null;
  }
}

function identifierParams(fn: SyntaxNode): (string | null)[] {
  return params(fn).map((p) => {
    const pat = paramPattern(p);
    return pat.type === "identifier" ? pat.text : null;
  });
}

/** Is `name` a response object at `node`: a res-like name, the error middleware's res, or a handler's 2nd parameter? */
function isResponseObject(name: string, node: SyntaxNode, middlewareRes: string | null): boolean {
  if (name === middlewareRes || RESPONSE_NAMES.test(name)) return true;
  for (let f = enclosingFunction(node); f; f = enclosingFunction(f)) {
    const ps = identifierParams(f);
    if (ps.length >= 2 && ps.length <= 3 && ps[1] === name) return true;
  }
  return false;
}

/** The body argument when `n` sends an HTTP response. */
function responseBody(n: SyntaxNode, middlewareRes: string | null): SyntaxNode | null {
  if (n.type === "new_expression") {
    const ctor = exprPath(n.childForFieldName("constructor"));
    return ctor === "Response" || ctor === "NextResponse" ? (args(n)[0] ?? null) : null;
  }
  if (n.type !== "call_expression") return null;
  const path = calleePath(n);
  if (path === "NextResponse.json" || path === "Response.json") return args(n)[0] ?? null;
  const m = EXPRESS_SINK.exec(path);
  if (m && isResponseObject(m[1]!, n, middlewareRes)) return args(n)[0] ?? null;
  return null;
}

const ERROR_PARAM = /^(?:e|ex|exc)$|err|exception/i;

/** `app.use(fn)` / `router.use("/x", fn)`: the function is an argument of a `.use(` call. */
function passedToUse(fn: SyntaxNode): boolean {
  const call = fn.parent?.type === "arguments" ? fn.parent.parent : null;
  return !!call && call.type === "call_expression" && callee(call)?.type === "member_expression" && calleeName(call) === "use";
}

interface ErrScope {
  body: SyntaxNode;
  err: string;
  /** Error middleware: the response parameter (3rd of 4). */
  res: string | null;
}

function jsScopes(pf: ParsedFile): ErrScope[] {
  const out: ErrScope[] = [];
  walk(pf.root, (n) => {
    if (n.type === "catch_clause") {
      const p = n.childForFieldName("parameter");
      const body = n.childForFieldName("body");
      if (p?.type === "identifier" && body) out.push({ body, err: p.text, res: null });
    } else if (isFunction(n)) {
      // Express error middleware: (err, req, res, next), passed to .use() or with an error-like first parameter.
      const ps = identifierParams(n);
      const body = functionBody(n);
      if (ps.length === 4 && ps[0] && ps[2] && body && (ERROR_PARAM.test(ps[0]) || passedToUse(n))) out.push({ body, err: ps[0], res: ps[2] });
    } else if (n.type === "call_expression" && callee(n)?.type === "member_expression" && calleeName(n) === "catch") {
      // promise.catch((err) => ...)
      const fn = unwrap(args(n)[0] ?? null);
      const first = fn && isFunction(fn) ? identifierParams(fn)[0] : null;
      const body = fn ? functionBody(fn) : null;
      if (first && body) out.push({ body, err: first, res: null });
    }
    return true;
  });
  return out;
}

function checkJs(pf: ParsedFile, report: Report): void {
  for (const scope of jsScopes(pf)) {
    walk(scope.body, (n) => {
      if (n.type !== "call_expression" && n.type !== "new_expression") return true;
      const body = responseBody(n, scope.res);
      if (body && leaksError(body, scope.err) && !envGuarded(n)) report(pf, n);
      return true;
    });
  }
}

// ---------------------------------------------------------------- Python (FastAPI)

const ROUTE_DECORATOR = /\.(?:get|post|put|patch|delete|options|head|api_route|route|websocket|exception_handler|middleware)$/;

function isTracebackCall(n: SyntaxNode, pf: ParsedFile): boolean {
  if (n.type !== "call") return false;
  const path = calleePath(n);
  const m = /^(?:traceback\.)?(\w+)$/.exec(path);
  if (!m || !TRACEBACK_FUNCS.has(m[1]!)) return false;
  return path.startsWith("traceback.") || importOf(pf, m[1]!)?.source === "traceback";
}

function containsTraceback(node: SyntaxNode, pf: ParsedFile, names: ReadonlySet<string>): boolean {
  let hit = false;
  walk(node, (n) => {
    if (hit) return false;
    if (isTracebackCall(n, pf) || (n.type === "identifier" && names.has(n.text))) hit = true;
    return !hit;
  });
  return hit;
}

/** Variables assigned a value built from a traceback call inside `fn` (`tb = traceback.format_exc()`). */
function tracebackNames(fn: SyntaxNode, pf: ParsedFile): Set<string> {
  const out = new Set<string>();
  for (const a of descendants(fn, "assignment")) {
    const left = a.childForFieldName("left");
    const right = a.childForFieldName("right");
    if (left?.type === "identifier" && right && containsTraceback(right, pf, out)) out.add(left.text);
  }
  return out;
}

function isHandler(fn: SyntaxNode, handlerNames: ReadonlySet<string>): boolean {
  const def = fn.parent?.type === "decorated_definition" ? fn.parent : null;
  if (def) {
    for (const d of kids(def).filter((k) => k.type === "decorator")) {
      const expr = kids(d)[0];
      const target = expr?.type === "call" ? callee(expr) : expr;
      if (target && ROUTE_DECORATOR.test(exprPath(target))) return true;
    }
  }
  return handlerNames.has(fn.childForFieldName("name")?.text ?? "");
}

function checkPy(pf: ParsedFile, report: Report): void {
  // FastAPI(debug=True)
  for (const c of descendants(pf.root, "call")) {
    const path = calleePath(c);
    if ((path === "FastAPI" || path.endsWith(".FastAPI")) && booleanValue(kwarg(c, "debug")) === true && !envGuarded(c)) report(pf, c);
  }
  // Functions registered with add_exception_handler(Exc, fn).
  const handlerNames = new Set<string>();
  for (const c of descendants(pf.root, "call")) {
    if (calleeName(c) !== "add_exception_handler") continue;
    const fn = positionalArgs(c)[1] ?? kwarg(c, "handler");
    if (fn?.type === "identifier") handlerNames.add(fn.text);
  }
  for (const fn of descendants(pf.root, "function_definition")) {
    const names = tracebackNames(fn, pf);
    const body = functionBody(fn);
    if (!body) continue;
    // Response objects and HTTPException details built from a traceback, in any function.
    const flagged: SyntaxNode[] = [];
    walk(body, (n) => {
      if (n.id !== body.id && n.type === "function_definition") return false;
      if (n.type === "call" && /(?:^|\.)(?:\w*Response|HTTPException)$/.test(calleePath(n)) && args(n).some((a) => containsTraceback(a, pf, names))) {
        if (!envGuarded(n)) {
          flagged.push(n);
          report(pf, n);
        }
        return false;
      }
      return true;
    });
    // Route handlers and exception handlers returning a traceback directly or in a dict.
    if (!isHandler(fn, handlerNames)) continue;
    walk(body, (n) => {
      if (n.id !== body.id && n.type === "function_definition") return false;
      if (n.type !== "return_statement") return true;
      const value = kids(n)[0];
      if (!value || flagged.some((f) => f.startIndex >= n.startIndex && f.endIndex <= n.endIndex)) return false;
      if (containsTraceback(value, pf, names) && !envGuarded(n)) report(pf, n);
      return false;
    });
  }
}

// ---------------------------------------------------------------- rule

function apiFiles(ctx: ProjectContext): { js: string[]; py: string[] } {
  const js = new Set<string>();
  const py = new Set<string>();
  for (const u of ctx.unitsOf("api")) {
    if (u.framework === "express" || u.framework === "nextjs") for (const f of ctx.codeFiles(u, "js")) js.add(f);
    if (u.framework === "fastapi") for (const f of ctx.codeFiles(u, "py")) py.add(f);
  }
  return { js: [...js].sort(), py: [...py].sort() };
}

export const errorLeakage = defineRule({
  id: "core/error-leakage",
  title: "Errors returned to the caller",
  pack: "core",
  maturity: "experimental",
  appliesTo: (ctx) => ctx.hasUnit("api"),
  check(ctx, emit) {
    const seen = new Set<string>();
    const report: Report = (pf, node) => {
      const k = `${pf.file}:${node.startIndex}`;
      if (seen.has(k)) return;
      seen.add(k);
      emit({
        severity: "medium",
        service: "core",
        file: pf.file,
        line: node.startPosition.row + 1,
        endLine: node.endPosition.row + 1,
        anchor: anchorText(node),
        evidence: node.text,
        why: WHY,
        fix: { summary: FIX },
      });
    };
    const { js, py } = apiFiles(ctx);
    for (const file of js) {
      const text = ctx.read(file) ?? "";
      if (!/catch|err|NextResponse|Response/.test(text)) continue;
      const pf = ctx.parse(file);
      if (pf) checkJs(pf, report);
    }
    for (const file of py) {
      const text = ctx.read(file) ?? "";
      if (!/traceback|FastAPI/.test(text)) continue;
      const pf = ctx.parse(file);
      if (pf) checkPy(pf, report);
    }
  },
});
