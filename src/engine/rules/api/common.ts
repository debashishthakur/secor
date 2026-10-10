// Shared helpers for the api pack (spec section 8.5): entry selection, request-input tracking,
// user-identity values (section 8.3), query chains, and test-template filling (section 8.8).

import { posix } from "node:path";
import type { Framework } from "../../../types.js";
import {
  boundNames,
  callee,
  calleeName,
  calleePath,
  exportsOf,
  exprPath,
  importOf,
  isCall,
  isFunction,
  isInside,
  kids,
  paramPattern,
  params,
  positionalArgs,
  pyParam,
  stringValue,
  topLevel,
  unwrap,
  walk,
} from "../../ast.js";
import { type GuardMatcher, callsOneLevel, classifyDbCall, identityBindings, referencesIdentity } from "../../auth-guards.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import { hasDep } from "../../deps.js";
import type { HandlerRef, InventoryEntry } from "../../inventory-types.js";
import { modelIndex } from "../../models.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { redact } from "../../redact.js";
import { resolvePyBinding } from "../../resolve.js";
import { renderTestTemplate } from "../../templates.js";

// ---------------------------------------------------------------- entries

/** HTTP routes and server actions of api units (the entry points the api pack checks). */
export function apiEntries(ctx: ProjectContext): InventoryEntry[] {
  return ctx.inventory.filter((e) => e.service === "api" && (e.kind === "http_route" || e.kind === "server_action"));
}

/** Stable identity of an entry point inside its file: "<METHOD> <path>" or the server action name. */
export function entryKey(e: InventoryEntry): string {
  return e.kind === "server_action" ? (e.name ?? e.file) : `${e.method ?? "*"} ${e.path ?? ""}`;
}

export function firstLine(text: string): string {
  return (text.split("\n", 1)[0] ?? "").trim();
}

export type HandlerKind = "express" | "pages" | "route" | "action" | "fastapi";

export function handlerKind(e: InventoryEntry): HandlerKind {
  if (e.framework === "fastapi") return "fastapi";
  if (e.framework === "express") return "express";
  if (e.kind === "server_action") return "action";
  return /(?:^|\/)pages\/api\//.test(e.file) ? "pages" : "route";
}

export interface HandlerUse {
  ref: HandlerRef;
  entries: InventoryEntry[];
}

/** Group entries by handler function, so one handler shared by several entries is analysed once. */
export function handlerUses(entries: readonly InventoryEntry[]): HandlerUse[] {
  const out = new Map<string, HandlerUse>();
  for (const e of entries) {
    for (const ref of e.internal.handlers) {
      const key = `${ref.file}:${ref.node.startIndex}:${ref.node.endIndex}`;
      const u = out.get(key);
      if (!u) out.set(key, { ref, entries: [e] });
      else if (!u.entries.includes(e)) u.entries.push(e);
    }
  }
  return [...out.values()];
}

/** The entry a node belongs to: the pages-router method branch containing it, else the first entry. */
export function entryFor(use: HandlerUse, node: SyntaxNode): InventoryEntry {
  for (const e of use.entries) {
    const b = e.internal.methodBranch;
    if (b && b.id !== use.ref.node.id && isInside(node, b)) return e;
  }
  return use.entries[0]!;
}

// ---------------------------------------------------------------- request input

/** params / query: route and query values; body: request body (unvalidated); model: pydantic-typed body (validated). */
export type InputKind = "params" | "query" | "body" | "model";
export const ALL_INPUT: readonly InputKind[] = ["params", "query", "body", "model"];

export interface RequestModel {
  kind: HandlerKind;
  lang: "js" | "py";
  fn: SyntaxNode;
  pf: ParsedFile;
  /** Request object names: Express/pages `req`, Next.js `Request`, FastAPI `Request`-typed params. */
  req: string[];
  /** Response object names (Express / pages router). */
  res: string[];
  /** Next.js route-handler context names (`ctx` → `ctx.params`). */
  ctxNames: string[];
  /** Locals bound directly to client input. */
  roots: Map<string, Set<InputKind>>;
  /** FastAPI: parameter name → type name, for body parameters. */
  pyTypes: Map<string, string>;
}

function addRoot(m: RequestModel, name: string, kind: InputKind): void {
  if (!name) return;
  const s = m.roots.get(name) ?? new Set<InputKind>();
  s.add(kind);
  m.roots.set(name, s);
}

const REQ_PARTS = new Map<string, InputKind>([
  ["body", "body"],
  ["params", "params"],
  ["query", "query"],
]);

/** Destructured request parts: `({ body, params }, res) =>` or `const { body } = req`. */
function destructuredParts(pattern: SyntaxNode, onPart: (local: string, kind: InputKind) => void): void {
  for (const c of kids(pattern)) {
    if (c.type === "shorthand_property_identifier_pattern") {
      const k = REQ_PARTS.get(c.text);
      if (k) onPart(c.text, k);
    } else if (c.type === "pair_pattern") {
      const k = REQ_PARTS.get(c.childForFieldName("key")?.text ?? "");
      const v = c.childForFieldName("value");
      if (k && v) for (const n of boundNames(v)) onPart(n, k);
    }
  }
}

export function requestModel(ctx: ProjectContext, e: InventoryEntry, ref: HandlerRef): RequestModel {
  const kind = handlerKind(e);
  const m: RequestModel = { kind, lang: ref.pf.lang === "python" ? "py" : "js", fn: ref.node, pf: ref.pf, req: [], res: [], ctxNames: [], roots: new Map(), pyTypes: new Map() };
  if (kind === "fastapi") {
    pyInputs(ctx, e, ref, m);
    return m;
  }
  const ps = params(ref.node);
  if (kind === "action") {
    // Every server action argument comes from the client.
    for (const p of ps) for (const n of boundNames(p)) addRoot(m, n, "body");
    return m;
  }
  const first = ps[0] ? paramPattern(ps[0]) : null;
  const second = ps[1] ? paramPattern(ps[1]) : null;
  if (first?.type === "identifier") m.req.push(first.text);
  else if (first?.type === "object_pattern") destructuredParts(first, (local, k) => addRoot(m, local, k));
  if (kind === "route") {
    if (second?.type === "identifier") m.ctxNames.push(second.text);
    else if (second?.type === "object_pattern") {
      for (const c of kids(second)) {
        if (c.type === "shorthand_property_identifier_pattern" && c.text === "params") addRoot(m, "params", "params");
        else if (c.type === "pair_pattern" && c.childForFieldName("key")?.text === "params") for (const n of boundNames(c.childForFieldName("value") ?? c)) addRoot(m, n, "params");
      }
    }
  } else if (second?.type === "identifier") m.res.push(second.text);
  return m;
}

// ---------------------------------------------------------------- FastAPI parameters

const PY_SCALARS = new Set(["int", "str", "float", "bool", "bytes", "UUID", "uuid", "date", "datetime", "time", "Decimal", "EmailStr", "HttpUrl", "AnyUrl", "Path", "Literal"]);
const PY_SPECIAL = /^(?:Response|BackgroundTasks|Session|AsyncSession|SecurityScopes|Connection|AsyncConnection)$/;
const PY_REQUEST = /^(?:Request|HTTPConnection|WebSocket)$/;

/** Base type name of a Python annotation: `Annotated[X, ...]` → X, `Optional[X]` / `X | None` → X, `list[X]` → "list". */
export function pyTypeName(type: SyntaxNode | null): string {
  if (!type) return "";
  const t = type.type === "type" ? (kids(type)[0] ?? type) : type;
  switch (t.type) {
    case "identifier":
      return t.text;
    case "attribute":
      return t.childForFieldName("attribute")?.text ?? t.text;
    case "generic_type": {
      const base = kids(t).find((k) => k.type === "identifier" || k.type === "attribute");
      const baseName = base ? (exprPath(base).split(".").pop() ?? "") : "";
      if (baseName === "Annotated" || baseName === "Optional") {
        const tp = kids(t).find((k) => k.type === "type_parameter");
        return pyTypeName(tp ? (kids(tp)[0] ?? null) : null);
      }
      return baseName;
    }
    case "subscript": {
      const baseName = exprPath(t.childForFieldName("value")).split(".").pop() ?? "";
      if (baseName === "Annotated" || baseName === "Optional") return pyTypeName(t.childrenForFieldName("subscript")[0] ?? null);
      return baseName;
    }
    case "binary_operator":
      return pyTypeName(t.childForFieldName("left"));
    default:
      return t.text;
  }
}

function isDependsCall(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  return !!u && isCall(u) && /^(?:fastapi\.)?(?:Depends|Security)$/.test(calleePath(u));
}

function annotatedHasDepends(t: SyntaxNode | null): boolean {
  if (!t) return false;
  let hit = false;
  walk(t, (n) => {
    if (hit) return false;
    if (isDependsCall(n)) hit = true;
    return !hit;
  });
  return hit && /Annotated/.test(t.text);
}

/** A FastAPI parameter that is a dependency (`= Depends(x)`, `Annotated[T, Depends(x)]`, or an alias of that). */
export function isPyDependency(ctx: ProjectContext, pf: ParsedFile, unitRoot: string, info: { type: SyntaxNode | null; default: SyntaxNode | null }): boolean {
  if (isDependsCall(info.default)) return true;
  if (!info.type) return false;
  if (annotatedHasDepends(info.type)) return true;
  const t = kids(info.type)[0] ?? info.type;
  if (t.type !== "identifier") return false;
  const local = topLevel(pf).get(t.text);
  if (local) return annotatedHasDepends(local.value);
  const imp = importOf(pf, t.text);
  if (imp && imp.imported !== "*") {
    const r = resolvePyBinding(ctx, pf.file, imp.source, imp.imported, imp.level, unitRoot);
    const tpf = r?.attr ? ctx.parse(r.file) : null;
    const decl = tpf && r?.attr ? topLevel(tpf).get(r.attr) : null;
    if (decl) return annotatedHasDepends(decl.value);
  }
  return false;
}

function pyInputs(ctx: ProjectContext, e: InventoryEntry, ref: HandlerRef, m: RequestModel): void {
  const pyd = modelIndex(ctx).pydantic;
  for (const p of params(ref.node)) {
    const info = pyParam(p);
    if (!info || !info.name || info.name === "self" || e.internal.guardParams.includes(info.name)) continue;
    if (isPyDependency(ctx, ref.pf, e.internal.unit.root, info)) continue;
    const typeName = pyTypeName(info.type);
    if (PY_REQUEST.test(typeName)) {
      m.req.push(info.name);
      continue;
    }
    if (PY_SPECIAL.test(typeName)) continue;
    const dflt = unwrap(info.default);
    const bodyDefault = !!dflt && isCall(dflt) && /^(?:fastapi\.)?Body$/.test(calleePath(dflt));
    if (/^(?:dict|Dict|Any|Mapping|MutableMapping|object|Json)$/.test(typeName) || (bodyDefault && !info.type)) addRoot(m, info.name, "body");
    else if (pyd.has(typeName) || (typeName && !PY_SCALARS.has(typeName) && /^[A-Z]/.test(typeName))) {
      addRoot(m, info.name, "model");
      m.pyTypes.set(info.name, typeName);
    } else addRoot(m, info.name, bodyDefault ? "body" : "params");
  }
}

// ---------------------------------------------------------------- taint over request input

function startsPath(path: string, base: string): boolean {
  return path === base || path.startsWith(`${base}.`) || path.startsWith(`${base}[`);
}

/** Kind of client input an expression path reads directly, if any. */
export function sourceKind(m: RequestModel, path: string): InputKind | null {
  for (const r of m.req) {
    if (m.lang === "js") {
      if (startsPath(path, `${r}.body`)) return "body";
      if (startsPath(path, `${r}.params`)) return "params";
      if (startsPath(path, `${r}.query`)) return "query";
      if (path === `${r}.json()` || path === `${r}.formData()` || path === `${r}.text()`) return "body";
      if (startsPath(path, `${r}.nextUrl.searchParams`)) return "query";
    } else {
      if (path === `${r}.json()` || path === `${r}.form()` || path === `${r}.body()`) return "body";
      if (startsPath(path, `${r}.query_params`)) return "query";
      if (startsPath(path, `${r}.path_params`)) return "params";
    }
  }
  for (const c of m.ctxNames) if (startsPath(path, `${c}.params`)) return "params";
  if (m.lang === "js" && /\.searchParams\.get\(\)$/.test(path)) return "query";
  return null;
}

const MEMBERISH = new Set(["member_expression", "subscript_expression", "call_expression", "attribute", "subscript", "call"]);

/** Is this identifier node a reference (not a Python attribute name or keyword-argument name)? */
export function isReference(n: SyntaxNode): boolean {
  const p = n.parent;
  if (!p) return true;
  if (p.type === "attribute" && p.childForFieldName("attribute")?.id === n.id) return false;
  if (p.type === "keyword_argument" && p.childForFieldName("name")?.id === n.id) return false;
  return true;
}

/**
 * Intra-procedural tracking of client input through local variables. Values computed by a database call are
 * not tracked (the row loaded by a request ID is not itself request input).
 */
export class InputTaint {
  readonly locals = new Map<string, Set<InputKind>>();

  constructor(readonly m: RequestModel) {
    for (const [k, v] of m.roots) this.locals.set(k, new Set(v));
    for (let pass = 0; pass < 2; pass++) this.propagate();
  }

  private mark(names: readonly string[], kinds: ReadonlySet<InputKind>): void {
    for (const n of names) {
      const s = this.locals.get(n) ?? new Set<InputKind>();
      for (const k of kinds) s.add(k);
      this.locals.set(n, s);
    }
  }

  private propagate(): void {
    walk(this.m.fn, (n) => {
      if (n.type === "variable_declarator") {
        const name = n.childForFieldName("name");
        const value = unwrap(n.childForFieldName("value"));
        if (!name || !value) return true;
        // const { body, params } = req
        if (name.type === "object_pattern" && value.type === "identifier" && (this.m.req.includes(value.text) || this.m.ctxNames.includes(value.text))) {
          destructuredParts(name, (local, k) => this.mark([local], new Set([k])));
          return true;
        }
        if (isDbExpr(value)) return true;
        const k = this.kinds(value);
        if (k.size) this.mark(boundNames(name), k);
      } else if (n.type === "assignment_expression" || n.type === "assignment") {
        const left = n.childForFieldName("left");
        const right = unwrap(n.childForFieldName("right"));
        if (!left || !right || isDbExpr(right)) return true;
        const k = this.kinds(right);
        if (k.size) this.mark(assignedNames(left), k);
      }
      return true;
    });
  }

  /** Kinds of client input an expression depends on. */
  kinds(node: SyntaxNode | null): Set<InputKind> {
    const out = new Set<InputKind>();
    if (!node) return out;
    walk(node, (n) => {
      if (n.type === "identifier" || n.type === "shorthand_property_identifier") {
        if (isReference(n)) for (const k of this.locals.get(n.text) ?? []) out.add(k);
        return true;
      }
      if (MEMBERISH.has(n.type)) {
        const k = sourceKind(this.m, exprPath(n));
        if (k) {
          out.add(k);
          return false;
        }
      }
      return true;
    });
    return out;
  }

  has(node: SyntaxNode | null, wanted: readonly InputKind[]): boolean {
    const k = this.kinds(node);
    return wanted.some((w) => k.has(w));
  }
}

/** Names bound by an assignment target: `x`, Python `a, b`, JS destructuring assignment. */
export function assignedNames(left: SyntaxNode): string[] {
  if (left.type === "identifier") return [left.text];
  if (left.type === "pattern_list" || left.type === "tuple_pattern") return kids(left).filter((k) => k.type === "identifier").map((k) => k.text);
  if (left.type === "object_pattern" || left.type === "array_pattern") return boundNames(left);
  return [];
}

// ---------------------------------------------------------------- query chains

/** Calls along an expression's receiver chain, outermost first: `a.from().select().eq()` → [eq, select, from]. */
export function spine(n: SyntaxNode | null): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  let cur = unwrap(n);
  while (cur) {
    if (isCall(cur)) {
      out.push(cur);
      cur = unwrap(callee(cur));
      continue;
    }
    if (cur.type === "member_expression" || cur.type === "attribute") {
      cur = unwrap(cur.childForFieldName("object"));
      continue;
    }
    if (cur.type === "subscript_expression") {
      cur = unwrap(cur.childForFieldName("object"));
      continue;
    }
    break;
  }
  return out;
}

/** The outermost call of the method chain a call belongs to (`x.from().select()` inside `...eq().single()`). */
export function chainTop(call: SyntaxNode): SyntaxNode {
  let cur = call;
  for (;;) {
    const p = cur.parent;
    if (!p || (p.type !== "member_expression" && p.type !== "attribute") || p.childForFieldName("object")?.id !== cur.id) return cur;
    const gp = p.parent;
    if (!gp || !isCall(gp) || callee(gp)?.id !== p.id) return cur;
    cur = gp;
  }
}

/** SQLAlchemy query building: `<x>.query(...)`, `select(...)`, `<chain>.filter(...)` / `.where(...)` / `.filter_by(...)`. */
function isPyQueryCall(c: SyntaxNode): boolean {
  if (c.type !== "call") return false;
  const name = calleeName(c);
  if (name === "query" || name === "select") return true;
  if (name === "filter" || name === "where" || name === "filter_by") return spine(c).some((x) => x.id !== c.id && (calleeName(x) === "query" || calleeName(x) === "select"));
  if (["execute", "scalars", "scalar", "exec"].includes(name)) return positionalArgs(c).some((a) => spine(a).some((x) => calleeName(x) === "select"));
  return false;
}

/** Does the expression's receiver chain include a database call (classified, or a SQLAlchemy / Drizzle query)? */
export function isDbExpr(n: SyntaxNode | null): boolean {
  return spine(n).some((c) => classifyDbCall(c) !== null || isPyQueryCall(c) || (/\.(?:from|where)$/.test(calleePath(c)) && /select\(\)/.test(calleePath(c))));
}

// ---------------------------------------------------------------- user identity (section 8.3)

/** Calls to `fn` whose results are the signed-in user: guards, plus the project helper named in the entry's guard label. */
function guardHelperNames(e: InventoryEntry): string[] {
  const g = e.auth.guard ?? "";
  if (e.auth.via !== "handler" || !g.includes(" → ")) return [];
  return [g.split(" → ")[0]!.trim()];
}

/**
 * Identity expressions for ownership checks: section 8.3's values plus (DECISIONS) the session / user objects bound
 * from guard calls themselves, FastAPI guard parameters (`<param>` and `<param>.id`) and simple aliases
 * (`const ownerId = session.user.id`).
 */
export function identityNames(e: InventoryEntry, m: RequestModel, guards: GuardMatcher): string[] {
  const out = new Set<string>();
  const helpers = new Set(guardHelperNames(e));
  if (m.lang === "js") {
    for (const x of identityBindings(m.fn, e.framework, guards)) out.add(x);
    walk(m.fn, (n) => {
      if (n.type !== "variable_declarator") return true;
      const value = unwrap(n.childForFieldName("value"));
      const name = n.childForFieldName("name");
      if (!value || !name || !isCall(value)) return true;
      if (guards.guardCall(value, e.framework) || helpers.has(calleeName(value))) {
        if (name.type === "identifier") out.add(name.text);
        if (helpers.has(calleeName(value)) && name.type === "identifier") for (const s of ["id", "user.id", "userId", "sub"]) out.add(`${name.text}.${s}`);
        for (const b of boundNames(name)) if (!/^(?:error|err|e)$/.test(b)) out.add(b);
      }
      return true;
    });
  }
  for (const p of e.internal.guardParams) {
    out.add(p);
    out.add(`${p}.id`);
  }
  if (m.kind === "express" || m.kind === "pages") {
    // Objects that auth middleware fills in (passport / express-jwt / express-session / res.locals).
    for (const r of m.req) for (const x of ["user", "auth", "session.userId", "session.user"]) out.add(`${r}.${x}`);
    for (const r of m.res) for (const x of ["locals.user", "locals.userId"]) out.add(`${r}.${x}`);
  }
  // Aliases: const ownerId = session.user.id; const { id: uid } = session.user; owner_id = current_user.id
  for (let pass = 0; pass < 2; pass++) {
    walk(m.fn, (n) => {
      let left: SyntaxNode | null = null;
      let right: SyntaxNode | null = null;
      if (n.type === "variable_declarator") {
        left = n.childForFieldName("name");
        right = unwrap(n.childForFieldName("value"));
      } else if (n.type === "assignment") {
        left = n.childForFieldName("left");
        right = unwrap(n.childForFieldName("right"));
      }
      if (!left || !right) return true;
      const extras = [...out];
      if (isDbExpr(right)) {
        // A record loaded with an identity filter is the signed-in user's own record (DECISIONS).
        if (referencesIdentity(right.text, m.lang, extras)) for (const b of left.type === "identifier" ? [left.text] : assignedNames(left)) if (!/^(?:error|err|e)$/.test(b)) out.add(b);
        return true;
      }
      if (left.type === "identifier" && referencesIdentity(right.text, m.lang, extras) && !isFunction(right)) out.add(left.text);
      else if (left.type === "object_pattern") {
        for (const c of kids(left)) {
          const key = c.type === "shorthand_property_identifier_pattern" ? c.text : c.type === "pair_pattern" ? (c.childForFieldName("key")?.text ?? "") : "";
          if (!key || !referencesIdentity(`${right.text}.${key}`, m.lang, extras)) continue;
          if (c.type === "shorthand_property_identifier_pattern") out.add(c.text);
          else for (const b of boundNames(c.childForFieldName("value") ?? c)) out.add(b);
        }
      }
      return true;
    });
  }
  return [...out];
}

export function refsIdentity(node: SyntaxNode | null, m: RequestModel, extras: readonly string[]): boolean {
  return !!node && referencesIdentity(node.text, m.lang, extras);
}

const JS_LITERALS = new Set(["string", "number", "true", "false", "null", "undefined", "regex"]);
const PY_LITERALS = new Set(["string", "integer", "float", "true", "false", "none"]);

export function isLiteral(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  if (!u) return true;
  if (u.type === "identifier" && u.text === "undefined") return true;
  if (u.type === "template_string") return stringValue(u) !== null;
  return JS_LITERALS.has(u.type) || PY_LITERALS.has(u.type);
}

/**
 * Ownership evidence in a handler (section 8.3) other than the query filter: the loaded record's owner compared
 * with an identity value, or an `auth.ownershipHelpers` function called.
 */
export function handlerOwnership(m: RequestModel, extras: readonly string[], guards: GuardMatcher): boolean {
  if (callsOneLevel(m.fn, m.pf).some((c) => guards.isOwnershipHelper(calleeName(c)))) return true;
  let hit = false;
  const ident = (n: SyntaxNode | null) => refsIdentity(n, m, extras);
  walk(m.fn, (n) => {
    if (hit) return false;
    let sides: (SyntaxNode | null)[] = [];
    if (n.type === "binary_expression" && ["===", "!==", "==", "!="].includes(n.childForFieldName("operator")?.text ?? "")) {
      sides = [n.childForFieldName("left"), n.childForFieldName("right")];
    } else if (n.type === "comparison_operator") {
      const ops = n.children.filter((c) => !!c && !c.isNamed).map((c) => c!.text);
      if (ops.some((o) => o === "==" || o === "!=")) sides = kids(n);
    } else if (isCall(n) && calleeName(n) === "equals") {
      // Mongoose ObjectId: doc.owner.equals(req.user._id)
      const recv = callee(n)?.childForFieldName("object") ?? null;
      sides = [recv, positionalArgs(n)[0] ?? null];
    }
    if (sides.length === 2) {
      const a = sides[0] ?? null;
      const b = sides[1] ?? null;
      if ((ident(a) && !ident(b) && !isLiteral(b)) || (ident(b) && !ident(a) && !isLiteral(a))) hit = true;
    }
    return !hit;
  });
  return hit;
}

const ADMIN_NAME = /admin|superuser|staff/i;
/** Names of admin checks: requireAdmin, isAdmin, admin (middleware), adminOnly, get_current_active_superuser. Not createAdminClient(). */
const ADMIN_CHECK = /^(?:(?:require|ensure|assert|check|verify|is|has|must|only|get_current_active|get_current)_?(?:admin|superuser|staff)\w*|(?:admin|superuser|staff)(?:_?(?:only|required|guard|middleware))?)$/i;
const ROLE_CALL = /role|permission|authori[sz]e|scope|ability/i;
const ROLE_FIELD = /\.(?:role|roles|is_?admin|isStaff|is_staff|is_superuser|isSuperuser)\b/;

/**
 * An admin-level authorization check (DECISIONS: replaces the ownership check for api/missing-ownership):
 * middleware / dependencies / calls named like requireAdmin, requireRole("admin"), or `user.role === "admin"`.
 */
export function adminAuthorization(entries: readonly InventoryEntry[], m: RequestModel): boolean {
  for (const e of entries) {
    if (e.internal.middleware.some((mw) => ADMIN_CHECK.test(mw.name) || (ROLE_CALL.test(mw.name) && isCall(unwrap(mw.node)) && callArgsMention(unwrap(mw.node)!)))) return true;
    if ((e.auth.guard ?? "").split(/\s+→\s+|\s+\(/).some((g) => ADMIN_CHECK.test(g.trim()))) return true;
    // FastAPI: Depends(get_current_active_superuser) in the decorator or on a parameter.
    if (e.framework === "fastapi") {
      for (const scope of [e.internal.registration.node, m.fn.childForFieldName("parameters")]) {
        if (!scope) continue;
        let dep = false;
        walk(scope, (n) => {
          if (dep) return false;
          if (isCall(n) && /^(?:fastapi\.)?(?:Depends|Security)$/.test(calleePath(n))) {
            const target = positionalArgs(n)[0];
            if (target && ADMIN_CHECK.test(exprPath(target).split(".").pop() ?? "")) dep = true;
          }
          return !dep;
        });
        if (dep) return true;
      }
    }
  }
  let hit = false;
  walk(m.fn, (n) => {
    if (hit) return false;
    if (isCall(n)) {
      const name = calleeName(n);
      // requireAdmin(), authorize("admin"), user.roles.includes("admin")
      if (ADMIN_CHECK.test(name) || ((ROLE_CALL.test(name) || ROLE_FIELD.test(calleePath(n))) && callArgsMention(n))) hit = true;
    } else if (n.type === "binary_expression" || n.type === "comparison_operator") {
      const parts = n.type === "binary_expression" ? [n.childForFieldName("left"), n.childForFieldName("right")] : kids(n);
      if (parts.some((p) => !!p && ROLE_FIELD.test(exprPath(p))) && parts.some((p) => !!p && ADMIN_NAME.test(stringValue(p) ?? ""))) hit = true;
    }
    return !hit;
  });
  return hit;
}

function callArgsMention(call: SyntaxNode): boolean {
  return positionalArgs(call).some((a) => ADMIN_NAME.test(stringValue(a) ?? "") || elementsMention(a));
}

function elementsMention(a: SyntaxNode): boolean {
  const u = unwrap(a);
  return !!u && (u.type === "array" || u.type === "list") && kids(u).some((k) => ADMIN_NAME.test(stringValue(k) ?? ""));
}

/** Route-level validation middleware (DECISIONS): validate(schema), validateBody(...), celebrate({...}). */
export function validationMiddleware(entries: readonly InventoryEntry[]): boolean {
  return entries.some((e) => e.internal.middleware.some((mw) => /valid|celebrate/i.test(mw.name)));
}

// ---------------------------------------------------------------- request body (mass assignment)

/** Is `n` the whole request body: `req.body`, `await req.json()`, a variable assigned from one, a rest of one, or a spread of one? */
export function isWholeBody(n: SyntaxNode | null, m: RequestModel, depth = 0): boolean {
  const u = unwrap(n);
  if (!u || depth > 3) return false;
  if (u.type === "object") {
    return kids(u).some((c) => c.type === "spread_element" && isWholeBody(kids(c)[0] ?? null, m, depth + 1));
  }
  const path = exprPath(u);
  const reqs = m.req.length ? m.req : ["req", "request"];
  for (const r of reqs) {
    if (path === `${r}.body` || path === `${r}.json()`) return true;
  }
  const isIdent = u.type === "identifier" || u.type === "shorthand_property_identifier";
  if (m.kind === "action") {
    // Server actions: a client-sent argument used whole, or Object.fromEntries(formData).
    if (isIdent && m.roots.has(u.text) && isTopLevelParam(m, u.text)) return true;
    if (path === "Object.fromEntries()" && isWholeBody(positionalArgs(u)[0] ?? null, m, depth + 1)) return true;
  }
  if (isIdent) {
    if (m.kind !== "action" && m.roots.get(u.text)?.has("body") && isTopLevelParam(m, u.text)) return true;
    const decl = declarationOf(m.fn, u.text, u);
    if (!decl) return false;
    if (decl.rest) return isWholeBody(decl.value, m, depth + 1);
    if (decl.direct) return isWholeBody(decl.value, m, depth + 1);
  }
  return false;
}

function isTopLevelParam(m: RequestModel, name: string): boolean {
  return params(m.fn).some((p) => boundNames(p).includes(name) && (paramPattern(p).type === "identifier" || m.kind !== "action"));
}

/**
 * The declaration of a local in a function before `at`: `const x = v` (direct) or `const { a, ...x } = v` (rest).
 * Python: `x = v`.
 */
export function declarationOf(fn: SyntaxNode, name: string, at: SyntaxNode): { value: SyntaxNode; direct: boolean; rest: boolean } | null {
  let found: { value: SyntaxNode; direct: boolean; rest: boolean } | null = null;
  walk(fn, (n) => {
    if (n.startIndex > at.startIndex) return false;
    if (n.type === "variable_declarator") {
      const nm = n.childForFieldName("name");
      const v = n.childForFieldName("value");
      if (nm && v) {
        if (nm.type === "identifier" && nm.text === name) found = { value: v, direct: true, rest: false };
        else if (nm.type === "object_pattern") {
          const rest = kids(nm).find((c) => c.type === "rest_pattern");
          if (rest && kids(rest)[0]?.text === name) found = { value: v, direct: false, rest: true };
        }
      }
    } else if (n.type === "assignment" || n.type === "assignment_expression") {
      const left = n.childForFieldName("left");
      const right = n.childForFieldName("right");
      if (left?.type === "identifier" && left.text === name && right) found = { value: right, direct: true, rest: false };
    }
    return true;
  });
  return found;
}

// ---------------------------------------------------------------- test templates (section 8.8)

export type TemplateVariant = "route" | "pages" | "action" | "middleware";

export interface TemplateTarget {
  unit: UnitInfo;
  framework: Framework;
  method?: string;
  path?: string;
  /** Next.js: the module to import (route file, pages API file, actions file or middleware). */
  file?: string;
  /** Next.js: the export to call (method name, "default", the action name, "middleware"). */
  exportName?: string;
  variant?: TemplateVariant;
}

const JS_EXT = /\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts)$/;

/** Import path from the suggested test location (tests/secor/) to a project file, without extension. */
export function importPathFrom(file: string): string {
  const rel = posix.relative("tests/secor", file.replace(JS_EXT, ""));
  return rel.startsWith(".") ? rel : `./${rel}`;
}

/** Template values come from the project: redact them (invariant 4) and keep them inside a double-quoted string. */
function quoteSafe(s: string): string {
  return redact(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/[\r\n]+/g, " ");
}

/** Express: the module that creates the app (`express()`) and the name it is exported under. */
export function expressApp(ctx: ProjectContext, unit: UnitInfo): { file: string; exportName: string } | null {
  for (const file of ctx.codeFiles(unit, "js")) {
    if (!/\bexpress\s*\(\s*\)/.test(ctx.read(file) ?? "")) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    let call: SyntaxNode | null = null;
    let varName = "";
    walk(pf.root, (n) => {
      if (call) return false;
      if (n.type === "variable_declarator") {
        const v = unwrap(n.childForFieldName("value"));
        if (v && isCall(v) && calleePath(v) === "express") {
          call = v;
          varName = n.childForFieldName("name")?.text ?? "app";
        }
      }
      return true;
    });
    if (!call) continue;
    const found = call as SyntaxNode;
    let exportName: string | null = null;
    for (const [name, value] of exportsOf(pf)) {
      const u = unwrap(value);
      if (u && (u.id === found.id || (u.type === "identifier" && u.text === varName))) {
        if (name !== "default") {
          exportName = name;
          break;
        }
        exportName ??= "default";
      }
    }
    return { file, exportName: exportName ?? varName };
  }
  return null;
}

/** FastAPI: dotted module and variable of the app (`app = FastAPI()`). */
export function fastapiApp(ctx: ProjectContext, unit: UnitInfo): { module: string; name: string } | null {
  for (const file of ctx.codeFiles(unit, "py")) {
    if (!/FastAPI\s*\(/.test(ctx.read(file) ?? "")) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const [name, d] of topLevel(pf)) {
      const v = unwrap(d.value);
      if (v && isCall(v) && /^(?:\w+\.)?FastAPI$/.test(calleePath(v))) {
        let rel = unit.root ? file.slice(unit.root.length + 1) : file;
        rel = rel.replace(/\.py$/, "").replace(/^src\//, "").replace(/\/__init__$/, "");
        return { module: rel.split("/").join("."), name };
      }
    }
  }
  return null;
}

/** Test-runner flag for Express templates: the project's vitest or jest (vitest when neither is listed). */
export function jsTestFlag(ctx: ProjectContext, unit: UnitInfo): "vitest" | "jest" {
  const manifests = [...unit.manifests, ...(ctx.detection?.roots.get("") ?? [])];
  if (hasDep(manifests, "npm", "vitest")) return "vitest";
  if (hasDep(manifests, "npm", "jest")) return "jest";
  return "vitest";
}

/** Fill the rule's test template for a finding (undefined when the rule has no template for the framework). */
export function testTemplate(ctx: ProjectContext, ruleId: string, id: string, t: TemplateTarget): string | undefined {
  const method = !t.method || t.method === "*" ? "GET" : t.method;
  const path = t.path ?? "/";
  if (t.framework === "express") {
    const app = expressApp(ctx, t.unit);
    const vars = { method, path: quoteSafe(path), importPath: quoteSafe(app ? importPathFrom(app.file) : "../../src/app"), handlerExport: app?.exportName ?? "app" };
    return renderTestTemplate(ruleId, "express", id, vars, new Set([jsTestFlag(ctx, t.unit)]));
  }
  if (t.framework === "nextjs") {
    const variant = t.variant ?? "route";
    const vars = { method: variant === "action" ? "action" : method, path: quoteSafe(path), importPath: quoteSafe(t.file ? importPathFrom(t.file) : "../../app/route"), handlerExport: t.exportName ?? method };
    return renderTestTemplate(ruleId, "nextjs", id, vars, new Set([variant]));
  }
  if (t.framework === "fastapi") {
    const app = fastapiApp(ctx, t.unit);
    const vars = { method, path: quoteSafe(path), importPath: redact(app?.module ?? "main"), handlerExport: app?.name ?? "app" };
    return renderTestTemplate(ruleId, "fastapi", id, vars);
  }
  return undefined;
}

/** Template target for an entry point. */
export function entryTarget(e: InventoryEntry): TemplateTarget {
  const kind = handlerKind(e);
  if (e.framework !== "nextjs") return { unit: e.internal.unit, framework: e.framework, method: e.method, path: e.path };
  if (kind === "action") {
    const exportName = (e.name ?? "").split("#").pop() ?? "action";
    return { unit: e.internal.unit, framework: "nextjs", method: "action", path: e.name ?? "", file: e.file, exportName, variant: "action" };
  }
  if (kind === "pages") return { unit: e.internal.unit, framework: "nextjs", method: e.method, path: e.path, file: e.file, exportName: "default", variant: "pages" };
  return { unit: e.internal.unit, framework: "nextjs", method: e.method, path: e.path, file: e.file, exportName: e.method ?? "GET", variant: "route" };
}
