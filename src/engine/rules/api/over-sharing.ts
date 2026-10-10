// api/over-sharing (spec section 8.5): a handler returns the direct result of a database read with no
// field selection, and the model has a sensitive field (password, hash, token, ...). Unknown model → no finding.

import {
  anchorText,
  boundNames,
  calleeName,
  calleePath,
  callsIn,
  descendants,
  endLine,
  exprPath,
  isCall,
  isFunction,
  isNew,
  kids,
  kwarg,
  line,
  objectProps,
  positionalArgs,
  prop,
  stringValue,
  unwrap,
  walk,
} from "../../ast.js";
import { classifyDbCall } from "../../auth-guards.js";
import { type ModelIndex, type ModelInfo, modelIndex, sensitiveFields } from "../../models.js";
import type { SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";
import { type RequestModel, apiEntries, entryFor, entryKey, handlerUses, pyTypeName, requestModel, spine } from "./common.js";

const ID = "api/over-sharing";
const WHY = "The response sends the whole database row to the client, including sensitive fields such as password hashes, tokens or keys.";
const FIX = "Select only the fields the client needs, or set a FastAPI response_model.";

interface RowRead {
  read: SyntaxNode;
  model: ModelInfo;
}

/** Values a handler sends back: res.json/res.send, NextResponse.json/Response.json, FastAPI `return x`. */
function responseValues(m: RequestModel, decorator: SyntaxNode | null, index: ModelIndex): { sink: SyntaxNode; value: SyntaxNode }[] {
  const out: { sink: SyntaxNode; value: SyntaxNode }[] = [];
  if (m.lang === "py") {
    const call = decorator ? kids(decorator)[0] : null;
    const rm = call && isCall(call) ? kwarg(call, "response_model") : null;
    if (rm && rm.type !== "none") return [];
    if (filtersByReturnType(m.fn.childForFieldName("return_type"), index)) return [];
    walk(m.fn, (n) => {
      if (n.id !== m.fn.id && isFunction(n)) return false;
      if (n.type === "return_statement") {
        const v = kids(n)[0];
        if (v) out.push({ sink: n, value: v });
      }
      return true;
    });
    return out;
  }
  const resNames = m.res.length ? m.res : ["res"];
  for (const c of callsIn(m.fn)) {
    if (isNew(c)) {
      // new Response(JSON.stringify(x)) / new NextResponse(JSON.stringify(x))
      if (!/^(?:Next)?Response$/.test(calleePath(c).replace(/^new /, "").replace(/\(\)$/, ""))) continue;
      const first = unwrap(positionalArgs(c)[0] ?? null);
      if (first && isCall(first) && calleePath(first) === "JSON.stringify") {
        const v = positionalArgs(first)[0];
        if (v) out.push({ sink: c, value: v });
      }
      continue;
    }
    const path = calleePath(c);
    const v = positionalArgs(c)[0];
    if (!v) continue;
    if (path === "NextResponse.json" || path === "Response.json") out.push({ sink: c, value: v });
    else if (resNames.some((r) => new RegExp(`^${r.replace(/\$/g, "\\$")}(?:\\.\\w+\\(\\))*\\.(?:json|send|jsonp)$`).test(path))) out.push({ sink: c, value: v });
  }
  return out;
}

/** A return annotation that FastAPI uses as the response model (a pydantic class, or a list of one). */
function filtersByReturnType(rt: SyntaxNode | null, index: ModelIndex): boolean {
  if (!rt) return false;
  const name = pyTypeName(rt);
  if (index.pydantic.has(name)) return true;
  if (/^(?:list|List|Sequence|Iterable)$/.test(name)) {
    const inner = rt.descendantsOfType("identifier").map((n) => n?.text ?? "");
    return inner.some((n) => index.pydantic.has(n));
  }
  return false;
}

/** Database reads a returned value comes straight from (through locals and object / dict wrappers). */
function rowReads(v: SyntaxNode | null, m: RequestModel, index: ModelIndex, depth = 0): RowRead[] {
  const u = unwrap(v);
  if (!u || depth > 3) return [];
  if (u.type === "object" || u.type === "dictionary") {
    const props = objectProps(u);
    const explicit = new Set(props.map((p) => p.key));
    // { ...user } copies the whole row unless the sensitive keys are overwritten ({ ...user, passwordHash: undefined }).
    const spreads = kids(u)
      .filter((c) => c.type === "spread_element" || c.type === "dictionary_splat")
      .flatMap((c) => rowReads(kids(c)[0] ?? null, m, index, depth + 1))
      .filter((r) => sensitiveFields(r.model).some((f) => !explicit.has(f)));
    return [...props.flatMap((p) => rowReads(p.value, m, index, depth + 1)), ...spreads];
  }
  if (u.type === "identifier" || u.type === "shorthand_property_identifier") return rowReads(localValue(m, u), m, index, depth + 1);
  const direct = readOf(u, m, index);
  return direct ? [direct] : [];
}

/** The value a local was assigned (JS `const x = v`, `const { data: x } = v` for Supabase results; Python `x = v`). */
function localValue(m: RequestModel, id: SyntaxNode): SyntaxNode | null {
  let found: SyntaxNode | null = null;
  walk(m.fn, (n) => {
    if (n.startIndex > id.startIndex) return false;
    if (n.type === "variable_declarator") {
      const name = n.childForFieldName("name");
      const value = n.childForFieldName("value");
      if (!name || !value) return true;
      if (name.type === "identifier" && name.text === id.text) found = value;
      else if (name.type === "object_pattern") {
        for (const c of kids(name)) {
          const key = c.type === "shorthand_property_identifier_pattern" ? c.text : c.type === "pair_pattern" ? (c.childForFieldName("key")?.text ?? "") : "";
          const locals = c.type === "pair_pattern" ? boundNames(c.childForFieldName("value") ?? c) : [c.text];
          if (key === "data" && locals.includes(id.text)) found = value;
        }
      }
    } else if (n.type === "assignment") {
      const left = n.childForFieldName("left");
      if (left?.type === "identifier" && left.text === id.text) found = n.childForFieldName("right");
    }
    return true;
  });
  return found;
}

function readOf(expr: SyntaxNode, m: RequestModel, index: ModelIndex): RowRead | null {
  const chain = spine(expr);
  if (m.lang === "py") return pyRead(expr, chain, index);
  for (const c of chain) {
    const path = calleePath(c);
    const name = calleeName(c);
    const d = classifyDbCall(c);
    // Drizzle relational: db.query.<table>.findFirst/findMany({ columns })
    const rel = /(?:^|\.)query\.(\w+)\.(?:findFirst|findMany)$/.exec(path);
    if (rel) {
      const model = index.drizzle.get(rel[1]!);
      if (!model || prop(positionalArgs(c)[0] ?? null, "columns")) return null;
      return { read: c, model };
    }
    if (d?.orm === "prisma" && d.op === "read") {
      const segs = path.split(".");
      const model = index.prisma.get((segs[segs.length - 2] ?? "").toLowerCase());
      const opts = positionalArgs(c)[0] ?? null;
      if (!model || prop(opts, "select") || prop(opts, "omit")) return null;
      if (opts && unwrap(opts)?.type !== "object") return null;
      return { read: c, model };
    }
    if (d?.orm === "supabase" && d.verb === "select") {
      const from = spine(c).find((x) => calleeName(x) === "from");
      const table = stringValue(positionalArgs(from ?? c)[0] ?? null);
      const model = table ? index.supabase.get(table.toLowerCase()) : undefined;
      const cols = positionalArgs(c)[0];
      const colText = cols ? stringValue(cols) : "";
      if (!model || colText === null || (colText !== "" && !/(?:^|,)\s*\*\s*(?:,|$)/.test(colText))) return null;
      return { read: c, model };
    }
    if (d?.orm === "mongoose" && d.op === "read" && ["findById", "findOne", "find"].includes(name)) {
      const model = index.mongoose.get(path.split(".")[0] ?? "");
      if (!model || model.serializerFiltered) return null;
      if (positionalArgs(c).length >= 2 || chain.some((x) => calleeName(x) === "select")) return null;
      return { read: c, model };
    }
    // Drizzle: db.select().from(table) with no column list
    if (name === "from" && /\.select\(\)\.from$/.test(path)) {
      const sel = spine(c).find((x) => calleeName(x) === "select");
      const table = unwrap(positionalArgs(c)[0] ?? null);
      const model = table?.type === "identifier" ? index.drizzle.get(table.text) : undefined;
      if (!model || !sel || positionalArgs(sel).length > 0) return null;
      return { read: c, model };
    }
  }
  return null;
}

function pyRead(expr: SyntaxNode, chain: SyntaxNode[], index: ModelIndex): RowRead | null {
  for (const c of chain) {
    const d = classifyDbCall(c);
    if (d?.orm === "sqlalchemy" && d.verb === "get") {
      const arg = unwrap(positionalArgs(c)[0] ?? null);
      const model = arg?.type === "identifier" ? index.sqlalchemy.get(arg.text) : undefined;
      return model ? { read: c, model } : null;
    }
    if (calleeName(c) === "query") return modelArg(c, index);
  }
  // select(Model) anywhere in the expression (SQLAlchemy 2.0 / SQLModel): session.execute(select(User)).scalar_one()
  for (const c of [expr, ...descendants(expr, "call")]) {
    if (isCall(c) && calleeName(c) === "select" && exprPath(c) === "select()") {
      const r = modelArg(c, index);
      if (r) return r;
    }
  }
  return null;
}

/** `query(Model)` / `select(Model)` with one model argument (column lists are a field selection). */
function modelArg(c: SyntaxNode, index: ModelIndex): RowRead | null {
  const a = positionalArgs(c);
  if (a.length !== 1) return null;
  const arg = unwrap(a[0]!);
  const model = arg?.type === "identifier" ? index.sqlalchemy.get(arg.text) : undefined;
  return model ? { read: c, model } : null;
}

export const overSharing = defineRule({
  id: ID,
  title: "Whole database row returned",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspApi,
  appliesTo: (ctx) => ctx.hasUnit("api") && modelIndex(ctx).count > 0,
  check(ctx, emit) {
    const index = modelIndex(ctx);
    const entries = apiEntries(ctx).filter((e) => e.kind === "http_route");
    for (const use of handlerUses(entries)) {
      const first = use.entries[0]!;
      const m = requestModel(ctx, first, use.ref);
      const decorator = first.framework === "fastapi" ? first.internal.registration.node : null;
      const reported = new Set<number>();
      for (const { sink, value } of responseValues(m, decorator, index)) {
        if (reported.has(sink.id)) continue;
        const hit = rowReads(value, m, index).find((r) => sensitiveFields(r.model).length > 0);
        if (!hit) continue;
        reported.add(sink.id);
        const fields = sensitiveFields(hit.model);
        const e = entryFor(use, sink);
        emit({
          severity: "high",
          service: "api",
          file: use.ref.file,
          line: line(sink),
          endLine: endLine(sink),
          anchor: `${entryKey(e)} ${anchorText(sink)} ${hit.model.name}`,
          evidence: `${anchorText(sink)} returns ${hit.model.name} with ${fields.slice(0, 3).join(", ")}`,
          why: WHY,
          fix: { summary: FIX },
          entryPointId: e.id,
        });
      }
    }
  },
});
