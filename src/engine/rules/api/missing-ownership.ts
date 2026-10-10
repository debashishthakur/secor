// api/missing-ownership (spec section 8.5): a guarded handler loads, updates or deletes a record by an ID
// taken from the request, and nothing ties the record to the signed-in user (section 8.3).

import { anchorText, callee, calleeName, calleePath, callsIn, closest, endLine, exprPath, isCall, kids, kwarg, line, positionalArgs, prop, resolveLocal, stringValue, walk } from "../../ast.js";
import { classifyDbCall, dbCallsIn } from "../../auth-guards.js";
import { findingId } from "../../finding.js";
import { guardMatcherFor } from "../../inventory.js";
import { modelIndex } from "../../models.js";
import type { SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";
import {
  ALL_INPUT,
  InputTaint,
  adminAuthorization,
  type RequestModel,
  apiEntries,
  chainTop,
  declarationOf,
  entryFor,
  entryTarget,
  handlerOwnership,
  handlerUses,
  identityNames,
  isReference,
  refsIdentity,
  requestModel,
  sourceKind,
  spine,
  testTemplate,
} from "./common.js";

const ID = "api/missing-ownership";
const WHY = "The record is looked up by an ID the caller controls, and nothing checks that it belongs to the signed-in user, so one user may read or change another user's data.";
const FIX = "Filter by the signed-in user's ID as well, or compare the record's owner before returning it.";

const PRISMA_BY_ID = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "update", "delete", "upsert"]);
const MONGOOSE_BY_ID = new Set(["findById", "findByIdAndUpdate", "findByIdAndDelete"]);

interface Lookup {
  /** The flagged call (the query). */
  node: SyntaxNode;
  /** Expression whose text is checked for an identity value (the query filter). */
  filter: SyntaxNode;
  /** Text of the request-controlled value used in the filter. */
  idText: string;
  /** Supabase table, for RLS. */
  table?: string;
}

/** First identifier / member expression under `n` that carries request input (pre-order: the largest such path). */
function taintedPart(n: SyntaxNode, taint: InputTaint): SyntaxNode | null {
  let found: SyntaxNode | null = null;
  walk(n, (x) => {
    if (found) return false;
    if ((x.type === "identifier" || x.type === "shorthand_property_identifier") && isReference(x) && taint.locals.has(x.text)) found = x;
    else if (MEMBER_TYPES.has(x.type) && sourceKind(taint.m, exprPath(x))) found = x;
    return !found;
  });
  return found;
}

const MEMBER_TYPES = new Set(["member_expression", "subscript_expression", "call_expression", "attribute", "subscript", "call"]);

function lookups(m: RequestModel, taint: InputTaint): Lookup[] {
  const out: Lookup[] = [];
  const seen = new Set<number>();
  const add = (node: SyntaxNode, filter: SyntaxNode, tainted: SyntaxNode | null, table?: string) => {
    if (!tainted || seen.has(node.id)) return;
    seen.add(node.id);
    out.push({ node, filter, idText: tainted.text, ...(table ? { table } : {}) });
  };
  for (const c of callsIn(m.fn)) {
    const name = calleeName(c);
    if (m.lang === "js") {
      const d = classifyDbCall(c);
      // Prisma <model>.(findUnique|findFirst|update|delete|upsert)({ where }) (also Drizzle relational queries)
      if (d?.orm === "prisma" && PRISMA_BY_ID.has(d.verb)) {
        const where = prop(positionalArgs(c)[0] ?? null, "where");
        if (where && taint.has(where, ALL_INPUT)) add(c, where, taintedPart(where, taint));
        continue;
      }
      // Mongoose findById / findByIdAndUpdate / findByIdAndDelete
      if (MONGOOSE_BY_ID.has(name)) {
        const first = positionalArgs(c)[0] ?? null;
        if (first && taint.has(first, ALL_INPUT)) add(c, first, taintedPart(first, taint));
        continue;
      }
      // Drizzle .where(eq(<table>.id, …))
      if (name === "eq" && calleePath(c) === "eq") {
        const [col, val] = positionalArgs(c);
        if (!col || !val || !/\.id$/.test(exprPath(col)) || !taint.has(val, ALL_INPUT)) continue;
        const whereCall = closestWhereCall(c);
        if (whereCall) add(chainTop(whereCall), argsNode(whereCall), taintedPart(val, taint));
        continue;
      }
      // Supabase .from(…).(select|update|delete)(…).eq('id', …)
      if (name === "eq" && calleePath(c).includes(".from()")) {
        const [col, val] = positionalArgs(c);
        if (stringValue(col ?? null) !== "id" || !val || !taint.has(val, ALL_INPUT)) continue;
        const chain = spine(c);
        if (!chain.some((x) => ["select", "update", "delete"].includes(calleeName(x)))) continue;
        const from = chain.find((x) => calleeName(x) === "from");
        const table = stringValue(positionalArgs(from ?? c)[0] ?? null) ?? undefined;
        const top = chainTop(c);
        add(top, top, taintedPart(val, taint), table);
      }
    } else {
      // SQLAlchemy session.get(Model, id)
      const d = classifyDbCall(c);
      if (d?.orm === "sqlalchemy" && d.verb === "get") {
        const idArg = positionalArgs(c)[1] ?? null;
        if (idArg && taint.has(idArg, ALL_INPUT)) add(c, idArg, taintedPart(idArg, taint));
        continue;
      }
      // Legacy SQLAlchemy: db.query(Model).get(id)
      if (name === "get" && spine(c).some((x) => x.id !== c.id && calleeName(x) === "query")) {
        const idArg = positionalArgs(c)[0] ?? null;
        if (idArg && taint.has(idArg, ALL_INPUT)) add(chainTop(c), idArg, taintedPart(idArg, taint));
        continue;
      }
      // .filter(Model.id == id) / .where(Model.id == id) / .filter_by(id=id) on a query
      if ((name === "filter" || name === "where" || name === "filter_by") && spine(c).some((x) => x.id !== c.id && (calleeName(x) === "query" || calleeName(x) === "select"))) {
        let tainted: SyntaxNode | null = null;
        if (name === "filter_by") {
          const v = kwarg(c, "id");
          if (v && taint.has(v, ALL_INPUT)) tainted = taintedPart(v, taint);
        } else {
          for (const a of positionalArgs(c)) {
            walk(a, (x) => {
              if (tainted) return false;
              if (x.type !== "comparison_operator" || !x.children.some((o) => !!o && !o.isNamed && o.text === "==")) return true;
              const sides = kids(x);
              const idSide = sides.findIndex((s) => /\.id$/.test(exprPath(s)));
              const other = idSide >= 0 ? sides[1 - idSide] : undefined;
              if (other && taint.has(other, ALL_INPUT)) tainted = taintedPart(other, taint);
              return false;
            });
          }
        }
        if (tainted) {
          const top = chainTop(c);
          add(top, top, tainted);
        }
      }
    }
  }
  return out;
}

function argsNode(call: SyntaxNode): SyntaxNode {
  return call.childForFieldName("arguments") ?? call;
}

/** The `.where(...)` call whose arguments contain `n`. */
function closestWhereCall(n: SyntaxNode): SyntaxNode | null {
  for (let p = closest(n, ["call_expression"]); p; p = closest(p, ["call_expression"])) {
    if (calleeName(p) === "where" && calleePath(p).includes(".")) {
      const a = p.childForFieldName("arguments");
      if (a && n.startIndex >= a.startIndex && n.endIndex <= a.endIndex) return p;
    }
  }
  return null;
}

export const missingOwnership = defineRule({
  id: ID,
  title: "Record loaded by ID without an ownership check",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspApi,
  appliesTo: (ctx) =>
    apiEntries(ctx).some((e) => e.auth.guarded && e.internal.handlers.some((h) => dbCallsIn(h.node, h.pf).length > 0 || /\.(?:filter|where|filter_by|eq)\s*\(|findById/.test(h.node.text))),
  check(ctx, emit) {
    const guards = guardMatcherFor(ctx);
    const rls = modelIndex(ctx).rlsTables;
    const entries = apiEntries(ctx).filter((e) => e.auth.guarded);
    for (const use of handlerUses(entries)) {
      const first = use.entries[0]!;
      const m = requestModel(ctx, first, use.ref);
      const taint = new InputTaint(m);
      const found = lookups(m, taint);
      if (!found.length) continue;
      const extras = identityNames(first, m, guards);
      if (handlerOwnership(m, extras, guards) || adminAuthorization(use.entries, m)) continue;
      const allCalls = callsIn(m.fn);
      for (const l of found) {
        if (refsIdentity(l.filter, m, extras)) continue;
        if (l.table && rls.has(l.table.toLowerCase()) && !serviceRoleClient(m, l.node)) continue;
        // Ownership checked by another query on the same ID (e.g. findFirst({ where: { id, userId } }) before update).
        const idRe = new RegExp(`(?<![\\w.$])${l.idText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w$])`);
        const otherCheck = allCalls.some((c) => c.id !== l.node.id && !isInsideNode(c, l.node) && isQueryish(c) && idRe.test(c.text) && refsIdentity(c, m, extras));
        if (otherCheck) continue;
        const e = entryFor(use, l.node);
        const anchor = anchorText(l.node);
        const id = findingId(ID, use.ref.file, anchor);
        emit({
          severity: "high",
          advisory: true,
          service: "api",
          file: use.ref.file,
          line: line(l.node),
          endLine: endLine(l.node),
          anchor,
          evidence: anchor,
          why: WHY,
          fix: { summary: FIX, testTemplate: testTemplate(ctx, ID, id, entryTarget(e)) },
          entryPointId: e.id,
        });
      }
    }
  },
});

const SERVICE_ROLE = /service[_-]?role|createAdminClient|createServiceClient|supabaseAdmin|adminClient|serviceClient/i;

/** A Supabase query on a service-role / admin client bypasses RLS (DECISIONS: no RLS credit then). */
function serviceRoleClient(m: RequestModel, query: SyntaxNode): boolean {
  const chain = spine(query);
  const from = chain.find((x) => calleeName(x) === "from");
  const recv = from ? (callee(from)?.childForFieldName("object") ?? null) : null;
  if (!recv) return false;
  if (SERVICE_ROLE.test(recv.text)) return true;
  if (recv.type !== "identifier") return false;
  const decl = declarationOf(m.fn, recv.text, query)?.value ?? resolveLocal(m.pf, recv.text, query);
  return !!decl && SERVICE_ROLE.test(decl.text);
}

function isInsideNode(n: SyntaxNode, container: SyntaxNode): boolean {
  return n.startIndex >= container.startIndex && n.endIndex <= container.endIndex;
}

/** A call that looks like a query (classified DB call, or a filter / where / eq / get in a chain). */
function isQueryish(c: SyntaxNode): boolean {
  if (!isCall(c)) return false;
  if (classifyDbCall(c)) return true;
  return ["filter", "where", "filter_by", "eq", "match", "findOne", "findFirst", "get"].includes(calleeName(c));
}
