// api/mass-assignment (spec section 8.5): the request body is written to the database as-is.
// JS: a create / update / insert / upsert whose data is req.body, await req.json(), a variable assigned from one,
// or a spread of one. FastAPI: Model(**payload.dict()) / payload.model_dump() where the input model has a
// privileged field (role, is_admin, owner_id, ...).

import { anchorText, callee, calleeName, callsIn, endLine, exprPath, isNew, kwarg, line, positionalArgs, prop, unwrap } from "../../ast.js";
import { type DbCall, classifyDbCall } from "../../auth-guards.js";
import { findingId } from "../../finding.js";
import { type ModelIndex, modelIndex, pydanticFields } from "../../models.js";
import type { SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";
import { type RequestModel, apiEntries, entryFor, entryTarget, handlerUses, isWholeBody, requestModel, testTemplate, validationMiddleware } from "./common.js";

const ID = "api/mass-assignment";
const WHY = "The request body is written to the database as-is, so a caller can set fields they should not control, such as a role, a plan or an owner ID.";
const FIX = "Validate with a schema and copy only allowed fields.";

export const PRIVILEGED_FIELD = /^(?:role|roles|is_?admin|admin|permissions?|owner_?id|user_?id|plan|tier|credits?|balance|is_?verified|email_?verified)$/i;

const WRITE_VERBS = new Set(["create", "createMany", "createManyAndReturn", "update", "updateMany", "updateManyAndReturn", "upsert", "insert", "insertMany", "findByIdAndUpdate", "findOneAndUpdate", "updateOne", "replaceOne", "raw"]);

/** The data a JS database write stores (Prisma: the `data` / `create` / `update` properties of the first argument). */
export function writtenData(d: DbCall): SyntaxNode[] {
  if (d.op !== "write" || !WRITE_VERBS.has(d.verb)) return [];
  if (d.orm === "prisma") return ["data", "create", "update"].map((k) => prop(d.dataArg, k)).filter((x): x is SyntaxNode => !!x);
  if (d.orm === "mongoose" && d.dataArg) {
    // Update operators: { $set: req.body }
    const ops = ["$set", "$setOnInsert"].map((k) => prop(d.dataArg, k)).filter((x): x is SyntaxNode => !!x);
    return [d.dataArg, ...ops];
  }
  return d.dataArg ? [d.dataArg] : [];
}

export interface MassWrite {
  /** The write call (or `new Model(...)` followed by `.save()`). */
  node: SyntaxNode;
  data: SyntaxNode;
}

/** JS writes whose data is the whole request body (section 8.5). Shared with api/unvalidated-input for its dedupe. */
export function jsMassWrites(m: RequestModel): MassWrite[] {
  const out: MassWrite[] = [];
  const calls = callsIn(m.fn);
  for (const c of calls) {
    const d = classifyDbCall(c);
    if (!d) continue;
    for (const data of writtenData(d)) {
      if (isWholeBody(data, m)) {
        out.push({ node: c, data });
        break;
      }
    }
  }
  // Mongoose: new Model(req.body) followed by .save() (DECISIONS)
  if (calls.some((c) => calleeName(c) === "save" && positionalArgs(c).length === 0)) {
    for (const c of calls) {
      if (!isNew(c) || !/^[A-Z]\w*$/.test(exprPath(callee(c)))) continue;
      const data = positionalArgs(c)[0];
      if (data && isWholeBody(data, m)) out.push({ node: c, data });
    }
  }
  return out;
}

/** FastAPI: `Model(**payload.dict())` / `payload.model_dump()` where payload's pydantic model has a privileged field. */
function pyMassWrites(m: RequestModel, index: ModelIndex): { node: SyntaxNode; fields: string[] }[] {
  const out: { node: SyntaxNode; fields: string[] }[] = [];
  const privileged = new Map<string, string[]>();
  for (const [param, type] of m.pyTypes) {
    const fields = (pydanticFields(index, type) ?? []).filter((f) => PRIVILEGED_FIELD.test(f));
    if (fields.length) privileged.set(param, fields);
  }
  if (!privileged.size) return out;
  for (const c of callsIn(m.fn)) {
    const name = calleeName(c);
    if (name !== "dict" && name !== "model_dump") continue;
    const recv = unwrap(callee(c)?.childForFieldName("object") ?? null);
    const fields = recv?.type === "identifier" ? privileged.get(recv.text) : undefined;
    if (!fields || kwarg(c, "include") || kwarg(c, "exclude")) continue;
    // Report the constructor for `Model(**payload.dict())`, else the dump call itself.
    const splat = c.parent?.type === "dictionary_splat" ? c.parent : null;
    const ctor = splat?.parent?.type === "argument_list" ? splat.parent.parent : null;
    out.push({ node: ctor ?? c, fields });
  }
  return out;
}

export const massAssignment = defineRule({
  id: ID,
  title: "Request body written straight to the database",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspApi,
  appliesTo: (ctx) => apiEntries(ctx).some((e) => e.writesDb),
  check(ctx, emit) {
    const index = modelIndex(ctx);
    for (const use of handlerUses(apiEntries(ctx).filter((e) => e.writesDb))) {
      const first = use.entries[0]!;
      const m = requestModel(ctx, first, use.ref);
      // Validation middleware on the route replaces req.body with the parsed, allow-listed value (DECISIONS).
      if (m.lang === "js" && validationMiddleware(use.entries)) continue;
      const hits: { node: SyntaxNode; evidence: string }[] =
        m.lang === "js"
          ? jsMassWrites(m).map((w) => ({ node: w.node, evidence: anchorText(w.node) }))
          : pyMassWrites(m, index).map((w) => ({ node: w.node, evidence: `${anchorText(w.node)} (input model has ${w.fields.join(", ")})` }));
      const seen = new Set<number>();
      for (const h of hits) {
        if (seen.has(h.node.id)) continue;
        seen.add(h.node.id);
        const e = entryFor(use, h.node);
        const anchor = anchorText(h.node);
        const id = findingId(ID, use.ref.file, anchor);
        emit({
          severity: "high",
          service: "api",
          file: use.ref.file,
          line: line(h.node),
          endLine: endLine(h.node),
          anchor,
          evidence: h.evidence,
          why: WHY,
          fix: { summary: FIX, testTemplate: testTemplate(ctx, ID, id, entryTarget(e)) },
          entryPointId: e.id,
        });
      }
    }
  },
});
