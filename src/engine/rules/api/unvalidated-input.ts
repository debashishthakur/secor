// api/unvalidated-input (spec section 8.5): request body fields reach a database write and the handler calls
// no schema validation. Writes already reported by api/mass-assignment (same handler and call) are skipped.

import { anchorText, callee, calleeName, calleePath, callsIn, endLine, exprPath, importOf, isNew, line, positionalArgs } from "../../ast.js";
import { callsOneLevel, classifyDbCall } from "../../auth-guards.js";
import type { InventoryEntry } from "../../inventory-types.js";
import { type ModelIndex, modelIndex } from "../../models.js";
import type { SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";
import { InputTaint, type RequestModel, apiEntries, entryFor, handlerUses, requestModel, validationMiddleware } from "./common.js";
import { jsMassWrites, writtenData } from "./mass-assignment.js";

const ID = "api/unvalidated-input";
const WHY = "Request body fields reach the database without schema validation, so unexpected types, sizes and values are stored.";
const FIX = "Parse the body with a schema first.";

const SCHEMA_PARSE = new Set(["parse", "safeParse", "parseAsync", "safeParseAsync", "spa"]);
const SCHEMA_VALIDATE = new Set(["validate", "validateSync", "validateAsync", "validateOrReject", "validationResult"]);
/** `.parse(` receivers that are not schema libraries. */
const NOT_A_SCHEMA = /^(?:JSON|Date|qs|querystring|url|URL|path|cookie|cookies|yaml|YAML|toml|TOML|csv|Papa|marked|chrono|dayjs|moment|Number|BigInt|devalue|superjson|SuperJSON)$/;
const PY_VALIDATE = new Set(["model_validate", "model_validate_json", "parse_obj", "parse_raw", "validate_python", "validate_json"]);

/** zod .parse/.safeParse, valibot parse(, yup / joi .validate(, class-validator validate(, express-validator, validation middleware. */
function jsValidates(m: RequestModel, entries: readonly InventoryEntry[]): boolean {
  for (const c of callsOneLevel(m.fn, m.pf)) {
    const name = calleeName(c);
    const path = calleePath(c);
    if (SCHEMA_PARSE.has(name)) {
      if (path.includes(".")) {
        const recv = path.slice(0, path.lastIndexOf("."));
        if (!NOT_A_SCHEMA.test(recv)) return true;
      } else if (/^valibot(?:\/|$)/.test(importOf(m.pf, name)?.source ?? "")) return true;
    }
    if (SCHEMA_VALIDATE.has(name)) return true;
  }
  return validationMiddleware(entries);
}

/** pydantic validation of a dict inside the handler: Model.model_validate(data), Model(**data) for a pydantic Model. */
function pyValidates(m: RequestModel, index: ModelIndex): boolean {
  return callsIn(m.fn).some((c) => PY_VALIDATE.has(calleeName(c)) || (calleePath(c) === calleeName(c) && index.pydantic.has(calleeName(c))));
}

export const unvalidatedInput = defineRule({
  id: ID,
  title: "Request body used without validation",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspApi,
  appliesTo: (ctx) => apiEntries(ctx).some((e) => e.writesDb),
  check(ctx, emit) {
    const index = modelIndex(ctx);
    for (const use of handlerUses(apiEntries(ctx).filter((e) => e.writesDb))) {
      const first = use.entries[0]!;
      const m = requestModel(ctx, first, use.ref);
      if (m.lang === "js" ? jsValidates(m, use.entries) : pyValidates(m, index)) continue;
      const taint = new InputTaint(m);
      const mass = new Set((m.lang === "js" ? jsMassWrites(m) : []).map((w) => w.node.id));
      const calls = callsIn(m.fn);
      const hasSave = calls.some((c) => calleeName(c) === "save" && positionalArgs(c).length === 0);
      const seen = new Set<number>();
      for (const c of calls) {
        if (mass.has(c.id) || seen.has(c.id)) continue;
        let data: SyntaxNode[] = [];
        const d = classifyDbCall(c);
        if (d && d.op === "write") {
          if (m.lang === "js") data = writtenData(d);
          else data = d.dataArg ? [d.dataArg] : positionalArgs(c);
        } else if (m.lang === "js" && hasSave && isNew(c) && /^[A-Z]\w*$/.test(exprPath(callee(c)))) {
          // Mongoose: new Model({...}) followed by .save()
          data = positionalArgs(c);
        }
        if (!data.some((x) => taint.has(x, ["body"]))) continue;
        seen.add(c.id);
        const e = entryFor(use, c);
        emit({
          severity: "medium",
          service: "api",
          file: use.ref.file,
          line: line(c),
          endLine: endLine(c),
          anchor: anchorText(c),
          evidence: anchorText(c),
          why: WHY,
          fix: { summary: FIX },
          entryPointId: e.id,
        });
      }
    }
  },
});
