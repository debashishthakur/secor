// api/sql-injection-risk (spec section 8.5): SQL text built from strings in api units.
// JS: query( / execute( / raw( / $queryRawUnsafe( / $executeRawUnsafe( / sql.unsafe( / knex.raw( / sequelize.query(
// with a template literal containing ${…} or a + concatenation with a non-literal.
// Python: execute( / executemany( / SQLAlchemy text( with an f-string, % formatting, .format( or +.
// Tagged templates (Prisma $queryRaw`…`, sql`…`) are the parameterised form and are not findings.

import {
  anchorText,
  callee,
  calleeName,
  calleePath,
  callsIn,
  enclosingFunction,
  endLine,
  functionBody,
  importOf,
  isCall,
  kids,
  line,
  positionalArgs,
  resolveLocal,
  unwrap,
  walk,
} from "../../ast.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";

const ID = "api/sql-injection-risk";
const WHY = "The SQL text is built from strings with values inserted into it, so request input can change the query (SQL injection).";
const FIX = "Use parameters or the tagged-template form.";

const JS_SINKS = new Set(["query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe"]);
const PY_SINKS = new Set(["execute", "executemany"]);
/** Static text must look like SQL (DECISIONS: keeps `execute(`${dir}/x`)` and similar non-SQL calls out). */
const SQL_WORDS = /\b(?:select|insert|update|delete|from|where|values|into|join|union|order\s+by|group\s+by|drop|alter|truncate|returning)\b/i;

interface Built {
  dynamic: boolean;
  staticText: string;
}

function literalText(n: SyntaxNode): string | null {
  if (n.type === "string") return kids(n).filter((k) => ["string_fragment", "string_content", "escape_sequence"].includes(k.type)).map((k) => k.text).join("");
  if (n.type === "template_string" && !kids(n).some((k) => k.type === "template_substitution")) return n.text.slice(1, -1);
  if (n.type === "number" || n.type === "integer" || n.type === "float") return n.text;
  return null;
}

/** How a SQL string expression is built: concatenation / interpolation with non-literal parts, and its static text. */
function built(expr: SyntaxNode | null): Built {
  const u = unwrap(expr);
  if (!u) return { dynamic: false, staticText: "" };
  switch (u.type) {
    case "template_string": {
      const subs = kids(u).some((k) => k.type === "template_substitution");
      return { dynamic: subs, staticText: kids(u).filter((k) => k.type === "string_fragment" || k.type === "escape_sequence").map((k) => k.text).join(" ") };
    }
    case "string": {
      // Python f-string with interpolation
      const interp = kids(u).some((k) => k.type === "interpolation");
      return { dynamic: interp && /^[rRbBuU]*[fF]/.test(u.text), staticText: kids(u).filter((k) => k.type === "string_content" || k.type === "string_fragment").map((k) => k.text).join(" ") };
    }
    case "binary_expression":
    case "binary_operator": {
      const op = u.childForFieldName("operator")?.text ?? "";
      const left = u.childForFieldName("left");
      const right = u.childForFieldName("right");
      if (op === "+") {
        const l = built(left);
        const r = built(right);
        const nonLiteral = (n: SyntaxNode | null) => {
          const x = unwrap(n);
          return !!x && literalText(x) === null && !["binary_expression", "binary_operator", "template_string", "string"].includes(x.type);
        };
        return { dynamic: l.dynamic || r.dynamic || nonLiteral(left) || nonLiteral(right), staticText: `${l.staticText} ${r.staticText}` };
      }
      if (op === "%" && u.type === "binary_operator") {
        const l = unwrap(left);
        if (l?.type === "string") return { dynamic: literalText(unwrap(right) ?? l) === null, staticText: literalText(l) ?? "" };
      }
      return { dynamic: false, staticText: "" };
    }
    case "call": {
      // "…".format(x)
      const fn = callee(u);
      if (fn?.type === "attribute" && fn.childForFieldName("attribute")?.text === "format") {
        const obj = unwrap(fn.childForFieldName("object"));
        if (obj?.type === "string") return { dynamic: positionalArgs(u).length > 0 || kids(u.childForFieldName("arguments") ?? u).length > 0, staticText: literalText(obj) ?? "" };
      }
      return { dynamic: false, staticText: "" };
    }
    default:
      return { dynamic: false, staticText: "" };
  }
}

/** Follow an identifier to its assignment (one hop), including `sql += <non-literal>` in the same function. */
function builtArg(pf: ParsedFile, arg: SyntaxNode, call: SyntaxNode): Built {
  const u = unwrap(arg);
  if (!u) return { dynamic: false, staticText: "" };
  if (u.type !== "identifier") return built(u);
  const value = resolveLocal(pf, u.text, call);
  const b = built(value);
  if (b.dynamic) return b;
  // let sql = "SELECT …"; sql += " WHERE id = " + id;
  const scope = enclosingFunction(call);
  const body = scope ? functionBody(scope) : pf.root;
  let augmented: Built | null = null;
  if (body) {
    walk(body, (n) => {
      if (augmented?.dynamic) return false;
      if (n.startIndex > call.startIndex) return false;
      if ((n.type === "augmented_assignment_expression" || n.type === "augmented_assignment") && n.childForFieldName("left")?.text === u.text && n.childForFieldName("operator")?.text === "+=") {
        const right = n.childForFieldName("right");
        const r = built(right);
        const x = unwrap(right);
        augmented = { dynamic: r.dynamic || (!!x && literalText(x) === null && x.type !== "string" && x.type !== "template_string"), staticText: `${b.staticText} ${r.staticText}` };
      }
      return true;
    });
  }
  return augmented ?? b;
}

function isSink(call: SyntaxNode, pf: ParsedFile): boolean {
  const name = calleeName(call);
  if (pf.lang === "python") {
    if (PY_SINKS.has(name) && calleePath(call).includes(".")) return true;
    if (name === "text") {
      const path = calleePath(call);
      if (/^(?:sqlalchemy|sa)\.text$/.test(path)) return true;
      return path === "text" && /^sqlalchemy(?:\.|$)/.test(importOf(pf, "text")?.source ?? "");
    }
    return false;
  }
  // Tagged templates are the parameterised form.
  if (call.childForFieldName("arguments")?.type === "template_string") return false;
  if (JS_SINKS.has(name)) return true;
  return name === "unsafe" && calleePath(call).endsWith(".unsafe");
}

export const sqlInjectionRisk = defineRule({
  id: ID,
  title: "SQL built from strings",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => ctx.hasUnit("api"),
  check(ctx, emit) {
    const files = [...new Set(ctx.unitsOf("api").flatMap((u) => ctx.codeFiles(u)))].sort();
    for (const file of files) {
      const text = ctx.read(file) ?? "";
      if (!/\b(?:query|execute|executemany|raw|unsafe|text|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/.test(text)) continue;
      const pf = ctx.parse(file);
      if (!pf) continue;
      for (const c of callsIn(pf.root)) {
        if (!isCall(c) || !isSink(c, pf)) continue;
        const first = positionalArgs(c)[0];
        if (!first) continue;
        const b = builtArg(pf, first, c);
        if (!b.dynamic || !SQL_WORDS.test(b.staticText)) continue;
        emit({
          severity: "high",
          service: "api",
          file,
          line: line(c),
          endLine: endLine(c),
          anchor: anchorText(c),
          evidence: anchorText(c),
          why: WHY,
          fix: { summary: FIX },
        });
      }
    }
  },
});
