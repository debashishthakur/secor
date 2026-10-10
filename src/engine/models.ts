// Model sources for the api pack (spec section 8.5): table/model → field names, read from
// Prisma schemas, Drizzle table definitions, Supabase migrations, Mongoose schemas and SQLAlchemy /
// SQLModel declarative models. Also: pydantic input models (api/mass-assignment) and Supabase tables
// with an RLS policy that references auth.uid() (api/missing-ownership).

import { booleanValue, callee, calleeName, exprPath, functionBody, isFunction, kids, kwarg, objectProps, positionalArgs, stringValue, unwrap, walk } from "./ast.js";
import type { ProjectContext } from "./context.js";
import type { ParsedFile, SyntaxNode } from "./parse.js";

export type ModelKind = "prisma" | "drizzle" | "supabase" | "mongoose" | "sqlalchemy";

export interface ModelInfo {
  kind: ModelKind;
  /** Model, table or class name as written. */
  name: string;
  file: string;
  line: number;
  /** Field / column names in source order (nested Mongoose paths as "a.b"). */
  fields: string[];
  /** Fields not returned by default: Mongoose `select: false`, SQLAlchemy `deferred(...)`. */
  hidden: string[];
  /** Output passes through a serializer (Mongoose toJSON customisation): treated as a field selection. */
  serializerFiltered?: boolean;
}

export interface PydanticModel {
  name: string;
  file: string;
  fields: string[];
  bases: string[];
}

export interface ModelIndex {
  /** Key: model name lowercased (the Prisma client accessor lowercased). */
  prisma: Map<string, ModelInfo>;
  /** Key: the table's variable name (`export const users = pgTable(...)`). */
  drizzle: Map<string, ModelInfo>;
  /** Key: table name lowercased. */
  supabase: Map<string, ModelInfo>;
  /** Key: model name (`model("User", ...)`) and the variable holding the model. */
  mongoose: Map<string, ModelInfo>;
  /** Key: class name. */
  sqlalchemy: Map<string, ModelInfo>;
  /** Key: class name (first definition in file order). */
  pydantic: Map<string, PydanticModel>;
  /** Supabase tables (lowercased, schema dropped) with an RLS policy that references auth.uid(). */
  rlsTables: Set<string>;
  /** Number of ORM / table models (pydantic models excluded). */
  count: number;
}

/** Field names that make returning a whole row a problem (spec 8.5, api/over-sharing). */
export const SENSITIVE_FIELD = /(password|passwd|hash|salt|secret|token|api_?key|ssn|otp)/i;

/** Fields of the model that match SENSITIVE_FIELD and are returned by default. */
export function sensitiveFields(m: ModelInfo): string[] {
  const hidden = new Set(m.hidden);
  return m.fields.filter((f) => !hidden.has(f) && SENSITIVE_FIELD.test(f));
}

const cache = new WeakMap<ProjectContext, ModelIndex>();

export function modelIndex(ctx: ProjectContext): ModelIndex {
  const hit = cache.get(ctx);
  if (hit) return hit;
  const index: ModelIndex = {
    prisma: new Map(),
    drizzle: new Map(),
    supabase: new Map(),
    mongoose: new Map(),
    sqlalchemy: new Map(),
    pydantic: new Map(),
    rlsTables: new Set(),
    count: 0,
  };
  const setOnce = <V>(m: Map<string, V>, k: string, v: V) => {
    if (k && !m.has(k)) m.set(k, v);
  };
  for (const file of ctx.files) {
    if (file.endsWith(".prisma")) {
      for (const m of parsePrismaSchema(ctx.read(file) ?? "", file)) setOnce(index.prisma, m.name.toLowerCase(), m);
    } else if (/(?:^|\/)supabase\/migrations\/[^/]+\.sql$/.test(file)) {
      const text = ctx.read(file) ?? "";
      for (const m of parseSqlTables(text, file)) {
        const existing = index.supabase.get(m.name.toLowerCase());
        if (existing) {
          for (const f of m.fields) if (!existing.fields.includes(f)) existing.fields.push(f);
        } else index.supabase.set(m.name.toLowerCase(), m);
      }
      for (const t of parseRlsTables(text)) index.rlsTables.add(t);
    }
  }
  for (const file of ctx.codeFiles(undefined, "js")) {
    const text = ctx.read(file) ?? "";
    if (!/Table\s*\(|Schema\s*\(/.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    for (const m of drizzleTables(pf)) setOnce(index.drizzle, m.varName, m.info);
    for (const m of mongooseModels(pf)) for (const k of m.keys) setOnce(index.mongoose, k, m.info);
  }
  const pyClasses: PyClass[] = [];
  for (const file of ctx.codeFiles(undefined, "py")) {
    const text = ctx.read(file) ?? "";
    if (!/^\s*class\s/m.test(text)) continue;
    const pf = ctx.parse(file);
    if (pf) pyClasses.push(...pythonClasses(pf));
  }
  classifyPythonClasses(pyClasses, index);
  const unique = new Set<ModelInfo>([...index.prisma.values(), ...index.drizzle.values(), ...index.supabase.values(), ...index.mongoose.values(), ...index.sqlalchemy.values()]);
  index.count = unique.size;
  cache.set(ctx, index);
  return index;
}

// ---------------------------------------------------------------- Prisma

/** `model Name { field Type ... }` and `view Name { ... }` blocks. */
export function parsePrismaSchema(text: string, file: string): ModelInfo[] {
  const out: ModelInfo[] = [];
  const re = /^[ \t]*(model|view)\s+(\w+)\s*\{/gm;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const start = m.index + m[0].length;
    const end = text.indexOf("}", start);
    if (end < 0) break;
    const fields: string[] = [];
    for (const raw of text.slice(start, end).split("\n")) {
      const lineText = raw.replace(/\/\/.*$/, "").trim();
      if (!lineText || lineText.startsWith("@@")) continue;
      const f = /^([A-Za-z_]\w*)\s+\S/.exec(lineText);
      if (f) fields.push(f[1]!);
    }
    out.push({ kind: "prisma", name: m[2]!, file, line: text.slice(0, m.index).split("\n").length, fields, hidden: [] });
  }
  return out;
}

// ---------------------------------------------------------------- Supabase migrations (SQL)

const SQL_CONSTRAINT = /^(?:constraint|primary|foreign|unique|check|exclude|like)\b/i;

function sqlIdent(s: string): string {
  return s.replace(/^"|"$/g, "");
}

/** Index of the parenthesis that closes the one opened just before `from` (quotes respected). */
function closingParen(text: string, from: number): number {
  let depth = 1;
  let quote: string | null = null;
  for (let i = from; i < text.length; i++) {
    const c = text[i]!;
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === "-" && text[i + 1] === "-") {
      const nl = text.indexOf("\n", i);
      i = nl < 0 ? text.length : nl;
    } else if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Top-level comma split (parentheses and quotes respected). */
function splitTopLevel(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === "-" && s[i + 1] === "-") {
      const nl = s.indexOf("\n", i);
      i = nl < 0 ? s.length : nl;
      cur += "\n";
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    if (c === "(") depth++;
    if (c === ")") depth--;
    if (c === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/** CREATE TABLE columns, plus ALTER TABLE ... ADD COLUMN. Table names drop the schema prefix. */
export function parseSqlTables(text: string, file: string): ModelInfo[] {
  const out = new Map<string, ModelInfo>();
  const create = /create\s+(?:(?:global\s+|local\s+)?(?:temporary|temp|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?((?:"?\w+"?\.)?"?\w+"?)\s*\(/gi;
  for (let m = create.exec(text); m; m = create.exec(text)) {
    const name = sqlIdent(m[1]!.split(".").pop()!);
    const start = m.index + m[0].length;
    const end = closingParen(text, start);
    if (end < 0) continue;
    const fields: string[] = [];
    for (const def of splitTopLevel(text.slice(start, end))) {
      const d = def.trim();
      if (!d || SQL_CONSTRAINT.test(d)) continue;
      const col = /^("[^"]+"|\w+)/.exec(d);
      if (col) fields.push(sqlIdent(col[1]!));
    }
    const key = name.toLowerCase();
    const existing = out.get(key);
    if (existing) for (const f of fields) existing.fields.includes(f) || existing.fields.push(f);
    else out.set(key, { kind: "supabase", name, file, line: text.slice(0, m.index).split("\n").length, fields, hidden: [] });
  }
  const alter = /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:"?\w+"?\.)?"?\w+"?)\s+([^;]*);/gi;
  for (let m = alter.exec(text); m; m = alter.exec(text)) {
    const key = sqlIdent(m[1]!.split(".").pop()!).toLowerCase();
    const t = out.get(key);
    if (!t) continue;
    for (const part of splitTopLevel(m[2]!)) {
      const add = /^\s*add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?("[^"]+"|\w+)/i.exec(part);
      if (add && !/^(?:constraint|primary|foreign|unique|check)$/i.test(add[1]!)) {
        const f = sqlIdent(add[1]!);
        if (!t.fields.includes(f)) t.fields.push(f);
      }
    }
  }
  return [...out.values()];
}

/** Tables with a CREATE POLICY whose USING / WITH CHECK references auth.uid(). */
export function parseRlsTables(text: string): string[] {
  const out: string[] = [];
  const re = /create\s+policy\s+(?:"[^"]*"|\w+)\s+on\s+((?:"?\w+"?\.)?"?\w+"?)([^;]*);/gi;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (/auth\s*\.\s*uid\s*\(\s*\)/i.test(m[2]!)) out.push(sqlIdent(m[1]!.split(".").pop()!).toLowerCase());
  }
  return out;
}

// ---------------------------------------------------------------- Drizzle

const DRIZZLE_TABLE = new Set(["pgTable", "mysqlTable", "sqliteTable"]);

function drizzleTables(pf: ParsedFile): { varName: string; info: ModelInfo }[] {
  const out: { varName: string; info: ModelInfo }[] = [];
  walk(pf.root, (n) => {
    if (n.type !== "call_expression" || !DRIZZLE_TABLE.has(calleeName(n))) return true;
    const decl = declaratorOf(n);
    const a = positionalArgs(n);
    const name = stringValue(a[0] ?? null) ?? decl ?? "";
    let cols = unwrap(a[1] ?? null);
    if (cols && isFunction(cols)) {
      const body = functionBody(cols);
      cols = unwrap(body?.type === "statement_block" ? (kids(body).find((s) => s.type === "return_statement")?.namedChildren[0] ?? null) : body);
    }
    const fields = objectProps(cols).map((p) => p.key);
    if (decl) out.push({ varName: decl, info: { kind: "drizzle", name, file: pf.file, line: n.startPosition.row + 1, fields, hidden: [] } });
    return true;
  });
  return out;
}

/** Name of the variable a value is assigned to (`const x = <call>` / `export const x = ...`), through `a || b`. */
function declaratorOf(n: SyntaxNode): string | null {
  let cur: SyntaxNode | null = n;
  for (let i = 0; cur && i < 4; i++) {
    const p: SyntaxNode | null = cur.parent;
    if (!p) return null;
    if (p.type === "variable_declarator") return p.childForFieldName("name")?.type === "identifier" ? (p.childForFieldName("name")?.text ?? null) : null;
    if (!["binary_expression", "parenthesized_expression", "as_expression", "satisfies_expression", "await_expression"].includes(p.type)) return null;
    cur = p;
  }
  return null;
}

// ---------------------------------------------------------------- Mongoose

function mongooseModels(pf: ParsedFile): { keys: string[]; info: ModelInfo }[] {
  const schemas = new Map<string, ModelInfo>();
  const inline = new Map<number, ModelInfo>();
  const serializer = /\btoJSON\b/.test(pf.source);
  walk(pf.root, (n) => {
    if (n.type !== "new_expression") return true;
    const ctor = exprPath(callee(n));
    if (ctor !== "Schema" && !/\.Schema$/.test(ctor)) return true;
    const def = unwrap(positionalArgs(n)[0] ?? null);
    const fields: string[] = [];
    const hidden: string[] = [];
    for (const p of objectProps(def)) {
      fields.push(p.key);
      const v = unwrap(p.value);
      if (!v || v.type !== "object") continue;
      if (booleanValue(objectProps(v).find((x) => x.key === "select")?.value ?? null) === false) hidden.push(p.key);
      if (!objectProps(v).some((x) => x.key === "type")) {
        // Nested path: { auth: { passwordHash: String } }
        for (const q of objectProps(v)) {
          const path = `${p.key}.${q.key}`;
          fields.push(path);
          const qv = unwrap(q.value);
          if (qv?.type === "object" && booleanValue(objectProps(qv).find((x) => x.key === "select")?.value ?? null) === false) hidden.push(path);
        }
      }
    }
    const info: ModelInfo = { kind: "mongoose", name: declaratorOf(n) ?? "Schema", file: pf.file, line: n.startPosition.row + 1, fields, hidden, ...(serializer ? { serializerFiltered: true } : {}) };
    const decl = declaratorOf(n);
    if (decl) schemas.set(decl, info);
    inline.set(n.id, info);
    return true;
  });
  const out: { keys: string[]; info: ModelInfo }[] = [];
  walk(pf.root, (n) => {
    if (n.type !== "call_expression" || calleeName(n) !== "model") return true;
    const a = positionalArgs(n);
    const modelName = stringValue(a[0] ?? null);
    const schemaArg = unwrap(a[1] ?? null);
    if (!modelName || !schemaArg) return true;
    const info = schemaArg.type === "identifier" ? schemas.get(schemaArg.text) : schemaArg.type === "new_expression" ? inline.get(schemaArg.id) : undefined;
    if (!info) return true;
    const named: ModelInfo = { ...info, name: modelName };
    const keys = [modelName];
    const decl = declaratorOf(n);
    if (decl && decl !== modelName) keys.push(decl);
    out.push({ keys, info: named });
    return true;
  });
  return out;
}

// ---------------------------------------------------------------- Python classes (SQLAlchemy / SQLModel / pydantic)

interface PyClass {
  name: string;
  file: string;
  line: number;
  bases: string[];
  tableKw: boolean;
  hasTablename: boolean;
  columns: { name: string; hidden: boolean; orm: boolean }[];
  annotated: string[];
}

const ORM_COLUMN_CALLS = new Set(["Column", "mapped_column", "column_property", "deferred", "Field"]);

function pythonClasses(pf: ParsedFile): PyClass[] {
  const out: PyClass[] = [];
  for (const top of kids(pf.root)) {
    const def = top.type === "decorated_definition" ? top.childForFieldName("definition") : top;
    if (!def || def.type !== "class_definition") continue;
    const name = def.childForFieldName("name")?.text ?? "";
    const supers = def.childForFieldName("superclasses");
    const bases: string[] = [];
    let tableKw = false;
    for (const s of supers ? kids(supers) : []) {
      if (s.type === "keyword_argument") {
        if (s.childForFieldName("name")?.text === "table" && s.childForFieldName("value")?.type === "true") tableKw = true;
        continue;
      }
      bases.push(exprPath(s).split(".").pop() ?? s.text);
    }
    const cls: PyClass = { name, file: pf.file, line: def.startPosition.row + 1, bases, tableKw, hasTablename: false, columns: [], annotated: [] };
    const body = def.childForFieldName("body");
    for (const stmt of body ? kids(body) : []) {
      if (stmt.type !== "expression_statement") continue;
      const a = kids(stmt)[0];
      if (a?.type !== "assignment") continue;
      const left = a.childForFieldName("left");
      if (left?.type !== "identifier") continue;
      const field = left.text;
      if (field === "__tablename__") {
        cls.hasTablename = true;
        continue;
      }
      if (field.startsWith("__") || field === "model_config" || field === "Config") continue;
      const type = a.childForFieldName("type");
      const right = unwrap(a.childForFieldName("right"));
      const typeText = type?.text ?? "";
      if (/^ClassVar\b/.test(typeText)) continue;
      const rightName = right && right.type === "call" ? calleeName(right) : "";
      if (rightName === "relationship" || rightName === "Relationship" || /\bRelationship\b|relationship/.test(typeText)) continue;
      const deferred = rightName === "deferred" || (right?.type === "call" && kwarg(right, "deferred")?.type === "true");
      if (type) cls.annotated.push(field);
      if (ORM_COLUMN_CALLS.has(rightName) || /^Mapped\[/.test(typeText)) cls.columns.push({ name: field, hidden: deferred, orm: rightName !== "Field" || /^Mapped\[/.test(typeText) });
      else if (type) cls.columns.push({ name: field, hidden: false, orm: false });
    }
    out.push(cls);
  }
  return out;
}

const PYDANTIC_ROOTS = new Set(["BaseModel", "SQLModel", "RootModel"]);

function classifyPythonClasses(classes: PyClass[], index: ModelIndex): void {
  const byName = new Map<string, PyClass>();
  for (const c of classes) if (!byName.has(c.name)) byName.set(c.name, c);
  const isOrmRoot = (c: PyClass) => c.hasTablename || c.tableKw || c.columns.some((x) => x.orm);
  // Pydantic: BaseModel / non-table SQLModel, or a subclass of a known pydantic class.
  const pyd = new Set<string>();
  for (let changed = true; changed; ) {
    changed = false;
    for (const c of classes) {
      if (pyd.has(c.name) || c.tableKw || c.hasTablename) continue;
      if (c.bases.some((b) => PYDANTIC_ROOTS.has(b) || pyd.has(b))) {
        pyd.add(c.name);
        changed = true;
      }
    }
  }
  const inherited = (c: PyClass, seen = new Set<string>()): { name: string; hidden: boolean }[] => {
    if (seen.has(c.name)) return [];
    seen.add(c.name);
    const own = c.columns.map((x) => ({ name: x.name, hidden: x.hidden }));
    const fromBases = c.bases.flatMap((b) => {
      const bc = byName.get(b);
      return bc ? inherited(bc, seen) : [];
    });
    const out: { name: string; hidden: boolean }[] = [];
    for (const f of [...fromBases, ...own]) {
      const i = out.findIndex((x) => x.name === f.name);
      if (i >= 0) out[i] = f;
      else out.push(f);
    }
    return out;
  };
  for (const c of classes) {
    if (pyd.has(c.name)) {
      if (!index.pydantic.has(c.name)) index.pydantic.set(c.name, { name: c.name, file: c.file, fields: inherited(c).map((f) => f.name), bases: c.bases });
      continue;
    }
    if (!isOrmRoot(c)) continue;
    const fields = inherited(c);
    if (!index.sqlalchemy.has(c.name)) index.sqlalchemy.set(c.name, { kind: "sqlalchemy", name: c.name, file: c.file, line: c.line, fields: fields.map((f) => f.name), hidden: fields.filter((f) => f.hidden).map((f) => f.name) });
  }
}

/** Fields of a pydantic model by class name (inherited fields included). */
export function pydanticFields(index: ModelIndex, name: string): string[] | null {
  return index.pydantic.get(name)?.fields ?? null;
}

