// Supabase migration model (spec 8.5, web/database-rules): a tolerant SQL statement splitter and a
// tracker for tables in schema `public`, their RLS state, policies and views, applied in file order.

export interface SqlStatement {
  /** Statement text with comments blanked out (same length and line breaks as the original). */
  text: string;
  /** Offset of the first character of the statement in the file. */
  start: number;
  /** 1-based line of the first character of the statement. */
  line: number;
}

/**
 * Split SQL into statements on top-level `;`. Handles `--` and nested `/* *\/` comments, '…' strings
 * (with '' escapes, and backslash escapes in E'…' strings), "…" identifiers and $tag$…$tag$ bodies.
 */
export function splitSql(source: string): SqlStatement[] {
  const out: SqlStatement[] = [];
  const clean = source.split("");
  let i = 0;
  let line = 1;
  let stmtStart = -1;
  let stmtLine = 1;
  const n = source.length;
  const isIdent = (c: string | undefined) => !!c && /[A-Za-z0-9_$]/.test(c);
  const blank = (from: number, to: number) => {
    for (let k = from; k < to; k++) if (clean[k] !== "\n") clean[k] = " ";
  };
  const mark = () => {
    if (stmtStart < 0) {
      stmtStart = i;
      stmtLine = line;
    }
  };
  const advance = (to: number) => {
    for (let k = i; k < to && k < n; k++) if (source.charCodeAt(k) === 10) line++;
    i = Math.min(to, n);
  };
  const flush = (end: number) => {
    if (stmtStart >= 0) {
      const text = clean.slice(stmtStart, end).join("");
      if (text.trim()) out.push({ text, start: stmtStart, line: stmtLine });
    }
    stmtStart = -1;
  };
  while (i < n) {
    const c = source[i]!;
    if (c === "-" && source[i + 1] === "-") {
      let j = source.indexOf("\n", i);
      if (j < 0) j = n;
      blank(i, j);
      advance(j);
      continue;
    }
    if (c === "/" && source[i + 1] === "*") {
      let depth = 0;
      let j = i;
      while (j < n) {
        if (source[j] === "/" && source[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (source[j] === "*" && source[j + 1] === "/") {
          depth--;
          j += 2;
          if (depth === 0) break;
        } else j++;
      }
      blank(i, j);
      advance(j);
      continue;
    }
    if (c === "'") {
      mark();
      const escapes = (source[i - 1] === "E" || source[i - 1] === "e") && !isIdent(source[i - 2]);
      let j = i + 1;
      while (j < n) {
        if (escapes && source[j] === "\\") {
          j += 2;
          continue;
        }
        if (source[j] === "'") {
          if (source[j + 1] === "'") {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      advance(j + 1);
      continue;
    }
    if (c === '"') {
      mark();
      let j = i + 1;
      while (j < n) {
        if (source[j] === '"') {
          if (source[j + 1] === '"') {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      advance(j + 1);
      continue;
    }
    if (c === "$" && !isIdent(source[i - 1])) {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(source.slice(i, i + 66));
      if (m) {
        mark();
        const close = source.indexOf(m[0], i + m[0].length);
        advance(close < 0 ? n : close + m[0].length);
        continue;
      }
    }
    if (c === ";") {
      flush(i);
      advance(i + 1);
      continue;
    }
    if (!/\s/.test(c)) mark();
    advance(i + 1);
  }
  flush(n);
  return out;
}

// ---------------------------------------------------------------- tokens

export interface SqlToken {
  /** ident: unquoted identifier or keyword (lowercased); qident: "quoted" identifier; str: '…'; dollar: $$…$$ body. */
  type: "ident" | "qident" | "str" | "dollar" | "num" | "punct";
  value: string;
  start: number;
  end: number;
}

export function tokenizeSql(text: string): SqlToken[] {
  const out: SqlToken[] = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(text.slice(i, i + 256))!;
      const word = m[0];
      // E'…' escape strings
      if ((word === "E" || word === "e") && text[i + 1] === "'") {
        i++;
        continue;
      }
      out.push({ type: "ident", value: word.toLowerCase(), start: i, end: i + word.length });
      i += word.length;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let v = "";
      while (j < n) {
        if (text[j] === '"') {
          if (text[j + 1] === '"') {
            v += '"';
            j += 2;
            continue;
          }
          break;
        }
        v += text[j];
        j++;
      }
      out.push({ type: "qident", value: v, start: i, end: j + 1 });
      i = j + 1;
      continue;
    }
    if (c === "'") {
      const escapes = (text[i - 1] === "E" || text[i - 1] === "e") && !/[A-Za-z0-9_$]/.test(text[i - 2] ?? "");
      let j = i + 1;
      let v = "";
      while (j < n) {
        if (escapes && text[j] === "\\") {
          v += text[j + 1] ?? "";
          j += 2;
          continue;
        }
        if (text[j] === "'") {
          if (text[j + 1] === "'") {
            v += "'";
            j += 2;
            continue;
          }
          break;
        }
        v += text[j];
        j++;
      }
      out.push({ type: "str", value: v, start: i, end: j + 1 });
      i = j + 1;
      continue;
    }
    if (c === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(text.slice(i, i + 66));
      if (m) {
        const close = text.indexOf(m[0], i + m[0].length);
        const end = close < 0 ? n : close + m[0].length;
        out.push({ type: "dollar", value: text.slice(i + m[0].length, close < 0 ? n : close), start: i, end });
        i = end;
        continue;
      }
    }
    if (/[0-9]/.test(c)) {
      const m = /^[0-9][0-9.eE]*/.exec(text.slice(i, i + 64))!;
      out.push({ type: "num", value: m[0], start: i, end: i + m[0].length });
      i += m[0].length;
      continue;
    }
    if (c === ":" && text[i + 1] === ":") {
      out.push({ type: "punct", value: "::", start: i, end: i + 2 });
      i += 2;
      continue;
    }
    out.push({ type: "punct", value: c, start: i, end: i + 1 });
    i++;
  }
  return out;
}

// ---------------------------------------------------------------- model

export interface SqlLoc {
  file: string;
  line: number;
  /** Statement text (comments blanked), for evidence. */
  text: string;
}

export interface QName {
  schema: string;
  name: string;
}

export interface TableState extends QName {
  rls: boolean;
  /** Where the table was (last) created; null when only seen in ALTER statements. */
  created: SqlLoc | null;
  /** Where RLS was last explicitly disabled (null if never). */
  disabledAt: SqlLoc | null;
}

export type PolicyCommand = "all" | "select" | "insert" | "update" | "delete";

export interface PolicyState {
  name: string;
  table: QName;
  permissive: boolean;
  command: PolicyCommand;
  /** Lowercased role names; empty = PUBLIC (the default). */
  roles: string[];
  using: string | null;
  check: string | null;
  loc: SqlLoc;
}

export interface ViewState extends QName {
  materialized: boolean;
  securityInvoker: boolean;
  sources: QName[];
  loc: SqlLoc;
}

export interface SupabaseModel {
  tables: Map<string, TableState>;
  policies: Map<string, PolicyState>;
  views: Map<string, ViewState>;
}

export function qkey(q: QName): string {
  return `${q.schema}.${q.name}`;
}

export function displayName(q: QName): string {
  const part = (s: string) => (/^[a-z_][a-z0-9_$]*$/.test(s) ? s : `"${s.replace(/"/g, '""')}"`);
  return `${part(q.schema)}.${part(q.name)}`;
}

function policyKey(table: QName, name: string): string {
  return `${qkey(table)}\u0000${name}`;
}

export function emptyModel(): SupabaseModel {
  return { tables: new Map(), policies: new Map(), views: new Map() };
}

class Cursor {
  i = 0;
  constructor(readonly toks: SqlToken[]) {}
  peek(o = 0): SqlToken | undefined {
    return this.toks[this.i + o];
  }
  /** Is the token at offset `o` the (unquoted) keyword `kw`? */
  is(kw: string, o = 0): boolean {
    const t = this.peek(o);
    return !!t && t.type === "ident" && t.value === kw;
  }
  isPunct(p: string, o = 0): boolean {
    const t = this.peek(o);
    return !!t && t.type === "punct" && t.value === p;
  }
  accept(...kws: string[]): boolean {
    if (kws.every((k, o) => this.is(k, o))) {
      this.i += kws.length;
      return true;
    }
    return false;
  }
  acceptPunct(p: string): boolean {
    if (this.isPunct(p)) {
      this.i++;
      return true;
    }
    return false;
  }
  done(): boolean {
    return this.i >= this.toks.length;
  }
  /** A name part: identifier, "quoted identifier" (case kept) or, for policy names, a string. */
  name(allowString = false): string | null {
    const t = this.peek();
    if (!t) return null;
    if (t.type === "ident" || t.type === "qident" || (allowString && t.type === "str")) {
      this.i++;
      return t.value;
    }
    return null;
  }
  /** Possibly schema-qualified name; unqualified names are in `public`. */
  qname(): QName | null {
    const parts: string[] = [];
    const first = this.name();
    if (first === null) return null;
    parts.push(first);
    while (this.isPunct(".")) {
      const save = this.i;
      this.i++;
      const next = this.name();
      if (next === null) {
        this.i = save;
        break;
      }
      parts.push(next);
    }
    if (parts.length === 1) return { schema: "public", name: parts[0]! };
    return { schema: parts[parts.length - 2]!, name: parts[parts.length - 1]! };
  }
  /** Text of the balanced (…) group at the cursor, without the outer parentheses. Advances past it. */
  group(text: string): string | null {
    if (!this.isPunct("(")) return null;
    const open = this.peek()!;
    let depth = 0;
    for (let j = this.i; j < this.toks.length; j++) {
      const t = this.toks[j]!;
      if (t.type !== "punct") continue;
      if (t.value === "(") depth++;
      else if (t.value === ")") {
        depth--;
        if (depth === 0) {
          this.i = j + 1;
          return text.slice(open.end, t.start);
        }
      }
    }
    this.i = this.toks.length;
    return text.slice(open.end);
  }
}

const POLICY_COMMANDS = new Set<PolicyCommand>(["all", "select", "insert", "update", "delete"]);

/** Apply one SQL file's statements to the model (in order). */
export function applySql(model: SupabaseModel, file: string, source: string): void {
  for (const st of splitSql(source)) {
    try {
      applyStatement(model, file, st);
    } catch {
      // Tolerant: a statement we cannot read is skipped.
    }
  }
}

function applyStatement(model: SupabaseModel, file: string, st: SqlStatement): void {
  const toks = tokenizeSql(st.text);
  const c = new Cursor(toks);
  const loc: SqlLoc = { file, line: st.line, text: st.text.trim() };
  if (c.accept("create")) {
    c.accept("or", "replace");
    if (c.is("temp") || c.is("temporary")) return;
    c.accept("unlogged");
    c.accept("global");
    c.accept("local");
    if (c.accept("table")) return createTable(model, c, loc);
    if (c.accept("policy")) return createPolicy(model, c, loc);
    c.accept("recursive");
    if (c.accept("view")) return createView(model, c, loc, st.text, false);
    if (c.accept("materialized", "view")) return createView(model, c, loc, st.text, true);
    return;
  }
  if (c.accept("alter", "table")) return alterTable(model, c, loc);
  if (c.accept("alter", "policy")) return alterPolicy(model, c, loc);
  if (c.accept("alter", "view") || c.accept("alter", "materialized", "view")) return alterView(model, c, st.text);
  if (c.accept("drop", "table")) return dropRelations(model, c, "table");
  if (c.accept("drop", "view") || c.accept("drop", "materialized", "view")) return dropRelations(model, c, "view");
  if (c.accept("drop", "policy")) {
    c.accept("if", "exists");
    const name = c.name(true);
    if (name === null || !c.accept("on")) return;
    const table = c.qname();
    if (table) model.policies.delete(policyKey(table, name));
    return;
  }
  if (c.accept("do")) return doBlock(model, toks);
}

function createTable(model: SupabaseModel, c: Cursor, loc: SqlLoc): void {
  const ifNotExists = c.accept("if", "not", "exists");
  const q = c.qname();
  if (!q) return;
  const key = qkey(q);
  const existing = model.tables.get(key);
  if (existing && ifNotExists) {
    // CREATE TABLE IF NOT EXISTS on a table that already exists is a no-op.
    existing.created ??= loc;
    return;
  }
  model.tables.set(key, { ...q, rls: false, created: loc, disabledAt: null });
}

function alterTable(model: SupabaseModel, c: Cursor, loc: SqlLoc): void {
  c.accept("if", "exists");
  c.accept("only");
  const q = c.qname();
  if (!q) return;
  c.acceptPunct("*");
  let key = qkey(q);
  const state = () => {
    let t = model.tables.get(key);
    if (!t) {
      t = { schema: q.schema, name: q.name, rls: false, created: null, disabledAt: null };
      model.tables.set(key, t);
    }
    return t;
  };
  // Actions are comma separated; scan for the ones that matter.
  while (!c.done()) {
    if (c.accept("enable", "row", "level", "security")) {
      state().rls = true;
    } else if (c.accept("disable", "row", "level", "security")) {
      const t = state();
      t.rls = false;
      t.disabledAt = loc;
    } else if (c.is("rename") && c.is("to", 1)) {
      c.i += 2;
      const to = c.name();
      if (to !== null) {
        const t = model.tables.get(key);
        const nq = { schema: q.schema, name: to };
        if (t) {
          model.tables.delete(key);
          model.tables.set(qkey(nq), { ...t, ...nq });
        }
        renamePolicies(model, q, nq);
        key = qkey(nq);
        q.name = to;
      }
    } else if (c.accept("set", "schema")) {
      const to = c.name();
      if (to !== null) {
        const t = model.tables.get(key);
        const nq = { schema: to, name: q.name };
        if (t) {
          model.tables.delete(key);
          model.tables.set(qkey(nq), { ...t, ...nq });
        }
        renamePolicies(model, q, nq);
        key = qkey(nq);
        q.schema = to;
      }
    } else {
      c.i++;
    }
  }
}

function renamePolicies(model: SupabaseModel, from: QName, to: QName): void {
  for (const [k, p] of [...model.policies]) {
    if (qkey(p.table) !== qkey(from)) continue;
    model.policies.delete(k);
    const np = { ...p, table: { ...to } };
    model.policies.set(policyKey(np.table, np.name), np);
  }
}

function readRoles(c: Cursor): string[] {
  const roles: string[] = [];
  for (;;) {
    const t = c.peek();
    if (!t) break;
    if (t.type === "ident" && (t.value === "using" || t.value === "with")) break;
    if (t.type === "ident" || t.type === "qident") {
      roles.push(t.type === "ident" ? t.value : t.value.toLowerCase());
      c.i++;
      if (!c.acceptPunct(",")) break;
      continue;
    }
    break;
  }
  return roles;
}

function createPolicy(model: SupabaseModel, c: Cursor, loc: SqlLoc): void {
  const name = c.name(true);
  if (name === null || !c.accept("on")) return;
  const table = c.qname();
  if (!table) return;
  const p: PolicyState = { name, table, permissive: true, command: "all", roles: [], using: null, check: null, loc };
  readPolicyClauses(c, p, loc.text, true);
  model.policies.set(policyKey(table, name), p);
}

function readPolicyClauses(c: Cursor, p: PolicyState, text: string, create: boolean): void {
  while (!c.done()) {
    if (create && c.accept("as")) {
      if (c.accept("restrictive")) p.permissive = false;
      else c.accept("permissive");
    } else if (create && c.accept("for")) {
      const t = c.peek();
      if (t?.type === "ident" && POLICY_COMMANDS.has(t.value as PolicyCommand)) {
        p.command = t.value as PolicyCommand;
        c.i++;
      }
    } else if (c.accept("to")) {
      p.roles = readRoles(c);
    } else if (c.accept("using")) {
      p.using = c.group(text);
    } else if (c.accept("with", "check")) {
      p.check = c.group(text);
    } else {
      c.i++;
    }
  }
}

function alterPolicy(model: SupabaseModel, c: Cursor, loc: SqlLoc): void {
  const name = c.name(true);
  if (name === null || !c.accept("on")) return;
  const table = c.qname();
  if (!table) return;
  const key = policyKey(table, name);
  const existing = model.policies.get(key);
  if (c.accept("rename", "to")) {
    const to = c.name(true);
    if (to !== null && existing) {
      model.policies.delete(key);
      model.policies.set(policyKey(table, to), { ...existing, name: to });
    }
    return;
  }
  if (!existing) return;
  const p: PolicyState = { ...existing, loc };
  readPolicyClauses(c, p, loc.text, false);
  model.policies.set(key, p);
}

function readViewOptions(group: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of group.split(",")) {
    const m = /^\s*([A-Za-z_][\w.]*)\s*(?:=\s*(.*?))?\s*$/.exec(part);
    if (!m) continue;
    out.set(m[1]!.toLowerCase(), (m[2] ?? "true").replace(/^'(.*)'$/, "$1").toLowerCase());
  }
  return out;
}

function isTrueOption(v: string | undefined): boolean {
  return v !== undefined && ["true", "on", "yes", "1"].includes(v);
}

function createView(model: SupabaseModel, c: Cursor, loc: SqlLoc, text: string, materialized: boolean): void {
  c.accept("if", "not", "exists");
  const q = c.qname();
  if (!q) return;
  if (c.isPunct("(")) c.group(text);
  let securityInvoker = false;
  while (!c.done() && !c.is("as")) {
    if (c.accept("with") && c.isPunct("(")) {
      const opts = readViewOptions(c.group(text) ?? "");
      securityInvoker = isTrueOption(opts.get("security_invoker"));
    } else c.i++;
  }
  if (!c.accept("as")) return;
  const sources = querySources(c.toks.slice(c.i));
  model.views.set(qkey(q), { ...q, materialized, securityInvoker: materialized ? false : securityInvoker, sources, loc });
}

function alterView(model: SupabaseModel, c: Cursor, text: string): void {
  c.accept("if", "exists");
  const q = c.qname();
  if (!q) return;
  const v = model.views.get(qkey(q));
  if (c.accept("rename", "to")) {
    const to = c.name();
    if (to !== null && v) {
      model.views.delete(qkey(q));
      model.views.set(qkey({ schema: q.schema, name: to }), { ...v, name: to });
    }
    return;
  }
  if (!v) return;
  if (c.accept("set") && c.isPunct("(")) {
    const opts = readViewOptions(c.group(text) ?? "");
    if (opts.has("security_invoker")) v.securityInvoker = !v.materialized && isTrueOption(opts.get("security_invoker"));
  } else if (c.accept("reset")) {
    if (c.toks.slice(c.i).some((t) => t.type === "ident" && t.value === "security_invoker")) v.securityInvoker = false;
  }
}

function dropRelations(model: SupabaseModel, c: Cursor, kind: "table" | "view"): void {
  c.accept("if", "exists");
  for (;;) {
    const q = c.qname();
    if (!q) break;
    const key = qkey(q);
    if (kind === "table") {
      model.tables.delete(key);
      for (const [k, p] of [...model.policies]) if (qkey(p.table) === key) model.policies.delete(k);
    } else {
      model.views.delete(key);
    }
    if (!c.acceptPunct(",")) break;
  }
}

/** A DO block that enables RLS dynamically (`execute format('alter table %I enable row level security', …)`). */
function doBlock(model: SupabaseModel, toks: SqlToken[]): void {
  const body = toks.find((t) => t.type === "dollar" || t.type === "str")?.value ?? "";
  if (!/enable\s+row\s+level\s+security/i.test(body)) return;
  let dynamic = false;
  for (const m of body.matchAll(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([^\s;]+)\s+enable\s+row\s+level\s+security/gi)) {
    const target = m[1]!;
    if (/[%|']|\$/.test(target)) {
      dynamic = true;
      continue;
    }
    const inner = new Cursor(tokenizeSql(target));
    const q = inner.qname();
    const t = q ? model.tables.get(qkey(q)) : undefined;
    if (t) t.rls = true;
  }
  if (dynamic || /\bformat\s*\(|quote_ident\s*\(|\|\|/.test(body)) {
    for (const t of model.tables.values()) if (t.schema === "public") t.rls = true;
  }
}

/**
 * Relations a view's query reads from: items of FROM clauses (comma lists included) and JOIN targets, at any
 * subquery depth. CTE names and set-returning function calls are excluded.
 */
export function querySources(toks: SqlToken[]): QName[] {
  const ctes = new Set<string>();
  for (let j = 0; j + 2 < toks.length; j++) {
    const a = toks[j]!;
    if ((a.type === "ident" || a.type === "qident") && toks[j + 1]?.type === "ident" && toks[j + 1]!.value === "as" && toks[j + 2]?.type === "punct" && toks[j + 2]!.value === "(") {
      ctes.add(a.value);
    }
  }
  const END = new Set(["where", "group", "order", "limit", "having", "union", "intersect", "except", "window", "returning", "offset", "fetch", "for"]);
  const KEYWORDS = new Set([...END, "select", "from", "join", "on", "using", "as", "lateral", "only", "inner", "left", "right", "full", "cross", "natural", "outer"]);
  const out: QName[] = [];
  const seen = new Set<string>();
  const c = new Cursor(toks);
  let depth = 0;
  let fromDepth = -1;
  const item = () => {
    c.accept("only");
    c.accept("lateral");
    if (c.isPunct("(")) return;
    const first = c.peek();
    const before = c.i;
    const q = c.qname();
    if (!q || !first) return;
    if (c.isPunct("(")) {
      // set-returning function in FROM; leave the "(" for the depth tracking
      return;
    }
    if (first.type === "ident" && KEYWORDS.has(first.value)) return;
    if (c.i - before === 1 && ctes.has(first.value)) return;
    const k = qkey(q);
    if (!seen.has(k)) {
      seen.add(k);
      out.push(q);
    }
  };
  while (!c.done()) {
    const t = c.peek()!;
    if (t.type === "punct" && t.value === "(") {
      depth++;
      c.i++;
      continue;
    }
    if (t.type === "punct" && t.value === ")") {
      depth--;
      if (depth < fromDepth) fromDepth = -1;
      c.i++;
      continue;
    }
    if (t.type === "ident" && (t.value === "from" || t.value === "join")) {
      c.i++;
      fromDepth = depth;
      item();
      continue;
    }
    if (t.type === "punct" && t.value === "," && depth === fromDepth) {
      c.i++;
      item();
      continue;
    }
    if (t.type === "ident" && END.has(t.value) && depth === fromDepth) fromDepth = -1;
    c.i++;
  }
  return out;
}

/** "Literally true", ignoring whitespace and parentheses (spec 8.5). */
export function isLiteralTrue(expr: string | null): boolean {
  if (expr === null) return false;
  return expr.replace(/[\s()]/g, "").toLowerCase() === "true";
}

/** Build the end state from schema files (sorted) then migrations (sorted by file name). */
export function buildSupabaseModel(files: { file: string; text: string }[]): SupabaseModel {
  const model = emptyModel();
  for (const f of files) applySql(model, f.file, f.text);
  return model;
}
