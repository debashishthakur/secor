// Auth, ownership, paid-API, rate-limit and database-call detection (spec section 8.3).

import type { Framework } from "../types.js";
import { args, callee, calleeName, calleePath, callsIn, exprPath, importOf, isCall, kids, positionalArgs, resolveFunction, stringValue, unwrap, walk } from "./ast.js";
import type { ParsedFile, SyntaxNode } from "./parse.js";

export const GUARD_REGEX = /^(?:require|ensure|assert|verify)(?:Auth|Authenticated|User|Session|Login|Admin)\w*$/;
const WRAPPER_GUARD_REGEX = /^with\w*(?:Auth|Session|User|Login)\w*$/;

const NEXT_GUARDS = new Set(["auth", "getServerSession", "currentUser", "getKindeServerSession"]);
const EXPRESS_GUARDS = new Set([
  "requireAuth",
  "isAuthenticated",
  "ensureAuthenticated",
  "authenticate",
  "authMiddleware",
  "verifyToken",
  "checkJwt",
  "requireUser",
  "protect",
  // MCP SDK bearer-token middleware also guards Express routes (DECISIONS.md).
  "requireBearerAuth",
]);
const FASTAPI_GUARDS = new Set(["get_current_user", "get_current_active_user", "verify_token", "require_auth"]);
const FASTAPI_GUARD_REGEX = /^(?:get_current_|require_|verify_|ensure_)\w*/;
export const FASTAPI_SECURITY_CLASSES = new Set([
  "OAuth2PasswordBearer",
  "HTTPBearer",
  "APIKeyHeader",
  "OAuth2AuthorizationCodeBearer",
  "HTTPBasic",
  "HTTPDigest",
  "APIKeyCookie",
  "APIKeyQuery",
  "OpenIdConnect",
]);

export class GuardMatcher {
  private readonly extra: Set<string>;
  private readonly ownership: Set<string>;
  private readonly rateHelpers: Set<string>;

  constructor(config: { guards: readonly string[]; ownershipHelpers: readonly string[]; rateLimitHelpers: readonly string[] }) {
    this.extra = new Set(config.guards);
    this.ownership = new Set(config.ownershipHelpers);
    this.rateHelpers = new Set(config.rateLimitHelpers);
  }

  /** Is a bare name a guard for this framework (defaults + config + the generic pattern)? */
  isGuardName(name: string, framework: Framework): boolean {
    if (!name) return false;
    if (this.extra.has(name) || GUARD_REGEX.test(name)) return true;
    switch (framework) {
      case "nextjs":
        return NEXT_GUARDS.has(name);
      case "express":
      case "mcp-ts":
        return EXPRESS_GUARDS.has(name);
      case "fastapi":
      case "mcp-py":
        return FASTAPI_GUARDS.has(name) || FASTAPI_GUARD_REGEX.test(name);
      default:
        return false;
    }
  }

  /** A wrapper such as `withAuth(handler)` that is named like a guard. */
  isGuardWrapper(name: string, framework: Framework): boolean {
    return this.isGuardName(name, framework) || WRAPPER_GUARD_REGEX.test(name);
  }

  /** If `call` is a guard call in handler code, return its label. */
  guardCall(call: SyntaxNode, framework: Framework): string | null {
    const path = calleePath(call);
    const name = calleeName(call);
    if (framework === "nextjs") {
      if (/(?:^|\.)auth\.getUser\(?\)?$/.test(path) || /\.auth\.getUser$/.test(path)) return "auth.getUser";
      if (path === "auth.protect" || path === "auth().protect") return "auth.protect";
    }
    if (framework === "express" || framework === "mcp-ts") {
      if (/(?:^|\.)passport\.authenticate$/.test(path)) return "passport.authenticate";
      if (name === "expressjwt") return "expressjwt";
    }
    if (this.isGuardName(name, framework)) return name;
    return null;
  }

  /** If a middleware expression (identifier, call, member) is a guard, return its label. */
  guardExpr(expr: SyntaxNode, framework: Framework): string | null {
    const u = unwrap(expr);
    if (!u) return null;
    if (isCall(u)) return this.guardCall(u, framework);
    const path = exprPath(u);
    const last = path.split(".").pop() ?? path;
    if (this.isGuardName(last, framework)) return last;
    return null;
  }

  isOwnershipHelper(name: string): boolean {
    return this.ownership.has(name);
  }

  isRateLimitHelper(name: string): boolean {
    return this.rateHelpers.has(name);
  }
}

// ---------------------------------------------------------------- paid API calls

const PAID_PATH = /(?:^|\.)(?:chat\.completions\.create|responses\.create|images\.generate|messages\.create)$/;
const AI_SDK_FUNCS = new Set(["generateText", "streamText", "generateObject", "streamObject"]);
const PAID_HOSTS = /\b(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com)\b/;

export function isPaidApiCall(call: SyntaxNode, pf: ParsedFile): boolean {
  const path = calleePath(call);
  if (PAID_PATH.test(path)) return true;
  const name = calleeName(call);
  if (AI_SDK_FUNCS.has(name) && path === name) {
    const imp = importOf(pf, name);
    if (imp && imp.source === "ai") return true;
  }
  if (/^(?:fetch|axios(?:\.\w+)?|httpx\.\w+|requests\.\w+|client\.(?:get|post))$/.test(path) || /\.(?:get|post)$/.test(path)) {
    const first = args(call)[0];
    if (first && PAID_HOSTS.test(first.text)) return true;
  }
  return false;
}

/** Calls in `fn`, plus calls in same-file functions it calls (one level deep), per section 8.3. */
export function callsOneLevel(fn: SyntaxNode, pf: ParsedFile): SyntaxNode[] {
  const direct = callsIn(fn);
  const out = [...direct];
  const seen = new Set<number>([fn.id]);
  for (const c of direct) {
    const target = callee(c);
    if (!target || target.type !== "identifier") continue;
    const f = resolveFunction(pf, target, c);
    if (f && !seen.has(f.id)) {
      seen.add(f.id);
      out.push(...callsIn(f));
    }
  }
  return out;
}

export function callsPaidApi(fn: SyntaxNode, pf: ParsedFile): boolean {
  return callsOneLevel(fn, pf).some((c) => isPaidApiCall(c, pf));
}

// ---------------------------------------------------------------- rate limiting

/** Is this middleware expression a rate limiter: rateLimit()/slowDown(), a variable assigned from one, or a configured helper? */
export function isRateLimitExpr(expr: SyntaxNode, pf: ParsedFile, guards: GuardMatcher): boolean {
  const u = unwrap(expr);
  if (!u) return false;
  if (isCall(u)) {
    const name = calleeName(u);
    return name === "rateLimit" || name === "slowDown" || guards.isRateLimitHelper(name);
  }
  if (u.type === "identifier") {
    if (guards.isRateLimitHelper(u.text)) return true;
    const decl = resolveDecl(pf, u.text);
    if (decl && isCall(decl)) {
      const name = calleeName(decl);
      return name === "rateLimit" || name === "slowDown" || guards.isRateLimitHelper(name);
    }
  }
  return false;
}

function resolveDecl(pf: ParsedFile, name: string): SyntaxNode | null {
  let found: SyntaxNode | null = null;
  walk(pf.root, (n) => {
    if (found) return false;
    if (n.type === "variable_declarator" && n.childForFieldName("name")?.text === name) found = unwrap(n.childForFieldName("value"));
    return true;
  });
  return found;
}

/** Rate limiting inside handler code: Upstash `ratelimit.limit(`, slowapi decorators, or configured helpers. */
export function handlerRateLimited(fn: SyntaxNode, pf: ParsedFile, guards: GuardMatcher): boolean {
  for (const c of callsOneLevel(fn, pf)) {
    const name = calleeName(c);
    if (guards.isRateLimitHelper(name)) return true;
    if (name === "limit") {
      const recv = exprPath(callee(c)?.childForFieldName("object") ?? null);
      if (/ratelimit|limiter/i.test(recv)) return true;
    }
  }
  return false;
}

/** Python: a decorator list containing `@limiter.limit(...)`. */
export function pyDecoratorRateLimited(decorators: readonly SyntaxNode[]): boolean {
  return decorators.some((d) => /^@\s*\w*limiter\w*\.limit\s*\(/i.test(d.text));
}

// ---------------------------------------------------------------- database calls

export interface DbCall {
  call: SyntaxNode;
  op: "read" | "write";
  /** create | update | upsert | delete | insert | find | select | raw */
  verb: string;
  orm: "prisma" | "drizzle" | "supabase" | "mongoose" | "sqlalchemy" | "knex" | "sql" | "other";
  /** Argument holding the data written (create/update/insert), when identifiable. */
  dataArg: SyntaxNode | null;
}

const PRISMA_WRITE = new Set(["create", "createMany", "createManyAndReturn", "update", "updateMany", "updateManyAndReturn", "upsert", "delete", "deleteMany"]);
const PRISMA_READ = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany"]);
const MONGOOSE_WRITE = new Set(["findByIdAndUpdate", "findByIdAndDelete", "findOneAndUpdate", "findOneAndDelete", "updateOne", "updateMany", "deleteOne", "deleteMany", "insertMany", "replaceOne"]);
const MONGOOSE_READ = new Set(["findById", "findOne", "find"]);
const DB_RECEIVER = /^(?:db|tx|trx|database|drizzle|knex|conn|connection|pool|client|sql|prisma|supabase|session|cursor|cur|engine)$/i;
const SQL_WRITE = /^\s*(?:insert|update|delete|replace|merge|upsert)\b/i;

/** Classify a call as a database read or write (heuristic; see DECISIONS.md). */
export function classifyDbCall(call: SyntaxNode): DbCall | null {
  const path = calleePath(call);
  const segs = path.replace(/\(\)/g, "").split(".");
  const name = segs[segs.length - 1] ?? "";
  const recv = segs.slice(0, -1);
  const a = positionalArgs(call);
  // Supabase: .from(x).insert/update/upsert/delete/select
  if (/\.from\(\)\.(?:insert|update|upsert|delete|select)$/.test(path) || /\.from\(\)\..*\.(?:insert|update|upsert|delete)$/.test(path)) {
    const op = name === "select" ? "read" : "write";
    return { call, op, verb: name === "select" ? "select" : name, orm: "supabase", dataArg: op === "write" && name !== "delete" ? (a[0] ?? null) : null };
  }
  // Prisma: prisma.<model>.<op>( or tx.<model>.<op>(
  if (recv.length >= 2 && (PRISMA_WRITE.has(name) || PRISMA_READ.has(name)) && !path.includes("()")) {
    const isWrite = PRISMA_WRITE.has(name);
    const dataObj = a[0] ?? null;
    return { call, op: isWrite ? "write" : "read", verb: name, orm: "prisma", dataArg: isWrite ? dataObj : null };
  }
  // Drizzle: db.insert(t).values(x) / db.update(t).set(x) / db.delete(t) / db.select().from(t)
  if (/^\w+\.insert\(\)\.values$/.test(path)) return { call, op: "write", verb: "insert", orm: "drizzle", dataArg: a[0] ?? null };
  if (/^\w+\.update\(\)\.set$/.test(path)) return { call, op: "write", verb: "update", orm: "drizzle", dataArg: a[0] ?? null };
  if (/^\w+\.delete$/.test(path) && DB_RECEIVER.test(recv[0] ?? "")) return { call, op: "write", verb: "delete", orm: "drizzle", dataArg: null };
  if (/^\w+\.select\(\)\.from$/.test(path) || /\.select\(\)\.from\(\)\.where$/.test(path)) return { call, op: "read", verb: "select", orm: "drizzle", dataArg: null };
  // Mongoose
  if (MONGOOSE_WRITE.has(name)) return { call, op: "write", verb: name, orm: "mongoose", dataArg: a[1] ?? a[0] ?? null };
  if (MONGOOSE_READ.has(name) && recv.length === 1 && /^[A-Z]/.test(recv[0] ?? "")) return { call, op: "read", verb: name, orm: "mongoose", dataArg: null };
  if (name === "create" && recv.length === 1 && /^[A-Z]/.test(recv[0] ?? "")) return { call, op: "write", verb: "create", orm: "mongoose", dataArg: a[0] ?? null };
  if (name === "save" && a.length === 0 && recv.length >= 1 && !/^(?:localStorage|sessionStorage)$/.test(recv[0] ?? "")) return { call, op: "write", verb: "save", orm: "mongoose", dataArg: null };
  // Knex: knex('t').insert(x) / .update(x) / .del()
  if (/^(?:knex|db|trx)\(\)\.(?:insert|update|del|delete)$/.test(path)) return { call, op: "write", verb: name, orm: "knex", dataArg: a[0] ?? null };
  // SQLAlchemy: session.add(x) / session.delete(x) / session.merge(x) / session.get(Model, id) / .query(Model)...
  if (recv.length >= 1 && /^(?:session|db|db_session|s)$/i.test(recv[recv.length - 1] ?? "")) {
    if (["add", "add_all", "merge", "delete", "bulk_save_objects"].includes(name)) return { call, op: "write", verb: name, orm: "sqlalchemy", dataArg: a[0] ?? null };
    if (name === "get") return { call, op: "read", verb: "get", orm: "sqlalchemy", dataArg: null };
  }
  // Raw SQL: query/execute with an INSERT/UPDATE/DELETE string
  if (["query", "execute", "executemany", "$executeRaw", "$executeRawUnsafe", "run", "exec"].includes(name)) {
    const first = a[0];
    const text = first ? (stringValue(first) ?? first.text.replace(/^[`"'fFrRbBuU]+/, "")) : "";
    if (SQL_WRITE.test(text)) return { call, op: "write", verb: "raw", orm: "sql", dataArg: a[1] ?? null };
    if (/^\s*select\b/i.test(text)) return { call, op: "read", verb: "raw", orm: "sql", dataArg: null };
  }
  return null;
}

export function dbCallsIn(fn: SyntaxNode, pf: ParsedFile, oneLevel = true): DbCall[] {
  const calls = oneLevel ? callsOneLevel(fn, pf) : callsIn(fn);
  const out: DbCall[] = [];
  for (const c of calls) {
    const d = classifyDbCall(c);
    if (d) out.push(d);
  }
  return out;
}

// ---------------------------------------------------------------- user identity values

const IDENTITY_JS = [/\bsession\??\.user\??\.id\b/, /\bauth\(\)\??\.userId\b/, /\breq\.user\??\.(?:id|_id)\b/, /\breq\.auth\??\.(?:userId|sub)\b/];

/**
 * Does the text reference a user identity value (section 8.3)? The fixed patterns cover Express and
 * Auth.js sessions; `extra` holds identifiers the caller traced to a guard call (`const { userId } = await auth()`,
 * `const user = await currentUser()` → "user.id"), and FastAPI params bound to guard dependencies (→ "<param>.id").
 */
export function referencesIdentity(text: string, lang: "js" | "py", extra: readonly string[] = []): boolean {
  if (lang === "js" && IDENTITY_JS.some((re) => re.test(text))) return true;
  return extra.some((p) => new RegExp(`(?<![\\w.])${p.replace(/[.$]/g, "\\$&")}(?![\\w])`).test(text));
}

/**
 * Identity expressions bound from guard calls in a JS handler: `const { userId } = await auth()` → "userId",
 * `const session = await getServerSession()` → "session.user.id", `const user = await currentUser()` → "user.id",
 * `const { data: { user } } = await supabase.auth.getUser()` → "user.id".
 */
export function identityBindings(fn: SyntaxNode, framework: Framework, guards: GuardMatcher): string[] {
  const out: string[] = [];
  const bind = (local: string, key: string) => {
    if (key === "userId" || key === "sub" || key === "user_id") out.push(local);
    else out.push(`${local}.id`, `${local}.user.id`, `${local}.userId`, `${local}.sub`);
  };
  const collect = (pat: SyntaxNode, keyHint: string | null): void => {
    switch (pat.type) {
      case "identifier":
        bind(pat.text, keyHint ?? pat.text);
        return;
      case "shorthand_property_identifier_pattern":
        bind(pat.text, pat.text);
        return;
      case "pair_pattern": {
        const value = pat.childForFieldName("value");
        if (value) collect(value, pat.childForFieldName("key")?.text ?? null);
        return;
      }
      case "assignment_pattern":
      case "object_assignment_pattern": {
        const left = pat.childForFieldName("left");
        if (left) collect(left, keyHint);
        return;
      }
      default:
        for (const k of kids(pat)) collect(k, null);
    }
  };
  walk(fn, (n) => {
    if (n.type !== "variable_declarator") return true;
    const value = unwrap(n.childForFieldName("value"));
    const name = n.childForFieldName("name");
    if (value && name && isCall(value) && guards.guardCall(value, framework)) collect(name, null);
    return true;
  });
  return [...new Set(out)];
}

export function firstStringArg(call: SyntaxNode): string | null {
  return stringValue(args(call)[0] ?? null);
}

export { kids };
