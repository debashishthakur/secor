// Next.js adapter (spec section 8.2): route handlers, pages-router API routes, server actions,
// pages, and middleware.{ts,js} / proxy.{ts,js} coverage (section 8.3).

import {
  args,
  callee,
  calleeName,
  callsIn,
  descendants,
  elements,
  exportsOf,
  exprPath,
  functionBody,
  functionName,
  hasDirective,
  isAsyncFunction,
  isCall,
  isFunction,
  kids,
  objectProps,
  paramNames,
  params,
  prop,
  resolveFunction,
  stringValue,
  topLevel,
  unwrap,
  walk,
} from "../ast.js";
import type { GuardMatcher } from "../auth-guards.js";
import type { HandlerRef } from "../inventory-types.js";
import type { ParsedFile, SyntaxNode } from "../parse.js";
import { nextSegmentsToPath } from "./paths.js";
import type { AdapterContext, RawEntry } from "./types.js";

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function relToRoot(root: string, file: string): string {
  return root ? file.slice(root.length + 1) : file;
}

export function nextjsAdapter(a: AdapterContext): RawEntry[] {
  const { ctx, unit, guards } = a;
  const out: RawEntry[] = [];
  const mw = nextMiddleware(a);

  for (const file of unit.files) {
    const r = relToRoot(unit.root, file);
    const appMatch = /^(?:src\/)?app\/(.*)$/.exec(r);
    const pagesMatch = /^(?:src\/)?pages\/(.*)$/.exec(r);

    if (unit.kind === "api") {
      // App router route handlers.
      const route = appMatch && /^(?:(.*)\/)?route\.(?:ts|js|tsx|jsx|mjs)$/.exec(appMatch[1]!);
      if (route) {
        const pf = ctx.parse(file);
        if (!pf) continue;
        const path = nextSegmentsToPath((route[1] ?? "").split("/"));
        const exps = exportsOf(pf);
        for (const method of HTTP_METHODS) {
          const value = exps.get(method);
          if (!value) continue;
          const { handlers, wrappers } = unwrapHandler(value, pf);
          const regNode = exportNode(pf, method) ?? value;
          out.push(entry(a, { kind: "http_route", method, path, file, pf, regNode, handlers, wrappers }, mw));
        }
        continue;
      }
      // Pages router API routes.
      const api = pagesMatch && /^api\/(.*)\.(?:ts|js|tsx|jsx|mjs)$/.exec(pagesMatch[1]!);
      if (api) {
        const pf = ctx.parse(file);
        if (!pf) continue;
        const segs = api[1]!.split("/");
        if (segs[segs.length - 1] === "index") segs.pop();
        const path = nextSegmentsToPath(["api", ...segs]);
        const value = exportsOf(pf).get("default");
        if (!value) continue;
        const { handlers, wrappers } = unwrapHandler(value, pf);
        const methods = handlers[0] ? branchedMethods(handlers[0].node) : [];
        const regNode = exportNode(pf, "default") ?? value;
        if (methods.length === 0) out.push(entry(a, { kind: "http_route", method: "*", path, file, pf, regNode, handlers, wrappers }, mw));
        else for (const m of methods) out.push(entry(a, { kind: "http_route", method: m.method, path, file, pf, regNode, handlers, wrappers, methodBranch: m.branch }, mw));
        continue;
      }
      // Server actions.
      if (/\.(?:ts|tsx|js|jsx|mjs)$/.test(file) && (ctx.read(file) ?? "").includes("use server")) {
        const pf = ctx.parse(file);
        if (!pf) continue;
        if (hasDirective(pf.root, "use server")) {
          for (const [name, value] of exportsOf(pf)) {
            const fn = resolveFunction(pf, value);
            if (!fn || !isAsyncFunction(fn)) continue;
            out.push(entry(a, { kind: "server_action", name: `${file}#${name}`, file, pf, regNode: exportNode(pf, name) ?? fn, handlers: [{ file, pf, node: fn }], wrappers: [] }, mw));
          }
        } else {
          walk(pf.root, (n) => {
            if (isFunction(n) && hasDirective(n, "use server")) {
              const name = functionName(n) ?? `action@L${n.startPosition.row + 1}`;
              out.push(entry(a, { kind: "server_action", name: `${file}#${name}`, file, pf, regNode: n, handlers: [{ file, pf, node: n }], wrappers: [] }, mw));
              return false;
            }
            return true;
          });
        }
      }
    } else {
      // Pages (web unit).
      const page = appMatch && /^(?:(.*)\/)?page\.(?:tsx|jsx|ts|js)$/.exec(appMatch[1]!);
      const legacy = pagesMatch && !pagesMatch[1]!.startsWith("api/") && /\.(?:tsx|jsx|ts|js)$/.test(pagesMatch[1]!) ? pagesMatch[1]! : null;
      if (page || legacy) {
        if (legacy && legacy.split("/").pop()!.startsWith("_")) continue;
        const pf = ctx.parse(file);
        if (!pf) continue;
        let path: string;
        if (page) path = nextSegmentsToPath((page[1] ?? "").split("/"));
        else {
          const segs = legacy!.replace(/\.(?:tsx|jsx|ts|js)$/, "").split("/");
          if (segs[segs.length - 1] === "index") segs.pop();
          path = nextSegmentsToPath(segs);
        }
        const value = exportsOf(pf).get("default");
        const { handlers, wrappers } = value ? unwrapHandler(value, pf) : { handlers: [], wrappers: [] };
        out.push(entry(a, { kind: "page", path, file, pf, regNode: value ?? pf.root, handlers, wrappers }, mw));
      }
    }
  }
  return out;

  function entry(
    ad: AdapterContext,
    e: { kind: RawEntry["kind"]; method?: string; path?: string; name?: string; file: string; pf: ParsedFile; regNode: SyntaxNode; handlers: HandlerRef[]; wrappers: string[]; methodBranch?: SyntaxNode },
    mwInfo: MiddlewareInfo | null,
  ): RawEntry {
    const covered = !!mwInfo && mwInfo.guarded && e.path !== undefined && mwInfo.covers(e.path) && e.kind !== "server_action";
    return {
      kind: e.kind,
      service: e.kind === "page" ? "web" : "api",
      framework: "nextjs",
      ...(e.method ? { method: e.method } : {}),
      ...(e.path !== undefined ? { path: e.path } : {}),
      ...(e.name ? { name: e.name } : {}),
      file: e.file,
      line: e.regNode.startPosition.row + 1,
      handlers: e.handlers,
      middleware: [],
      wrappers: e.wrappers,
      registration: { file: e.file, pf: e.pf, node: e.regNode },
      middlewareCovered: covered,
      ...(mwInfo?.rateLimited && e.path !== undefined && e.kind !== "server_action" && mwInfo.covers(e.path) ? { rateLimited: true } : {}),
      ...(e.methodBranch ? { methodBranch: e.methodBranch } : {}),
      ...(covered ? { auth: handlerGuard(e.handlers, e.wrappers, ad.guards) ?? { guarded: true, via: "middleware" as const, guard: mwInfo!.guard } } : {}),
    };
  }
}

/** If the handler itself is guarded (call or wrapper), that wins over middleware coverage. */
function handlerGuard(handlers: HandlerRef[], wrappers: string[], guards: GuardMatcher): RawEntry["auth"] | null {
  for (const w of wrappers) if (guards.isGuardWrapper(w, "nextjs")) return { guarded: true, via: "handler", guard: w };
  for (const h of handlers) {
    for (const c of callsIn(h.node)) {
      const g = guards.guardCall(c, "nextjs");
      if (g) return { guarded: true, via: "handler", guard: g };
    }
  }
  return null;
}

function exportNode(pf: ParsedFile, name: string): SyntaxNode | null {
  const d = topLevel(pf).get(name);
  if (d) return d.node;
  for (const stmt of kids(pf.root)) {
    if (stmt.type !== "export_statement") continue;
    if (name === "default" && /^export\s+default\b/.test(stmt.text)) return stmt;
    const clause = kids(stmt).find((c) => c.type === "export_clause");
    if (clause && kids(clause).some((s) => (s.childForFieldName("alias") ?? s.childForFieldName("name"))?.text === name)) return stmt;
  }
  return null;
}

/** Unwrap `withAuth(handler)` / `auth(async (req) => ...)` to the inner function(s), remembering wrapper names. */
export function unwrapHandler(value: SyntaxNode, pf: ParsedFile): { handlers: HandlerRef[]; wrappers: string[] } {
  const wrappers: string[] = [];
  let cur: SyntaxNode | null = unwrap(value);
  for (let depth = 0; cur && depth < 4; depth++) {
    if (isFunction(cur)) return { handlers: [{ file: pf.file, pf, node: cur }], wrappers };
    if (cur.type === "identifier") {
      const fn = resolveFunction(pf, cur);
      if (fn) return { handlers: [{ file: pf.file, pf, node: fn }], wrappers };
      const decl = topLevel(pf).get(cur.text);
      cur = decl ? unwrap(decl.value) : null;
      continue;
    }
    if (isCall(cur)) {
      wrappers.push(calleeName(cur));
      const inner = args(cur).find((x) => {
        const u = unwrap(x);
        return isFunction(u) || u?.type === "identifier";
      });
      cur = inner ? unwrap(inner) : null;
      continue;
    }
    break;
  }
  return { handlers: [], wrappers };
}

/** Methods a pages-router handler branches on (`req.method === 'POST'`, `switch (req.method)`), with the branch node. */
export function branchedMethods(fn: SyntaxNode): { method: string; branch: SyntaxNode }[] {
  const reqName = paramNames(fn)[0] ?? "req";
  const out = new Map<string, SyntaxNode>();
  const isMethodExpr = (n: SyntaxNode | null) => !!n && exprPath(unwrap(n)) === `${reqName}.method`;
  const body = functionBody(fn);
  if (!body) return [];
  walk(body, (n) => {
    if (n.type === "binary_expression") {
      const op = n.childForFieldName("operator")?.text;
      const l = n.childForFieldName("left");
      const r = n.childForFieldName("right");
      const lit = isMethodExpr(l) ? stringValue(r) : isMethodExpr(r) ? stringValue(l) : null;
      if (lit && (op === "===" || op === "==")) {
        const branch = n.parent?.type === "parenthesized_expression" && n.parent.parent?.type === "if_statement" ? n.parent.parent : n;
        if (!out.has(lit.toUpperCase())) out.set(lit.toUpperCase(), branch);
      } else if (lit && (op === "!==" || op === "!=")) {
        // `if (req.method !== 'POST') return 405` → only POST is handled.
        if (!out.has(lit.toUpperCase())) out.set(lit.toUpperCase(), fn);
      }
    } else if (n.type === "switch_statement" && isMethodExpr(n.childForFieldName("value"))) {
      for (const c of descendants(n, "switch_case")) {
        const v = stringValue(c.childForFieldName("value"));
        if (v && !out.has(v.toUpperCase())) out.set(v.toUpperCase(), c);
      }
    }
    return true;
  });
  const found = [...out.entries()].filter(([m]) => HTTP_METHODS.includes(m)).map(([method, branch]) => ({ method, branch }));
  // Code after the method branches (or a switch default) serves every other method: add a "*" entry for it,
  // unless that code only rejects them (405 / Method Not Allowed).
  if (found.length && found.every((f) => f.branch.id !== fn.id) && hasFallThrough(body)) found.push({ method: "*", branch: fn });
  return found;
}

function hasFallThrough(body: SyntaxNode): boolean {
  const rejects = (t: string) => /\b405\b|method not allowed|setHeader\(\s*["']Allow/i.test(t);
  const sw = descendants(body, "switch_statement")[0];
  if (sw) {
    const dflt = descendants(sw, "switch_default")[0];
    return !!dflt && !rejects(dflt.text);
  }
  const stmts = kids(body);
  let last = -1;
  stmts.forEach((st, i) => {
    if (st.type === "if_statement" && /\.method\b/.test(st.childForFieldName("condition")?.text ?? "")) last = i;
  });
  if (last < 0) return false;
  const rest = stmts.slice(last + 1);
  const lastIf = stmts[last]!;
  const hasElse = !!lastIf.childForFieldName("alternative");
  if (hasElse) return !rejects(lastIf.childForFieldName("alternative")!.text);
  return rest.length > 0 && !rejects(rest.map((r) => r.text).join("\n"));
}

// ---------------------------------------------------------------- middleware.ts / proxy.ts

export interface MiddlewareInfo {
  file: string;
  guarded: boolean;
  guard?: string;
  /** The middleware applies rate limiting (Upstash `ratelimit.limit(`, a configured helper) — section 8.3. */
  rateLimited: boolean;
  matchers: RegExp[] | null;
  covers(path: string): boolean;
}

export function nextMiddleware(a: AdapterContext): MiddlewareInfo | null {
  const { ctx, unit, guards } = a;
  const prefix = unit.root ? `${unit.root}/` : "";
  const candidates = ["middleware", "proxy"].flatMap((n) => ["", "src/"].flatMap((d) => ["ts", "js"].map((e) => `${prefix}${d}${n}.${e}`)));
  const file = candidates.find((f) => ctx.hasFile(f));
  if (!file) return null;
  const pf = ctx.parse(file);
  if (!pf) return null;
  let guard: string | undefined;
  for (const c of callsIn(pf.root)) {
    const g = guards.guardCall(c, "nextjs");
    if (g) {
      guard = g;
      break;
    }
  }
  if (!guard) {
    // Auth.js: `export { auth as middleware }`, `export default auth(...)`; next-auth/middleware `withAuth`.
    const exps = exportsOf(pf);
    for (const key of ["middleware", "proxy", "default"]) {
      const v = exps.get(key);
      if (!v) continue;
      const u = unwrap(v);
      const name = u ? (isCall(u) ? calleeName(u) : u.type === "export_specifier" ? (u.childForFieldName("name")?.text ?? "") : u.text) : "";
      if (guards.isGuardWrapper(name, "nextjs")) {
        guard = name;
        break;
      }
    }
    if (!guard && /export\s*\{\s*(?:default|auth)\s+as\s+(?:middleware|proxy|default)\s*\}/.test(pf.source)) guard = "auth";
    if (!guard && /from\s+["']next-auth\/middleware["']/.test(pf.source)) guard = "next-auth/middleware";
  }
  const rateLimited = callsIn(pf.root).some((c) => {
    const name = calleeName(c);
    if (guards.isRateLimitHelper(name)) return true;
    return name === "limit" && /ratelimit|limiter/i.test(exprPath(callee(c)?.childForFieldName("object") ?? null));
  });
  const matchers = readMatchers(pf);
  return {
    file,
    guarded: !!guard,
    guard,
    rateLimited,
    matchers,
    covers(path: string) {
      if (!matchers) return true;
      const sample = path.replace(/:\w+\*\??/g, "x/y").replace(/:\w+\??/g, "x");
      return matchers.some((re) => re.test(sample));
    },
  };
}

function readMatchers(pf: ParsedFile): RegExp[] | null {
  const config = topLevel(pf).get("config");
  if (!config) return null;
  const m = prop(config.value, "matcher");
  if (!m) return null;
  const sources: string[] = [];
  const s = stringValue(m);
  if (s !== null) sources.push(s);
  for (const e of elements(m)) {
    const v = stringValue(e) ?? stringValue(prop(e, "source"));
    if (v !== null) sources.push(v);
  }
  if (sources.length === 0) return null;
  return sources.map(nextMatcherToRegExp);
}

/** Convert a Next.js (path-to-regexp) matcher to a RegExp: `:p`, `:p*`, `:p+`, `:p?` and raw `(...)` groups. */
export function nextMatcherToRegExp(pattern: string): RegExp {
  let out = "";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i]!;
    if (c === "/" && pattern[i + 1] === ":") {
      const m = /^\/:(\w+)(\([^)]*\))?([*+?])?/.exec(pattern.slice(i));
      if (m) {
        const seg = m[2] ? m[2] : "[^/]+";
        const mod = m[3];
        if (mod === "*") out += `(?:/${seg})*`;
        else if (mod === "+") out += `(?:/${seg})+`;
        else if (mod === "?") out += `(?:/${seg})?`;
        else out += `/${seg}`;
        i += m[0].length;
        continue;
      }
    }
    if (c === "(") {
      let depth = 0;
      let j = i;
      for (; j < pattern.length; j++) {
        if (pattern[j] === "\\") {
          j++;
          continue;
        }
        if (pattern[j] === "(") depth++;
        else if (pattern[j] === ")") {
          depth--;
          if (depth === 0) break;
        }
      }
      out += pattern.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (c === "*") {
      out += ".*";
      i++;
      continue;
    }
    out += c.replace(/[.+?^${}|[\]\\]/g, "\\$&");
    i++;
  }
  try {
    return new RegExp(`^${out}/?$`);
  } catch {
    return /^$/;
  }
}

export { callee, objectProps, params };
