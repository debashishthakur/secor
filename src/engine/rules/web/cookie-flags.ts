// web/cookie-flags: Session cookie missing flags (spec 8.5). Next.js cookies().set / response.cookies.set,
// Express res.cookie and express-session, Starlette / FastAPI set_cookie.

import { posix } from "node:path";
import type { Framework } from "../../../types.js";
import { anchorText, args, callee, enclosingFunction, exprPath, importOf, isCall, kwarg, objectProps, paramNames, positionalArgs, resolveLocal, stringValue, unwrap, walk } from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import { hasDep } from "../../deps.js";
import type { UnitInfo } from "../../detect.js";
import { findingId } from "../../finding.js";
import type { InventoryEntry } from "../../inventory-types.js";
import { langForFile, type ParsedFile, type SyntaxNode } from "../../parse.js";
import { renderTestTemplate, type TemplateVars } from "../../templates.js";
import { defineRule, SOURCES } from "../types.js";
import { editObjectText, evalString, hasPySplat, hasSpread, type ObjectFlagEdit, quoteStyle, rangeEdit, resolveObject, serviceFor, makePatch } from "./util.js";

const RULE_ID = "web/cookie-flags";
const WHY = "Without HttpOnly, Secure and SameSite a session cookie can be read by injected scripts, sent over plain HTTP, or sent along with requests from other sites.";
const NAME_RE = /session|sess|sid|token|auth|jwt|refresh/i;
/** CSRF double-submit cookies must be readable by scripts, so HttpOnly is not expected on them. */
const CSRF_RE = /csrf|xsrf/i;
const FLAGS = ["httpOnly", "secure", "sameSite"] as const;
type Flag = (typeof FLAGS)[number];

type SiteKind = "next" | "express" | "express-session" | "python";

interface CookieSite {
  kind: SiteKind;
  file: string;
  pf: ParsedFile;
  call: SyntaxNode;
  unit: UnitInfo;
}

export interface FlagResult {
  missing: Flag[];
  /** Flags whose value could not be determined (spread, unresolved options); they are not reported. */
  unknown: Flag[];
  patch?: string;
}

// ---------------------------------------------------------------- JS

function isCookiesCall(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  return !!u && isCall(u) && exprPath(callee(u)) === "cookies";
}

function classifyJsCall(pf: ParsedFile, call: SyntaxNode): SiteKind | null {
  const fn = callee(call);
  if (!fn) return null;
  if (fn.type === "identifier") {
    const imp = importOf(pf, fn.text);
    return imp && imp.source === "express-session" ? "express-session" : null;
  }
  if (fn.type !== "member_expression") return null;
  const method = fn.childForFieldName("property")?.text;
  const obj = unwrap(fn.childForFieldName("object"));
  if (!obj) return null;
  if (method === "set") {
    if (isCookiesCall(obj)) return "next";
    if (obj.type === "member_expression" && obj.childForFieldName("property")?.text === "cookies") {
      const owner = exprPath(obj.childForFieldName("object"));
      if (/^(?:req|request)$/.test(owner)) return null;
      return "next";
    }
    if (obj.type === "identifier") {
      const v = resolveLocal(pf, obj.text, obj);
      if (isCookiesCall(v)) return "next";
    }
    return null;
  }
  if (method === "cookie" && obj.type === "identifier" && args(call).length >= 2) {
    if (/^(?:res|response|resp)$/.test(obj.text)) return "express";
    const fnNode = enclosingFunction(call);
    if (fnNode && paramNames(fnNode)[1] === obj.text) return "express";
  }
  return null;
}

/** Cookie name for a set call: string constant, or the identifier text when it cannot be resolved. */
function jsCookieName(pf: ParsedFile, site: CookieSite): string | null {
  const a = args(site.call);
  const first = a[0] ?? null;
  if (!first) return null;
  const obj = unwrap(first)?.type === "object" ? unwrap(first) : null;
  const nameNode = obj ? (objectProps(obj).find((p) => p.key === "name")?.value ?? null) : first;
  if (!nameNode) return null;
  const v = evalString(pf, nameNode);
  if (v !== null) return v;
  const u = unwrap(nameNode);
  if (u?.type === "template_string") return u.text;
  return u && (u.type === "identifier" || u.type === "member_expression") ? exprPath(u) : null;
}

/** Evaluate the three flags on a JS options object (null = no options given). */
function jsFlags(pf: ParsedFile, obj: SyntaxNode | null, defaults: Partial<Record<Flag, boolean>>): { missing: Flag[]; unknown: Flag[]; existing: Map<Flag, SyntaxNode> } {
  const missing: Flag[] = [];
  const unknown: Flag[] = [];
  const existing = new Map<Flag, SyntaxNode>();
  const props = obj ? objectProps(obj) : [];
  const spread = obj ? hasSpread(obj) : false;
  for (const flag of FLAGS) {
    const p = props.find((x) => x.key === flag);
    if (!p) {
      if (defaults[flag]) continue;
      (spread ? unknown : missing).push(flag);
      continue;
    }
    existing.set(flag, p.node);
    const v = unwrap(p.value);
    if (v?.type === "false" || (v?.type === "identifier" && v.text === "undefined")) missing.push(flag);
  }
  return { missing, unknown, existing };
}

function jsFlagValue(flag: Flag, q: string): string {
  return flag === "sameSite" ? `${q}lax${q}` : "true";
}

function jsObjectPatch(source: string, file: string, obj: SyntaxNode, existing: Map<Flag, SyntaxNode>, q: string, flags: readonly Flag[]): string | undefined {
  const edits: ObjectFlagEdit[] = [];
  for (const flag of flags) {
    const node = existing.get(flag) ?? null;
    if (node) {
      const v = unwrap(node.childForFieldName("value"));
      // Non-literal values (e.g. secure: isProd) are left alone; only false / undefined are replaced.
      const ok = !!v && v.type !== "false" && !(v.type === "identifier" && v.text === "undefined");
      if (ok || node.type !== "pair") continue;
    }
    edits.push({ key: flag, value: jsFlagValue(flag, q), existing: node && node.type === "pair" ? node : null });
  }
  if (edits.length === 0) return undefined;
  const text = editObjectText(source, obj, edits);
  if (text === null) return undefined;
  return makePatch(file, source, [rangeEdit(source, obj.startIndex, obj.endIndex, text)]);
}

/** Flags the patch sets: all three, except HttpOnly on CSRF cookies (scripts must read those). */
function patchFlags(noHttpOnly: boolean): Flag[] {
  return FLAGS.filter((f) => !(noHttpOnly && f === "httpOnly"));
}

function jsOptionsText(flags: readonly Flag[], q: string): string {
  return `{ ${flags.map((f) => `${f}: ${jsFlagValue(f, q)}`).join(", ")} }`;
}

function jsSite(site: CookieSite, noHttpOnly = false): FlagResult | null {
  const { pf, call, file } = site;
  const want = patchFlags(noHttpOnly);
  const source = pf.source;
  const q = quoteStyle(pf);
  const a = args(call);
  if (site.kind === "express-session") {
    const opts = a[0] ? unwrap(a[0]) : null;
    const optsObj = opts ? resolveObject(pf, opts) : null;
    if (opts && !optsObj) return null;
    const cookieProp = optsObj ? objectProps(optsObj).find((p) => p.key === "cookie") : undefined;
    if (!cookieProp && optsObj && hasSpread(optsObj)) return null;
    const cookieObj = cookieProp ? resolveObject(pf, cookieProp.value) : null;
    if (cookieProp && !cookieObj) return null;
    // express-session sets HttpOnly by default (spec decision, see decisions-web.md).
    const r = jsFlags(pf, cookieObj, { httpOnly: true });
    let patch: string | undefined;
    if (cookieObj && unwrap(cookieProp!.value)?.type === "object") patch = jsObjectPatch(source, file, cookieObj, r.existing, q, want);
    else if (!cookieProp && optsObj && opts?.type === "object") {
      const value = jsOptionsText(want, q);
      const text = editObjectText(source, optsObj, [{ key: "cookie", value, existing: null }]);
      if (text !== null) patch = makePatch(file, source, [rangeEdit(source, optsObj.startIndex, optsObj.endIndex, text)]);
    }
    return { missing: r.missing, unknown: r.unknown, ...(patch ? { patch } : {}) };
  }
  // Options object: Next object form set({ name, value, ...opts }), or the third argument.
  const first = a[0] ? unwrap(a[0]) : null;
  const objectForm = site.kind === "next" && first?.type === "object";
  const optsNode = objectForm ? first : (a[2] ?? null);
  const optsObj = optsNode ? resolveObject(pf, optsNode) : null;
  if (optsNode && !optsObj) return null;
  const r = jsFlags(pf, optsObj, {});
  let patch: string | undefined;
  if (optsObj && unwrap(optsNode)?.type === "object") patch = jsObjectPatch(source, file, optsObj, r.existing, q, want);
  else if (!optsNode && a.length >= 2) {
    const last = a[a.length - 1]!;
    const ins = `, ${jsOptionsText(want, q)}`;
    patch = makePatch(file, source, [rangeEdit(source, last.endIndex, last.endIndex, ins)]);
  }
  return { missing: r.missing, unknown: r.unknown, ...(patch ? { patch } : {}) };
}

// ---------------------------------------------------------------- Python

const PY_FLAG: Record<Flag, string> = { httpOnly: "httponly", secure: "secure", sameSite: "samesite" };
const PY_POSITION: Record<Flag, number> = { secure: 6, httpOnly: 7, sameSite: 8 };

function pyCookieName(pf: ParsedFile, call: SyntaxNode): string | null {
  const node = kwarg(call, "key") ?? positionalArgs(call)[0] ?? null;
  if (!node) return null;
  const s = stringValue(node);
  if (s !== null) return s;
  const u = unwrap(node);
  if (u?.type === "identifier") {
    const v = stringValue(resolveLocal(pf, u.text, u));
    return v ?? u.text;
  }
  return u ? exprPath(u) : null;
}

function pySite(site: CookieSite, starlette: boolean, noHttpOnly = false): FlagResult | null {
  const { pf, call, file } = site;
  const source = pf.source;
  const splat = hasPySplat(call);
  const positional = positionalArgs(call);
  const missing: Flag[] = [];
  const unknown: Flag[] = [];
  const replace: { node: SyntaxNode; text: string }[] = [];
  const add: string[] = [];
  for (const flag of FLAGS) {
    const v = kwarg(call, PY_FLAG[flag]) ?? positional[PY_POSITION[flag]] ?? null;
    const u = unwrap(v);
    const patchIt = !(noHttpOnly && flag === "httpOnly");
    if (!u) {
      if (!patchIt) {
        (splat ? unknown : missing).push(flag);
        continue;
      }
      if (flag === "sameSite" && starlette) {
        // Starlette defaults samesite to "lax"; the patch still sets it explicitly.
        add.push(`samesite=${pyQuote(pf)}lax${pyQuote(pf)}`);
        continue;
      }
      (splat ? unknown : missing).push(flag);
      add.push(flag === "sameSite" ? `samesite=${pyQuote(pf)}lax${pyQuote(pf)}` : `${PY_FLAG[flag]}=True`);
      continue;
    }
    const isFalse = u.type === "false" || u.type === "none";
    if (isFalse) {
      missing.push(flag);
      if (patchIt) replace.push({ node: u, text: flag === "sameSite" ? `${pyQuote(pf)}lax${pyQuote(pf)}` : "True" });
    }
  }
  let patch: string | undefined;
  if (!splat && missing.some((f) => !(noHttpOnly && f === "httpOnly"))) {
    const argList = call.childForFieldName("arguments");
    const all = args(call);
    const last = all[all.length - 1];
    if (argList && last) {
      const base = argList.startIndex;
      let text = source.slice(argList.startIndex, argList.endIndex);
      const edits = [...replace.map((r) => ({ start: r.node.startIndex, end: r.node.endIndex, text: r.text })), ...(add.length ? [{ start: last.endIndex, end: last.endIndex, text: `, ${add.join(", ")}` }] : [])].sort((x, y) => y.start - x.start);
      for (const e of edits) text = text.slice(0, e.start - base) + e.text + text.slice(e.end - base);
      patch = makePatch(file, source, [rangeEdit(source, argList.startIndex, argList.endIndex, text)]);
    }
  }
  return { missing, unknown, ...(patch ? { patch } : {}) };
}

function pyQuote(pf: ParsedFile): string {
  return quoteStyle(pf);
}

// ---------------------------------------------------------------- cookie deletion

function isZeroOrPast(n: SyntaxNode | null): boolean {
  const u = unwrap(n);
  if (!u) return false;
  if ((u.type === "number" || u.type === "integer" || u.type === "float") && Number(u.text) <= 0) return true;
  if (u.type === "unary_expression" && u.text.trim().startsWith("-")) return true;
  // new Date(0) / datetime(1970, …)
  return /^new\s+Date\s*\(\s*0\s*\)$/.test(u.text) || /^(?:datetime\.)?datetime\(\s*1970\b/.test(u.text);
}

/** A set call that deletes the cookie: empty value, maxAge <= 0 or an expiry in the past. */
export function deletesCookie(site: { kind: SiteKind; pf: ParsedFile; call: SyntaxNode }): boolean {
  const { call, pf } = site;
  if (site.kind === "express-session") return false;
  if (site.kind === "python") {
    const value = kwarg(call, "value") ?? positionalArgs(call)[1] ?? null;
    if (value && stringValue(value) === "") return true;
    return isZeroOrPast(kwarg(call, "max_age")) || isZeroOrPast(kwarg(call, "expires"));
  }
  const a = args(call);
  const first = a[0] ? unwrap(a[0]) : null;
  const objectForm = first?.type === "object";
  const valueNode = objectForm ? (objectProps(first).find((p) => p.key === "value")?.value ?? null) : (a[1] ?? null);
  if (valueNode && stringValue(valueNode) === "") return true;
  const opts = objectForm ? first : resolveObject(pf, a[2] ?? null);
  const props = opts ? objectProps(opts) : [];
  return props.some((p) => (p.key === "maxAge" || p.key === "expires") && isZeroOrPast(p.value));
}

// ---------------------------------------------------------------- sites

function findSites(ctx: ProjectContext): CookieSite[] {
  const out: CookieSite[] = [];
  const seen = new Set<string>();
  const units = ctx.units.filter((u) => u.kind === "web" || u.kind === "api");
  for (const unit of units) {
    for (const file of unit.files) {
      if (seen.has(file)) continue;
      const lang = langForFile(file);
      if (!lang) continue;
      const text = ctx.read(file);
      if (text === null) continue;
      if (lang === "python") {
        if (!text.includes("set_cookie")) continue;
      } else if (!/cookie|express-session/i.test(text)) continue;
      seen.add(file);
      const pf = ctx.parse(file);
      if (!pf) continue;
      walk(pf.root, (n) => {
        if (lang === "python") {
          if (n.type === "call" && /(?:^|\.)set_cookie$/.test(exprPath(callee(n)))) out.push({ kind: "python", file, pf, call: n, unit });
          return true;
        }
        if (n.type !== "call_expression") return true;
        const kind = classifyJsCall(pf, n);
        if (kind) out.push({ kind, file, pf, call: n, unit });
        return true;
      });
    }
  }
  return out;
}

function isStarlette(site: CookieSite): boolean {
  if (/^\s*(?:from|import)\s+(?:flask|django|werkzeug)\b/m.test(site.pf.source)) return false;
  return site.unit.framework === "fastapi" || /^\s*(?:from|import)\s+(?:fastapi|starlette)\b/m.test(site.pf.source);
}

// ---------------------------------------------------------------- test templates

function entryFor(ctx: ProjectContext, site: CookieSite): InventoryEntry | null {
  const inside = (e: InventoryEntry) => e.internal.handlers.some((h) => h.file === site.file && h.node.startIndex <= site.call.startIndex && site.call.endIndex <= h.node.endIndex);
  return ctx.inventory.find(inside) ?? ctx.inventory.find((e) => e.file === site.file && e.kind === "http_route") ?? null;
}

function stripExt(file: string): string {
  return file.replace(/\.[cm]?[jt]sx?$/, "").replace(/\.py$/, "");
}

function appFile(ctx: ProjectContext, unit: UnitInfo, re: RegExp, lang: "js" | "py"): string | null {
  for (const f of ctx.codeFiles(unit, lang)) if (re.test(ctx.read(f) ?? "")) return f;
  return null;
}

export function cookieTestTemplate(ctx: ProjectContext, site: CookieSite, id: string): string | undefined {
  const entry = entryFor(ctx, site);
  const framework: Framework | null = entry?.framework ?? (["express", "nextjs", "fastapi"].includes(site.unit.framework) ? site.unit.framework : null);
  if (framework !== "express" && framework !== "nextjs" && framework !== "fastapi") return undefined;
  const vars: TemplateVars = {};
  const method = entry?.method && entry.method !== "*" ? entry.method : entry?.kind === "server_action" ? "POST" : "GET";
  vars.method = method;
  if (entry?.path) vars.path = entry.path;
  const flags = new Set<string>();
  if (framework === "express") {
    const app = appFile(ctx, site.unit, /=\s*express\s*\(\s*\)/, "js") ?? entry?.file ?? site.file;
    vars.importPath = posix.relative("tests/secor", stripExt(app));
    const jest = hasDep(site.unit.manifests, "npm", "jest") && !hasDep(site.unit.manifests, "npm", "vitest");
    flags.add(jest ? "jest" : "vitest");
  } else if (framework === "nextjs") {
    const file = entry?.file ?? site.file;
    vars.importPath = posix.relative("tests/secor", stripExt(file));
    vars.handlerExport = entry?.kind === "server_action" ? (entry.name?.split("#").pop() ?? "default") : (entry?.method ?? "POST");
  } else {
    const app = appFile(ctx, site.unit, /\bFastAPI\s*\(/, "py") ?? site.file;
    vars.importPath = stripExt(app).split("/").join(".");
  }
  return renderTestTemplate(RULE_ID, framework, id, vars, flags);
}

// ---------------------------------------------------------------- rule

export const cookieFlagsRule = defineRule({
  id: RULE_ID,
  title: "Session cookie missing flags",
  pack: "web",
  maturity: "experimental",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => ctx.hasUnit("web") || ctx.hasUnit("api"),
  check(ctx, emit) {
    for (const site of findSites(ctx)) {
      let result: FlagResult | null;
      let csrf = false;
      if (site.kind === "express-session") result = jsSite(site);
      else {
        const name = site.kind === "python" ? pyCookieName(site.pf, site.call) : jsCookieName(site.pf, site);
        if (name === null || !NAME_RE.test(name)) continue;
        if (deletesCookie(site)) continue;
        csrf = CSRF_RE.test(name);
        result = site.kind === "python" ? pySite(site, isStarlette(site), csrf) : jsSite(site, csrf);
        if (result && csrf) result = { ...result, missing: result.missing.filter((f) => f !== "httpOnly") };
      }
      if (!result || result.missing.length === 0) continue;
      const anchor = anchorText(site.call);
      const py = site.kind === "python";
      const listed = result.missing.map((f) => (py ? PY_FLAG[f] : f)).join(", ");
      const set = patchFlags(csrf)
        .map((f) => (py ? `${PY_FLAG[f]}=${f === "sameSite" ? '"lax"' : "True"}` : `${f}: ${jsFlagValue(f, '"')}`))
        .join(", ");
      const what = site.kind === "express-session" ? "the express-session cookie" : "this cookie";
      const testTemplate = cookieTestTemplate(ctx, site, findingId(RULE_ID, site.file, anchor));
      emit({
        severity: "medium",
        service: serviceFor(ctx, site.file),
        file: site.file,
        line: site.call.startPosition.row + 1,
        endLine: site.call.endPosition.row + 1,
        anchor,
        evidence: site.call.text,
        why: WHY,
        fix: {
          summary: `Set ${set} on ${what} (missing: ${listed}).`,
          ...(result.patch ? { patch: result.patch } : {}),
          ...(testTemplate ? { testTemplate } : {}),
        },
      });
    }
  },
});
