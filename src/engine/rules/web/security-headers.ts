// web/security-headers: Security header missing (spec 8.5). Header sources: next.config headers(),
// vercel.json, netlify.toml [[headers]], _headers / public/_headers, Express helmet(), and explicit
// header assignments in middleware.

import { parse as parseToml } from "smol-toml";
import { args, callee, elements, exportsOf, exprPath, functionBody, importOf, isCall, isFunction, kids, objectProps, stringValue, unwrap, walk } from "../../ast.js";
import { type JsonNode, jsonProp, lineAt, parseJsonPos } from "../../backends/json-pos.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import { langForFile, type ParsedFile, type SyntaxNode } from "../../parse.js";
import { defineRule, SOURCES } from "../types.js";
import { evalBoolean, evalString, firstListed, indentAt, insertLines, quoteStyle, rangeEdit, resolveValue, serviceFor, unitRel, makePatch } from "./util.js";

const WHY = "Security headers are the browser's defence against injected scripts (CSP), downgrade to plain HTTP (HSTS), MIME sniffing and clickjacking; without them the site relies on every page being free of those bugs.";

export type HeaderGroup = "csp" | "hsts" | "xcto" | "frame";
const GROUPS: HeaderGroup[] = ["csp", "hsts", "xcto", "frame"];
const HEADER_NAME: Record<HeaderGroup, string> = {
  csp: "Content-Security-Policy",
  hsts: "Strict-Transport-Security",
  xcto: "X-Content-Type-Options",
  frame: "X-Frame-Options",
};
export const RECOMMENDED: Record<HeaderGroup, string> = {
  csp: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  hsts: "max-age=63072000; includeSubDomains",
  xcto: "nosniff",
  frame: "DENY",
};
const CATCH_ALL = /^\/(?:\(\.\*\??\)|:\w+\*|:\w+\(\.\*\)|\*{1,2})?$/;
const SOURCE_LABEL: Record<HeaderSource["kind"], string> = {
  "next-config": "next.config headers()",
  vercel: "vercel.json headers",
  netlify: "netlify.toml [[headers]]",
  "headers-file": "_headers rules",
  helmet: "helmet()",
  middleware: "middleware header assignments",
};

export interface HeaderDef {
  name: string;
  value: string | null;
  file: string;
  line: number;
}

export interface HeaderSource {
  kind: "next-config" | "vercel" | "netlify" | "headers-file" | "helmet" | "middleware";
  file: string;
  line: number;
  headers: HeaderDef[];
  /** Groups provided without explicit headers (helmet). */
  provides: Set<HeaderGroup>;
  /** Unified diff adding one header, when the source has a simple catch-all structure. */
  patchFor?: (name: string, value: string) => string | undefined;
}

// ---------------------------------------------------------------- next.config

function configObject(pf: ParsedFile, n: SyntaxNode | null, depth = 0): SyntaxNode | null {
  const u = resolveValue(pf, n);
  if (!u || depth > 5) return null;
  if (u.type === "object") return u;
  if (isCall(u)) {
    for (const a of args(u)) {
      const o = configObject(pf, a, depth + 1);
      if (o) return o;
    }
    return null;
  }
  if (isFunction(u)) {
    const body = functionBody(u);
    if (!body) return null;
    if (body.type !== "statement_block") return configObject(pf, body, depth + 1);
    for (const r of returnsOf(body)) {
      const o = configObject(pf, r, depth + 1);
      if (o) return o;
    }
  }
  return null;
}

/** Values of `return` statements directly in a function body (nested functions skipped). */
function returnsOf(body: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  walk(body, (n) => {
    if (n.id !== body.id && isFunction(n)) return false;
    if (n.type === "return_statement") {
      const v = kids(n)[0];
      if (v) out.push(v);
      return false;
    }
    return true;
  });
  return out;
}

/** The array returned by headers(): `async headers() { return [...] }` or `headers: async () => [...]`. */
function headersArray(pf: ParsedFile, member: SyntaxNode): SyntaxNode | null {
  const fn = member.type === "method_definition" ? member : resolveValue(pf, member);
  if (!fn || !isFunction(fn)) return null;
  const body = functionBody(fn);
  if (!body) return null;
  const candidates = body.type === "statement_block" ? returnsOf(body) : [body];
  for (const c of candidates) {
    const arr = resolveValue(pf, c);
    if (arr?.type === "array") return arr;
  }
  return null;
}

function jsLiteral(pf: ParsedFile, s: string): string {
  const q = quoteStyle(pf);
  return s.includes(q) ? JSON.stringify(s) : `${q}${s}${q}`;
}

function insertIntoArray(source: string, file: string, arr: SyntaxNode, itemText: string): string | undefined {
  const items = kids(arr);
  const last = items[items.length - 1];
  if (arr.namedChildren.some((c) => c?.type === "comment")) return undefined;
  if (!last) return makePatch(file, source, [rangeEdit(source, arr.startIndex + 1, arr.endIndex - 1, itemText)]);
  if (!arr.text.includes("\n")) return makePatch(file, source, [rangeEdit(source, last.endIndex, last.endIndex, `, ${itemText}`)]);
  return makePatch(file, source, [rangeEdit(source, last.endIndex, last.endIndex, `,\n${indentAt(source, last.startIndex)}${itemText}`)]);
}

function nextConfigSource(ctx: ProjectContext, unit: UnitInfo): HeaderSource | null {
  const file = firstListed(ctx, ["js", "mjs", "ts", "cjs", "mts"].map((e) => unitRel(unit, `next.config.${e}`)));
  if (!file) return null;
  const pf = ctx.parse(file);
  if (!pf) return null;
  const obj = configObject(pf, exportsOf(pf).get("default") ?? null);
  const member = obj ? objectProps(obj).find((p) => p.key === "headers") : undefined;
  if (!member) return null;
  const arr = headersArray(pf, member.value);
  const headers: HeaderDef[] = [];
  let catchAll: SyntaxNode | null = null;
  for (const entry of arr ? elements(arr) : []) {
    const e = resolveValue(pf, entry);
    if (e?.type !== "object") continue;
    const props = objectProps(e);
    const src = evalString(pf, props.find((p) => p.key === "source")?.value ?? null);
    const hdrNode = resolveValue(pf, props.find((p) => p.key === "headers")?.value ?? null);
    if (hdrNode?.type !== "array") continue;
    if (src !== null && CATCH_ALL.test(src) && !catchAll) catchAll = hdrNode;
    for (const h of elements(hdrNode)) {
      const ho = resolveValue(pf, h);
      if (ho?.type !== "object") continue;
      const hp = objectProps(ho);
      const keyProp = hp.find((p) => p.key === "key");
      const key = evalString(pf, keyProp?.value ?? null);
      if (key === null) continue;
      headers.push({ name: key, value: evalString(pf, hp.find((p) => p.key === "value")?.value ?? null), file, line: (keyProp?.node ?? ho).startPosition.row + 1 });
    }
  }
  const target = catchAll;
  return {
    kind: "next-config",
    file,
    line: member.node.startPosition.row + 1,
    headers,
    provides: new Set(),
    ...(target ? { patchFor: (name: string, value: string) => insertIntoArray(pf.source, file, target, `{ key: ${jsLiteral(pf, name)}, value: ${jsLiteral(pf, value)} }`) } : {}),
  };
}

// ---------------------------------------------------------------- vercel.json

function jsonString(n: JsonNode | undefined | null): string | null {
  return n && n.kind === "string" ? n.value : null;
}

function vercelSource(ctx: ProjectContext, file: string): HeaderSource | null {
  const text = ctx.read(file);
  const root = text === null ? null : parseJsonPos(text);
  const hp = jsonProp(root, "headers");
  if (!text || !hp || hp.value.kind !== "array") return null;
  const headers: HeaderDef[] = [];
  let catchAll: JsonNode | null = null;
  for (const item of hp.value.items) {
    const src = jsonString(jsonProp(item, "source")?.value);
    const list = jsonProp(item, "headers")?.value;
    if (!list || list.kind !== "array") continue;
    if (src !== null && CATCH_ALL.test(src) && !catchAll) catchAll = list;
    for (const h of list.items) {
      const key = jsonString(jsonProp(h, "key")?.value);
      if (key === null) continue;
      headers.push({ name: key, value: jsonString(jsonProp(h, "value")?.value), file, line: lineAt(text, h.start) });
    }
  }
  const target = catchAll;
  const patchFor =
    target && target.kind === "array"
      ? (name: string, value: string) => {
          const item = `{ "key": ${JSON.stringify(name)}, "value": ${JSON.stringify(value)} }`;
          const last = target.items[target.items.length - 1];
          if (!last) return makePatch(file, text, [rangeEdit(text, target.start + 1, target.end - 1, item)]);
          const multiline = text.slice(target.start, target.end).includes("\n");
          const ins = multiline ? `,\n${indentAt(text, last.start)}${item}` : `, ${item}`;
          return makePatch(file, text, [rangeEdit(text, last.end, last.end, ins)]);
        }
      : undefined;
  return { kind: "vercel", file, line: lineAt(text, hp.keyStart), headers, provides: new Set(), ...(patchFor ? { patchFor } : {}) };
}

// ---------------------------------------------------------------- netlify.toml

function netlifySource(ctx: ProjectContext, file: string): HeaderSource | null {
  const text = ctx.read(file);
  if (text === null) return null;
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  const blocks = Array.isArray(doc.headers) ? (doc.headers as Record<string, unknown>[]) : [];
  if (blocks.length === 0) return null;
  const lines = text.split("\n");
  const blockLines = lines.map((l, i) => (/^\s*\[\[\s*headers\s*\]\]/.test(l) ? i : -1)).filter((i) => i >= 0);
  const headers: HeaderDef[] = [];
  blocks.forEach((b, bi) => {
    const values = b.values && typeof b.values === "object" ? (b.values as Record<string, unknown>) : {};
    const from = blockLines[bi] ?? 0;
    const to = blockLines[bi + 1] ?? lines.length;
    for (const [name, value] of Object.entries(values)) {
      const re = new RegExp(`^\\s*["']?${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']?\\s*=`, "i");
      let line = from + 1;
      for (let i = from; i < to; i++) if (re.test(lines[i]!)) {
        line = i + 1;
        break;
      }
      headers.push({ name, value: typeof value === "string" ? value : null, file, line });
    }
  });
  // Patch: the first catch-all block with a [headers.values] table.
  let patchFor: HeaderSource["patchFor"];
  const idx = blocks.findIndex((b) => typeof b.for === "string" && CATCH_ALL.test(b.for));
  if (idx >= 0 && blockLines[idx] !== undefined) {
    const from = blockLines[idx]!;
    const to = blockLines[idx + 1] ?? lines.length;
    const valuesLine = lines.slice(from, to).findIndex((l) => /^\s*\[\s*headers\.values\s*\]/.test(l));
    if (valuesLine >= 0) {
      let last = from + valuesLine;
      for (let i = from + valuesLine + 1; i < to; i++) {
        const l = lines[i]!;
        if (/^\s*\[/.test(l)) break;
        if (/^\s*[^#\s][^=]*=/.test(l)) last = i;
        else if (l.trim() && !l.trim().startsWith("#")) return null;
      }
      const indent = last > from + valuesLine ? /^\s*/.exec(lines[last]!)![0] : `${/^\s*/.exec(lines[from + valuesLine]!)![0]}  `;
      patchFor = (name, value) => makePatch(file, text, [insertLines(last + 1, [`${indent}${name} = ${JSON.stringify(value)}`])]);
    }
  }
  return { kind: "netlify", file, line: (blockLines[0] ?? 0) + 1, headers, provides: new Set(), ...(patchFor ? { patchFor } : {}) };
}

// ---------------------------------------------------------------- _headers

export function parseHeadersFile(text: string): { path: string; line: number; headers: { name: string; value: string; line: number }[] }[] {
  const out: { path: string; line: number; headers: { name: string; value: string; line: number }[] }[] = [];
  text.split("\n").forEach((raw, i) => {
    const l = raw.replace(/\r$/, "");
    if (!l.trim() || l.trim().startsWith("#")) return;
    if (!/^\s/.test(l)) {
      out.push({ path: l.trim(), line: i + 1, headers: [] });
      return;
    }
    const m = /^\s+([^:\s]+)\s*:\s*(.*)$/.exec(l);
    const block = out[out.length - 1];
    if (m && block) block.headers.push({ name: m[1]!, value: m[2]!.trim(), line: i + 1 });
  });
  return out;
}

function headersFileSource(ctx: ProjectContext, file: string): HeaderSource | null {
  const text = ctx.read(file);
  if (text === null) return null;
  const blocks = parseHeadersFile(text);
  if (blocks.length === 0) return null;
  const headers = blocks.flatMap((b) => b.headers.map((h) => ({ name: h.name, value: h.value, file, line: h.line })));
  const ca = blocks.find((b) => CATCH_ALL.test(b.path));
  let patchFor: HeaderSource["patchFor"];
  if (ca) {
    const lines = text.split("\n");
    const lastLine = ca.headers.length ? ca.headers[ca.headers.length - 1]!.line : ca.line;
    const indent = ca.headers.length ? /^\s*/.exec(lines[lastLine - 1]!)![0] : "  ";
    patchFor = (name, value) => makePatch(file, text, [insertLines(lastLine, [`${indent}${name}: ${value}`])]);
  }
  return { kind: "headers-file", file, line: blocks[0]!.line, headers, provides: new Set(), ...(patchFor ? { patchFor } : {}) };
}

// ---------------------------------------------------------------- helmet() and middleware

function helmetSources(ctx: ProjectContext, files: readonly string[]): HeaderSource[] {
  const out: HeaderSource[] = [];
  for (const file of files) {
    const text = ctx.read(file);
    if (!text || !text.includes("helmet")) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    walk(pf.root, (n) => {
      if (n.type !== "call_expression") return true;
      const fn = unwrap(callee(n));
      if (fn?.type !== "identifier") return true;
      const imp = importOf(pf, fn.text);
      if (!imp || imp.source !== "helmet") return true;
      const provides = new Set<HeaderGroup>(GROUPS);
      const opts = resolveValue(pf, args(n)[0] ?? null);
      const off = (...keys: string[]) => (opts?.type === "object" ? objectProps(opts).some((p) => keys.includes(p.key) && evalBoolean(pf, p.value) === false) : false);
      if (off("contentSecurityPolicy")) provides.delete("csp");
      if (off("hsts", "strictTransportSecurity")) provides.delete("hsts");
      if (off("noSniff", "xContentTypeOptions")) provides.delete("xcto");
      if (off("frameguard", "xFrameOptions") && !provides.has("csp")) provides.delete("frame");
      out.push({ kind: "helmet", file, line: n.startPosition.row + 1, headers: [], provides });
      return true;
    });
  }
  return out;
}

const KNOWN = new Set(GROUPS.map((g) => HEADER_NAME[g].toLowerCase()));

/** Explicit assignments of the four headers: res.setHeader / res.set / res.header / headers.set, and Python response.headers[...] = … */
function middlewareSources(ctx: ProjectContext, files: readonly string[]): HeaderSource[] {
  const out: HeaderSource[] = [];
  for (const file of files) {
    const text = ctx.read(file);
    if (!text || !/Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options/i.test(text)) continue;
    const pf = ctx.parse(file);
    if (!pf) continue;
    const headers: HeaderDef[] = [];
    walk(pf.root, (n) => {
      if (n.type === "call_expression") {
        const method = exprPath(callee(n)).split(".").pop() ?? "";
        if (!["setHeader", "set", "header", "append"].includes(method)) return true;
        const a = args(n);
        const name = stringValue(a[0] ?? null);
        if (name !== null && KNOWN.has(name.toLowerCase())) headers.push({ name, value: evalString(pf, a[1] ?? null), file, line: n.startPosition.row + 1 });
        else if (a.length === 1 && unwrap(a[0]!)?.type === "object") {
          for (const p of objectProps(a[0]!)) if (KNOWN.has(p.key.toLowerCase())) headers.push({ name: p.key, value: evalString(pf, p.value), file, line: p.node.startPosition.row + 1 });
        }
      } else if (n.type === "assignment") {
        const left = n.childForFieldName("left");
        if (left?.type === "subscript" && /(?:^|\.)headers$/.test(exprPath(left.childForFieldName("value")))) {
          const name = stringValue(left.childForFieldName("subscript"));
          if (name !== null && KNOWN.has(name.toLowerCase())) headers.push({ name, value: stringValue(n.childForFieldName("right")), file, line: n.startPosition.row + 1 });
        }
      }
      return true;
    });
    if (headers.length) out.push({ kind: "middleware", file, line: headers[0]!.line, headers, provides: new Set() });
  }
  return out;
}

// ---------------------------------------------------------------- per unit

export function headerSources(ctx: ProjectContext, unit: UnitInfo): HeaderSource[] {
  const out: HeaderSource[] = [];
  if (unit.framework === "nextjs") {
    const nc = nextConfigSource(ctx, unit);
    if (nc) out.push(nc);
  }
  const roots = [...new Set([unit.root, ""])];
  for (const r of roots) {
    const v = r ? `${r}/vercel.json` : "vercel.json";
    if (ctx.hasFile(v)) {
      const s = vercelSource(ctx, v);
      if (s) out.push(s);
    }
    const n = r ? `${r}/netlify.toml` : "netlify.toml";
    if (ctx.hasFile(n)) {
      const s = netlifySource(ctx, n);
      if (s) out.push(s);
    }
  }
  for (const rel of ["_headers", "public/_headers"]) {
    const f = unitRel(unit, rel);
    if (ctx.hasFile(f)) {
      const s = headersFileSource(ctx, f);
      if (s) out.push(s);
    }
  }
  // Server code that serves this site: a Next.js unit's own files (middleware / custom server);
  // for other web units, the project's api units (Express / FastAPI serving the built site).
  let serverFiles: string[];
  if (unit.framework === "nextjs") {
    const mw = ["middleware", "proxy"].flatMap((n) => ["", "src/"].flatMap((d) => ["ts", "js"].map((e) => unitRel(unit, `${d}${n}.${e}`)))).filter((f) => ctx.hasFile(f));
    out.push(...helmetSources(ctx, ctx.codeFiles(unit, "js")));
    serverFiles = mw;
  } else {
    const apiFiles = [...new Set(ctx.unitsOf("api").flatMap((u) => ctx.codeFiles(u)))].sort();
    out.push(...helmetSources(ctx, apiFiles.filter((f) => langForFile(f) !== "python")));
    serverFiles = apiFiles;
  }
  out.push(...middlewareSources(ctx, serverFiles));
  const seen = new Set<string>();
  return out
    .filter((s) => {
      const k = `${s.kind}\u0000${s.file}\u0000${s.line}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
}

/** CSP directives: name → sources (lowercased names). */
export function parseCsp(value: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0]!.toLowerCase();
    if (!out.has(name)) out.set(name, tokens.slice(1));
  }
  return out;
}

export function presentGroups(sources: readonly HeaderSource[]): Set<HeaderGroup> {
  const present = new Set<HeaderGroup>();
  for (const s of sources) {
    for (const g of s.provides) present.add(g);
    for (const h of s.headers) {
      const n = h.name.toLowerCase();
      if (n === "content-security-policy") {
        present.add("csp");
        if (h.value !== null && parseCsp(h.value).has("frame-ancestors")) present.add("frame");
      } else if (n === "strict-transport-security") present.add("hsts");
      else if (n === "x-content-type-options") present.add("xcto");
      else if (n === "x-frame-options") present.add("frame");
    }
  }
  return present;
}

function primaryFile(ctx: ProjectContext, unit: UnitInfo): string {
  const cands =
    unit.framework === "nextjs"
      ? ["js", "mjs", "ts", "cjs", "mts"].map((e) => unitRel(unit, `next.config.${e}`))
      : [...["ts", "js", "mjs", "mts", "cjs", "cts"].map((e) => unitRel(unit, `vite.config.${e}`)), unitRel(unit, "index.html")];
  return firstListed(ctx, [...cands, unitRel(unit, "package.json")]) ?? unitRel(unit, "package.json");
}

function guidance(ctx: ProjectContext, unit: UnitInfo, name: string, value: string): string {
  const v = JSON.stringify(value);
  if (unit.framework === "nextjs") return `Add it to next.config headers() for all paths, for example: async headers() { return [{ source: "/(.*)", headers: [{ key: "${name}", value: ${v} }] }]; }`;
  const express = ctx.unitsOf("api", "express").length > 0;
  return `Set it where the site is served for all paths: for example vercel.json { "headers": [{ "source": "/(.*)", "headers": [{ "key": "${name}", "value": ${v} }] }] }, a Netlify _headers file with "/*" then "  ${name}: ${value}"${express ? ", or app.use(helmet()) in Express" : ""}.`;
}

export const securityHeadersRule = defineRule({
  id: "web/security-headers",
  title: "Security header missing",
  pack: "web",
  // Promoted after validation (DECISIONS.md, "Validation and promotion").
  maturity: "stable",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => ctx.hasUnit("web"),
  check(ctx, emit) {
    const units = [...ctx.unitsOf("web")].sort((a, b) => (a.root < b.root ? -1 : a.root > b.root ? 1 : a.framework.localeCompare(b.framework)));
    for (const unit of units) {
      const sources = headerSources(ctx, unit);
      const present = presentGroups(sources);
      const where = sources[0] ?? null;
      const file = where?.file ?? primaryFile(ctx, unit);
      const line = where?.line ?? 1;
      const single = sources.length === 1 ? sources[0]! : null;
      for (const g of GROUPS) {
        if (present.has(g)) continue;
        const name = HEADER_NAME[g];
        const value = RECOMMENDED[g];
        const patch = single?.patchFor?.(name, value);
        const alt = g === "frame" && present.has("csp") ? " Alternatively, add frame-ancestors 'none' to the existing Content-Security-Policy." : "";
        const cspNote = g === "csp" ? " Start from this policy and adjust it to the scripts, styles and connections the site needs; try it as Content-Security-Policy-Report-Only first." : "";
        emit({
          severity: "low",
          service: serviceFor(ctx, file),
          file,
          line,
          anchor: `headers:${name}`,
          evidence: where ? `${SOURCE_LABEL[where.kind]} in ${where.file}${sources.length > 1 ? ` (and ${sources.length - 1} more source${sources.length > 2 ? "s" : ""})` : ""} do not set ${name}` : `no header source (next.config headers(), vercel.json, netlify.toml, _headers, helmet() or middleware) found for ${unit.root || "the project root"}`,
          why: WHY,
          fix: {
            summary: `${patch ? `Add ${name}: ${value} for all paths.` : guidance(ctx, unit, name, value)}${alt}${cspNote}`,
            ...(patch ? { patch } : {}),
          },
        });
      }
      // CSP with both 'unsafe-inline' and 'unsafe-eval' in script-src (or default-src).
      for (const s of sources) {
        for (const h of s.headers) {
          if (h.name.toLowerCase() !== "content-security-policy" || h.value === null) continue;
          const d = parseCsp(h.value);
          const directive = d.has("script-src") ? "script-src" : "default-src";
          const list = (d.get(directive) ?? []).map((x) => x.toLowerCase());
          if (!list.includes("'unsafe-inline'") || !list.includes("'unsafe-eval'")) continue;
          emit({
            severity: "low",
            advisory: true,
            service: serviceFor(ctx, h.file),
            file: h.file,
            line: h.line,
            anchor: `headers:Content-Security-Policy:${directive}`,
            evidence: `${h.name}: ${h.value}`,
            why: WHY,
            fix: { summary: `Remove 'unsafe-inline' and 'unsafe-eval' from ${directive}; use nonces or hashes for the inline scripts the site needs.` },
          });
        }
      }
    }
  },
});

