// web/client-secrets: Secret shipped to the browser (spec 8.5).

import type { Severity } from "../../../types.js";
import { args, callee, exprPath, importOf, objectProps, walk } from "../../ast.js";
import { clientGraph, isKnownServerFile } from "../../client-graph.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import { type DetectorMatch, detectSecrets, isConfigLikeFile } from "../../detectors/index.js";
import { findOnDisk } from "../../files.js";
import { langForFile } from "../../parse.js";
import { redact, redactSecretValue } from "../../redact.js";
import { sha256Hex } from "../../util/hash.js";
import { defineRule, SOURCES } from "../types.js";
import { type EnvEntry, envFiles, evalBoolean, expandEnv, lineOfOffset, parseEnv, resolveObject, unitRel } from "./util.js";

const WHY = "Browser code, public environment variables and built bundles can be read by every visitor, so a key in them is public.";
const BUILD_LIMIT = 5000;
const AI_CLIENTS = new Set(["OpenAI", "AzureOpenAI", "Anthropic", "AnthropicBedrock", "AnthropicVertex"]);
/** Test, story and e2e files are never shipped (and jsdom tests often need dangerouslyAllowBrowser). */
const NOT_SHIPPED = /(?:^|\/)(?:__tests__|__mocks__|tests?|e2e|cypress|playwright)\/|\.(?:test|spec|stories|cy)\.[cm]?[jt]sx?$/;

/** Detector severity when it is below high (Stripe test keys, Google API keys); otherwise critical. */
export function clientSecretSeverity(m: DetectorMatch): Severity {
  return m.severity === "low" || m.severity === "medium" ? m.severity : "critical";
}

function humanAction(m: DetectorMatch): string {
  if (m.kind === "google-api-key") return "Restrict this key to your domains and the APIs it needs at the provider, or rotate it if it was not meant to be public.";
  return "Rotate this key at the provider: it has already been exposed to browsers.";
}

/** One-line evidence around a match; long (minified) lines are redacted first, then windowed. */
export function evidenceAround(text: string, m: { start: number; end: number; value: string; prefix?: string }): string {
  const ls = text.lastIndexOf("\n", m.start - 1) + 1;
  let le = text.indexOf("\n", m.end);
  if (le < 0) le = text.length;
  const lineText = text.slice(ls, le);
  if (lineText.length <= 240) return lineText.trim();
  const red = redact(lineText);
  const token = redactSecretValue(m.value, m.prefix);
  const approx = Math.max(0, Math.round(((m.start - ls) / Math.max(1, lineText.length)) * red.length) - token.length - 200);
  let at = red.indexOf(token, approx);
  if (at < 0) at = red.indexOf(token);
  if (at < 0) return redact(text.slice(m.start, m.end));
  return red.slice(Math.max(0, at - 60), Math.min(red.length, at + token.length + 60)).trim();
}

function seedOf(via: Map<string, string>, file: string): string {
  let cur = file;
  for (let i = 0; i < 1000; i++) {
    const prev = via.get(cur);
    if (!prev || prev === cur) return cur;
    cur = prev;
  }
  return cur;
}

/** First reference of each public env var in the unit's code, as "file:line". */
function envReferences(ctx: ProjectContext, unit: UnitInfo, prefix: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = prefix === "VITE_" ? /import\.meta\.env\.(VITE_[A-Za-z0-9_]+)|import\.meta\.env\[\s*["'](VITE_[A-Za-z0-9_]+)["']\s*\]/g : /process\.env\.(NEXT_PUBLIC_[A-Za-z0-9_]+)|process\.env\[\s*["'](NEXT_PUBLIC_[A-Za-z0-9_]+)["']\s*\]/g;
  for (const file of ctx.codeFiles(unit, "js")) {
    const text = ctx.read(file);
    if (!text || !text.includes(prefix)) continue;
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) {
      const key = (m[1] ?? m[2])!;
      if (!out.has(key)) out.set(key, `${file}:${lineOfOffset(text, m.index)}`);
    }
  }
  return out;
}

/** Built browser bundles: `.next/static/**` (Next.js) or Vite's `dist/**` (only when it holds an index.html). */
function buildOutput(ctx: ProjectContext, unit: UnitInfo): { files: string[]; truncated: boolean } {
  let dir: string | null = null;
  let skip: string | null = null;
  if (unit.framework === "nextjs") dir = unitRel(unit, ".next/static");
  else if (unit.framework === "vite") {
    if (ctx.read(unitRel(unit, "dist/index.html")) !== null) {
      dir = unitRel(unit, "dist");
      skip = `${dir}/server/`;
    } else if (ctx.read(unitRel(unit, "dist/client/index.html")) !== null) dir = unitRel(unit, "dist/client");
  }
  if (!dir) return { files: [], truncated: false };
  const files = findOnDisk(ctx.root, dir, (rel) => /\.[cm]?js$/.test(rel) && !(skip && rel.startsWith(skip)), { skipDirs: false, limit: BUILD_LIMIT + 1 });
  return { files: files.slice(0, BUILD_LIMIT), truncated: files.length > BUILD_LIMIT };
}

export const clientSecretsRule = defineRule({
  id: "web/client-secrets",
  title: "Secret shipped to the browser",
  pack: "web",
  maturity: "experimental",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => ctx.hasUnit("web"),
  check(ctx, emit) {
    const seen = new Set<string>();
    const reported = new Set<string>();
    // fix.summary is fixed text; project text (paths, variable names) goes into evidence (invariant 12).
    const report = (file: string, text: string, m: DetectorMatch, summary: string, opts: { evidence?: string; note?: string; line?: number } = {}) => {
      const key = `${file}\u0000${m.start}\u0000${m.value.length}`;
      if (seen.has(key)) return;
      seen.add(key);
      const hash = sha256Hex(m.value);
      reported.add(hash);
      const ev = opts.evidence ?? evidenceAround(text, m);
      emit({
        severity: clientSecretSeverity(m),
        service: "web",
        file,
        line: opts.line ?? lineOfOffset(text, m.start + m.valueStart),
        anchor: hash,
        evidence: opts.note ? `${ev} [${opts.note}]` : ev,
        why: WHY,
        fix: { summary, humanAction: humanAction(m) },
      });
    };
    const CODE_FIX = "Move the code that uses this key to a server route or server action and read the key from a server-only environment variable; the browser should call your server, not the provider.";
    const BUILD_FIX = "This key is in the built browser bundle. Find where it enters client code (a public environment variable or a client import), move that code to the server, and rebuild.";

    const units = [...ctx.unitsOf("web")].sort((a, b) => (a.root < b.root ? -1 : a.root > b.root ? 1 : a.framework.localeCompare(b.framework)));
    // 1. Client-reachable code.
    for (const unit of units) {
      const graph = clientGraph(ctx, unit);
      for (const file of graph.files) {
        const text = ctx.read(file);
        if (text === null) continue;
        const seed = seedOf(graph.via, file);
        const note = seed !== file ? `in the browser bundle through ${seed}` : undefined;
        for (const m of detectSecrets(text, { configLike: isConfigLikeFile(file) })) report(file, text, m, CODE_FIX, note ? { note } : {});
      }
    }
    // 2. dangerouslyAllowBrowser: true in an OpenAI / Anthropic client.
    for (const unit of units) {
      for (const file of unit.files) {
        const lang = langForFile(file);
        if (!lang || lang === "python") continue;
        const text = ctx.read(file);
        if (text === null || !text.includes("dangerouslyAllowBrowser")) continue;
        if (NOT_SHIPPED.test(file) || isKnownServerFile(ctx, unit, file)) continue;
        const pf = ctx.parse(file);
        if (!pf) continue;
        walk(pf.root, (n) => {
          if (n.type !== "new_expression") return true;
          const ctor = exprPath(callee(n));
          const name = ctor.split(".").pop() ?? ctor;
          const imp = importOf(pf, ctor.split(".")[0] ?? ctor);
          const fromSdk = !!imp && /^(?:openai|@anthropic-ai\/[\w.-]+)(?:\/|$)/.test(imp.source);
          if (!AI_CLIENTS.has(name) && !fromSdk) return true;
          const opts = resolveObject(pf, args(n)[0] ?? null);
          const flag = opts ? objectProps(opts).find((p) => p.key === "dangerouslyAllowBrowser") : undefined;
          if (!flag || evalBoolean(pf, flag.value) !== true) return true;
          const k = `${file}\u0000dab\u0000${n.startIndex}`;
          if (seen.has(k)) return true;
          seen.add(k);
          emit({
            severity: "critical",
            service: "web",
            file,
            line: flag.node.startPosition.row + 1,
            anchor: `${name}:dangerouslyAllowBrowser`,
            evidence: n.text,
            why: WHY,
            fix: {
              summary: "Remove dangerouslyAllowBrowser and call the model API from a server route or server action that holds the key; the browser should call your server, not the provider.",
              humanAction: "Rotate the API key used by this client: a key used from the browser is visible to every visitor.",
            },
          });
          return true;
        });
      }
    }
    // 3. Public env vars: NEXT_PUBLIC_* / VITE_* entries in .env* files.
    for (const unit of units) {
      const prefix = unit.framework === "nextjs" ? "NEXT_PUBLIC_" : "VITE_";
      const files = envFiles(ctx, unit.root).map((file) => {
        const text = ctx.read(file) ?? "";
        return { file, text, entries: parseEnv(text) };
      });
      if (files.length === 0) continue;
      const refs = envReferences(ctx, unit, prefix);
      const lookup = (own: EnvEntry[]) => (key: string) => {
        const hit = own.find((e) => e.key === key) ?? files.flatMap((f) => f.entries).find((e) => e.key === key);
        return hit?.value;
      };
      for (const { file, text, entries } of files) {
        const envFix = `Remove the ${prefix} prefix so the value is not inlined into the browser bundle, read it only in server code, and call the provider from a server route or server action.`;
        const noteFor = (key: string) => {
          const ref = refs.get(key);
          return ref ? { note: `used in ${ref}` } : {};
        };
        for (const m of detectSecrets(text, { configLike: true })) {
          const e = entries.find((x) => m.start >= x.start && m.start < x.end);
          if (!e || !e.key.startsWith(prefix)) continue;
          report(file, text, m, envFix, noteFor(e.key));
        }
        // dotenv-expand: NEXT_PUBLIC_X=$SECRET_X
        for (const e of entries) {
          if (!e.key.startsWith(prefix)) continue;
          const expanded = expandEnv(e, lookup(entries));
          if (expanded === null) continue;
          for (const m of detectSecrets(`${e.key}=${expanded}`, { configLike: true })) {
            const raw = text.slice(e.start, e.end).split("\n")[0]!.trim();
            const ref = refs.get(e.key);
            report(file, `${e.key}=${expanded}`, { ...m, start: e.start + m.start }, envFix, { evidence: `${raw} (value expands to: ${m.label})`, line: e.line, ...(ref ? { note: `used in ${ref}` } : {}) });
          }
        }
      }
    }
    // 4. Build output.
    for (const unit of units) {
      const { files, truncated } = buildOutput(ctx, unit);
      if (truncated) ctx.addGap("Build output", `more than ${BUILD_LIMIT} built files; only the first ${BUILD_LIMIT} were read`);
      for (const file of files) {
        const text = ctx.read(file);
        if (text === null) continue;
        for (const m of detectSecrets(text)) {
          if (reported.has(sha256Hex(m.value))) continue;
          report(file, text, m, BUILD_FIX);
        }
      }
    }
  },
});
