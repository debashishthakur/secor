// web/production-debug: Debug features on in production (spec 8.5). Public source maps (next.config
// productionBrowserSourceMaps, Vite build.sourcemap) and dev servers as the production start command
// (package.json scripts.start, Dockerfile CMD / ENTRYPOINT, Procfile web:).

import { posix } from "node:path";
import { walk } from "../../ast.js";
import { jsonProp, lineAt, parseJsonPos } from "../../backends/json-pos.js";
import type { ProjectContext } from "../../context.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { defineRule, SOURCES } from "../types.js";
import { evalBoolean, evalString, firstListed, rangeEdit, resolveValue, rootsOf, serviceFor, unitRel, makePatch } from "./util.js";

const WHY = "Development servers and public source maps expose debugging features, verbose errors and the original source code, and are not built to serve production traffic.";

export type DevKind = "next dev" | "vite" | "nodemon" | "uvicorn --reload";

export type TokenEdit = { op: "replace"; index: number; value: string } | { op: "insert"; after: number; value: string } | { op: "remove"; index: number };

export type SegmentHit = { kind: DevKind; edits: TokenEdit[] | null } | { kind: "script"; script: string };


const WRAPPERS = new Set(["npx", "bunx", "exec", "env", "cross-env", "dotenv", "time", "nice"]);
const SCRIPT_RUNNERS = /^(?:npm|yarn|pnpm|bun)$/;

function unquote(t: string): string {
  return t.replace(/^(["'])(.*)\1$/, "$2");
}

/** Analyse one command (no shell operators) given as unquoted tokens, from index `from`. Edit indices are absolute. */
export function analyseCommand(tokens: readonly string[], from = 0): SegmentHit | null {
  let i = from;
  for (;;) {
    const t = tokens[i];
    if (t === undefined) return null;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) i++;
    else if (WRAPPERS.has(t)) {
      i++;
      if (t === "dotenv") {
        const dd = tokens.indexOf("--", i);
        if (dd >= 0) i = dd + 1;
      }
    } else if ((t === "pnpm" && tokens[i + 1] === "exec") || ((t === "poetry" || t === "uv" || t === "pipenv") && tokens[i + 1] === "run")) i += 2;
    else if (/^python[0-9.]*$/.test(t) && tokens[i + 1] === "-m") i += 2;
    else break;
  }
  const prog = posix.basename(tokens[i]!);
  const rest = tokens.slice(i + 1);
  if (SCRIPT_RUNNERS.test(prog)) {
    const sub = rest[0];
    if (sub === undefined) return null;
    if (sub === "run" || sub === "run-script") return rest[1] && !rest[1].startsWith("-") ? { kind: "script", script: rest[1] } : null;
    if (sub === "start") return { kind: "script", script: "start" };
    if (prog === "npm") return null;
    if (["next", "vite", "nodemon", "uvicorn"].includes(sub)) return analyseCommand(tokens, i + 1);
    if (sub.startsWith("-") || ["install", "add", "build", "test", "exec", "dlx", "x", "i", "ci"].includes(sub)) return null;
    return { kind: "script", script: sub };
  }
  if (prog === "next") {
    if (rest[0] !== "dev") return null;
    const edits: TokenEdit[] = [{ op: "replace", index: i + 1, value: "start" }];
    rest.forEach((t, k) => {
      if (t === "--turbo" || t === "--turbopack") edits.push({ op: "remove", index: i + 1 + k });
    });
    return { kind: "next dev", edits };
  }
  if (prog === "vite") {
    const sub = rest[0];
    if (sub === "dev" || sub === "serve") return { kind: "vite", edits: [{ op: "replace", index: i + 1, value: "preview" }] };
    if (sub === undefined || sub.startsWith("-")) return { kind: "vite", edits: [{ op: "insert", after: i, value: "preview" }] };
    return null;
  }
  if (prog === "nodemon") {
    const ok = rest.length >= 1 && rest.every((t) => !t.startsWith("-"));
    return { kind: "nodemon", edits: ok ? [{ op: "replace", index: i, value: "node" }] : null };
  }
  if (prog === "uvicorn") {
    const k = rest.indexOf("--reload");
    if (k < 0) return null;
    const ambiguous = rest.some((t) => t.startsWith("--reload-"));
    return { kind: "uvicorn --reload", edits: ambiguous ? null : [{ op: "remove", index: i + 1 + k }] };
  }
  return null;
}

interface Tok {
  text: string;
  start: number;
  end: number;
}

/** Shell command → segments of tokens (split on &&, ||, ;, |, &), with offsets. */
export function shellSegments(cmd: string): Tok[][] {
  const segs: Tok[][] = [[]];
  const re = /"(?:[^"\\]|\\.)*"|'[^']*'|&&|\|\||[;&|]|[^\s;&|]+/g;
  for (let m = re.exec(cmd); m; m = re.exec(cmd)) {
    if (/^(?:&&|\|\||[;&|])$/.test(m[0])) segs.push([]);
    else segs[segs.length - 1]!.push({ text: m[0], start: m.index, end: m.index + m[0].length });
  }
  return segs.filter((s) => s.length > 0);
}

export interface CommandHit {
  kind: DevKind | "script";
  /** npm scripts the command runs (`npm run dev`, `yarn start`), for the caller to resolve; only when no dev server is run directly. */
  scripts?: string[];
  /** The whole command with the fix applied; null when the change is not a single unambiguous edit. */
  fixed: string | null;
}

/** First dev server in a shell command string, else the npm scripts it runs. */
export function analyseShell(cmd: string): CommandHit | null {
  const scripts: string[] = [];
  for (const seg of shellSegments(cmd)) {
    const toks = seg.map((t) => unquote(t.text));
    // sh -c "…"
    if (/^(?:\/bin\/)?(?:ba)?sh$/.test(toks[0] ?? "") && toks[1] === "-c" && toks[2] !== undefined) {
      const inner = analyseShell(toks[2]);
      if (inner && inner.kind !== "script") return { kind: inner.kind, fixed: null };
      if (inner?.scripts) scripts.push(...inner.scripts);
      continue;
    }
    const hit = analyseCommand(toks);
    if (!hit) continue;
    if (hit.kind === "script") {
      scripts.push(hit.script);
      continue;
    }
    return { kind: hit.kind, fixed: hit.edits ? applyToString(cmd, seg, hit.edits) : null };
  }
  return scripts.length ? { kind: "script", scripts, fixed: null } : null;
}

function applyToString(cmd: string, seg: Tok[], edits: TokenEdit[]): string {
  let out = cmd;
  const ordered = [...edits].sort((a, b) => pos(b) - pos(a));
  for (const e of ordered) {
    if (e.op === "replace") {
      const t = seg[e.index]!;
      out = out.slice(0, t.start) + e.value + out.slice(t.end);
    } else if (e.op === "insert") {
      const t = seg[e.after]!;
      out = `${out.slice(0, t.end)} ${e.value}${out.slice(t.end)}`;
    } else {
      const t = seg[e.index]!;
      let s = t.start;
      while (s > 0 && /[ \t]/.test(out[s - 1]!)) s--;
      out = out.slice(0, s) + out.slice(t.end);
    }
  }
  return out;
  function pos(e: TokenEdit): number {
    return e.op === "insert" ? seg[e.after]!.end : seg[e.index]!.start;
  }
}

/** Exec-form command (JSON array) analysis; the fix rewrites the array. */
export function analyseExec(arr: string[]): CommandHit | null {
  if (/^(?:\/bin\/)?(?:ba)?sh$/.test(arr[0] ?? "") && arr[1] === "-c" && arr[2] !== undefined) {
    const inner = analyseShell(arr[2]);
    if (!inner) return null;
    if (inner.kind === "script") return inner;
    return { kind: inner.kind, fixed: inner.fixed === null ? null : `[${[arr[0], arr[1], inner.fixed, ...arr.slice(3)].map((x) => JSON.stringify(x)).join(", ")}]` };
  }
  const hit = analyseCommand(arr);
  if (!hit) return null;
  if (hit.kind === "script") return { kind: "script", scripts: [hit.script], fixed: null };
  if (!hit.edits) return { kind: hit.kind, fixed: null };
  let next = [...arr];
  for (const e of [...hit.edits].sort((a, b) => (b.op === "insert" ? b.after : b.index) - (a.op === "insert" ? a.after : a.index))) {
    if (e.op === "replace") next[e.index] = e.value;
    else if (e.op === "insert") next = [...next.slice(0, e.after + 1), e.value, ...next.slice(e.after + 1)];
    else next = [...next.slice(0, e.index), ...next.slice(e.index + 1)];
  }
  return { kind: hit.kind, fixed: `[${next.map((x) => JSON.stringify(x)).join(", ")}]` };
}

// ---------------------------------------------------------------- Dockerfile / Procfile

export interface DockerInstruction {
  instr: string;
  args: string;
  line: number;
  endLine: number;
  /** Offsets of the arguments in the file. */
  argsStart: number;
  argsEnd: number;
}

export function dockerInstructions(text: string): DockerInstruction[] {
  const out: DockerInstruction[] = [];
  const lines = text.split("\n");
  let offset = 0;
  const lineOffsets = lines.map((l) => {
    const o = offset;
    offset += l.length + 1;
    return o;
  });
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!.replace(/\r$/, "");
    if (!raw.trim() || raw.trim().startsWith("#")) continue;
    const m = /^\s*([A-Za-z]+)(\s+|$)/.exec(raw);
    if (!m) continue;
    let args = raw.slice(m[0].length);
    const argsStart = lineOffsets[i]! + m[0].length;
    let j = i;
    while (/\\\s*$/.test(lines[j]!.replace(/\r$/, "")) && j + 1 < lines.length) {
      args = `${args.replace(/\s*\\\s*$/, "")} ${lines[j + 1]!.replace(/\r$/, "").trim()}`;
      j++;
    }
    out.push({ instr: m[1]!.toUpperCase(), args: args.trim(), line: i + 1, endLine: j + 1, argsStart, argsEnd: lineOffsets[j]! + lines[j]!.replace(/\r$/, "").length });
    i = j;
  }
  return out;
}

function execForm(args: string): string[] | null {
  if (!args.startsWith("[")) return null;
  try {
    const v = JSON.parse(args) as unknown;
    return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- source maps

function sourceMapPairs(pf: ParsedFile, key: string, parentKey: string | null): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  walk(pf.root, (n) => {
    if (n.type !== "pair") return true;
    const k = n.childForFieldName("key");
    const name = k ? (k.type === "string" ? k.text.slice(1, -1) : k.text) : "";
    if (name !== key) return true;
    if (parentKey !== null) {
      const obj = n.parent;
      const owner = obj?.parent;
      const ownerKey = owner?.type === "pair" ? owner.childForFieldName("key")?.text.replace(/^["']|["']$/g, "") : null;
      if (ownerKey !== parentKey) return true;
    }
    out.push(n);
    return true;
  });
  return out;
}

// ---------------------------------------------------------------- rule

const FIX: Record<DevKind, string> = {
  "next dev": "Build with next build and start with next start; next dev is a development server.",
  vite: "Serve the output of vite build from a static host (or vite preview); the Vite dev server is for development only.",
  nodemon: "Run the app with node in production; nodemon watches files and restarts the process on changes.",
  "uvicorn --reload": "Remove --reload from the production command; it watches files and is meant for development.",
};

export const productionDebugRule = defineRule({
  id: "web/production-debug",
  title: "Debug features on in production",
  pack: "web",
  maturity: "experimental",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => ctx.hasUnit("web") || ctx.hasUnit("api"),
  check(ctx, emit) {
    // ---- Source maps
    for (const unit of ctx.unitsOf("web")) {
      const isNext = unit.framework === "nextjs";
      const file = isNext
        ? firstListed(ctx, ["js", "mjs", "ts", "cjs", "mts"].map((e) => unitRel(unit, `next.config.${e}`)))
        : firstListed(ctx, ["ts", "js", "mjs", "mts", "cjs", "cts"].map((e) => unitRel(unit, `vite.config.${e}`)));
      const pf = file ? ctx.parse(file) : null;
      if (!file || !pf) continue;
      const pairs = isNext ? sourceMapPairs(pf, "productionBrowserSourceMaps", null) : sourceMapPairs(pf, "sourcemap", "build");
      for (const p of pairs) {
        const value = p.childForFieldName("value");
        const v = resolveValue(pf, value);
        const on = evalBoolean(pf, value) === true || (!isNext && v !== null && evalString(pf, v) === "inline");
        if (!on || !value) continue;
        const patch = makePatch(file, pf.source, [rangeEdit(pf.source, value.startIndex, value.endIndex, "false")]);
        emit({
          severity: "low",
          service: serviceFor(ctx, file),
          file,
          line: p.startPosition.row + 1,
          anchor: isNext ? "productionBrowserSourceMaps" : "build.sourcemap",
          evidence: p.text,
          why: WHY,
          fix: {
            summary: isNext ? "Set productionBrowserSourceMaps to false so production builds do not publish source maps." : 'Set build.sourcemap to false (or "hidden" and keep the maps off the public server).',
            ...(patch ? { patch } : {}),
          },
        });
      }
    }

    // ---- Start commands
    const roots = rootsOf(ctx, ["web", "api"]);
    const pkgScripts = new Map<string, { scripts: Record<string, string>; file: string } | null>();
    const scriptsAt = (dir: string) => {
      if (pkgScripts.has(dir)) return pkgScripts.get(dir)!;
      const file = dir ? `${dir}/package.json` : "package.json";
      const text = ctx.read(file);
      let res: { scripts: Record<string, string>; file: string } | null = null;
      if (text !== null) {
        try {
          const pkg = JSON.parse(text) as { scripts?: Record<string, unknown> };
          const scripts: Record<string, string> = {};
          for (const [k, v] of Object.entries(pkg.scripts ?? {})) if (typeof v === "string") scripts[k] = v;
          res = { scripts, file };
        } catch {
          res = null;
        }
      }
      pkgScripts.set(dir, res);
      return res;
    };
    /** Resolve npm-script indirection one level: the first of `scripts` that runs a dev server. */
    const viaScript = (dir: string, scripts: readonly string[], skipStart: boolean): { kind: DevKind; script: string; command: string } | null => {
      for (const script of scripts) {
        if (skipStart && script === "start") continue;
        const cmd = scriptsAt(dir)?.scripts[script];
        if (cmd === undefined) continue;
        const hit = analyseShell(cmd);
        if (hit && hit.kind !== "script") return { kind: hit.kind, script, command: cmd };
      }
      return null;
    };
    const flaggedStart = new Set<string>();

    // package.json scripts.start
    for (const dir of roots) {
      const file = dir ? `${dir}/package.json` : "package.json";
      const text = ctx.read(file);
      if (text === null || !ctx.hasFile(file)) continue;
      const start = jsonProp(jsonProp(parseJsonPos(text), "scripts")?.value, "start");
      if (!start || start.value.kind !== "string") continue;
      const cmd = start.value.value;
      const hit = analyseShell(cmd);
      if (!hit) continue;
      let kind: DevKind | null = null;
      let fixed: string | null = null;
      let evidence = text.slice(start.keyStart, start.value.end);
      if (hit.kind === "script") {
        const r = viaScript(dir, hit.scripts ?? [], true);
        if (!r) continue;
        kind = r.kind;
        evidence = `${evidence} → ${r.script}: ${r.command}`;
      } else {
        kind = hit.kind;
        fixed = hit.fixed;
      }
      flaggedStart.add(dir);
      const raw = text.slice(start.value.start, start.value.end);
      const patch = fixed !== null && raw === JSON.stringify(cmd) ? makePatch(file, text, [rangeEdit(text, start.value.start, start.value.end, JSON.stringify(fixed))]) : undefined;
      emit({
        severity: "medium",
        service: serviceFor(ctx, file),
        file,
        line: lineAt(text, start.keyStart),
        anchor: "scripts.start",
        evidence,
        why: WHY,
        fix: { summary: FIX[kind], ...(patch ? { patch } : {}) },
      });
    }

    // Dockerfile CMD / ENTRYPOINT (final stage) and Procfile web:
    for (const dir of roots) {
      for (const name of ["Dockerfile", "Dockerfile.prod", "Dockerfile.production"]) {
        const file = dir ? `${dir}/${name}` : name;
        if (!ctx.hasFile(file)) continue;
        const text = ctx.read(file);
        if (text === null) continue;
        const all = dockerInstructions(text);
        let lastFrom = -1;
        all.forEach((ins, k) => {
          if (ins.instr === "FROM") lastFrom = k;
        });
        const stage = all.slice(lastFrom + 1);
        const cmdIns = [...stage].reverse().find((x) => x.instr === "CMD");
        const epIns = [...stage].reverse().find((x) => x.instr === "ENTRYPOINT");
        const parts = [epIns, cmdIns].filter((x): x is DockerInstruction => !!x);
        if (parts.length === 0) continue;
        const arrays = parts.map((p) => execForm(p.args));
        let hit: CommandHit | null = null;
        let at: DockerInstruction = parts[parts.length - 1]!;
        if (parts.length === 1) {
          const arr = arrays[0];
          hit = arr ? analyseExec(arr) : analyseShell(parts[0]!.args);
          at = parts[0]!;
        } else if (arrays.every((a) => a !== null)) {
          const joined = arrays.flatMap((a) => a!);
          const h = analyseExec(joined);
          hit = h ? { ...h, fixed: null } : null;
          if (h && h.kind === "uvicorn --reload" && !arrays[1]!.includes("--reload")) at = parts[0]!;
        } else {
          // Mixed forms: a shell-form ENTRYPOINT ignores CMD; an exec-form ENTRYPOINT is analysed on its own.
          const ep = arrays[0] ?? null;
          const h = ep ? analyseExec(ep) : analyseShell(epIns!.args);
          hit = h ? { ...h, fixed: null } : null;
          at = epIns!;
        }
        if (!hit) continue;
        let kind: DevKind;
        let evidence = `${at.instr} ${at.args}`;
        if (hit.kind === "script") {
          const r = viaScript(dir, hit.scripts ?? [], flaggedStart.has(dir));
          if (!r) continue;
          kind = r.kind;
          evidence = `${evidence} → ${r.script}: ${r.command}`;
        } else kind = hit.kind;
        const patch =
          hit.kind !== "script" && hit.fixed !== null && at.line === at.endLine ? makePatch(file, text, [rangeEdit(text, at.argsStart, at.argsEnd, hit.fixed)]) : undefined;
        emit({
          severity: "medium",
          service: serviceFor(ctx, file),
          file,
          line: at.line,
          ...(at.endLine !== at.line ? { endLine: at.endLine } : {}),
          anchor: at.instr,
          evidence,
          why: WHY,
          fix: { summary: FIX[kind], ...(patch ? { patch } : {}) },
        });
      }
      const procfile = dir ? `${dir}/Procfile` : "Procfile";
      if (ctx.hasFile(procfile)) {
        const text = ctx.read(procfile) ?? "";
        const m = /^web[ \t]*:[ \t]*(.*?)[ \t]*\r?$/m.exec(text);
        if (m) {
          const cmd = m[1]!;
          const cmdStart = m.index + m[0].indexOf(cmd, m[0].indexOf(":") + 1);
          const hit = analyseShell(cmd);
          if (hit) {
            let kind: DevKind | null = null;
            let evidence = m[0].trim();
            if (hit.kind === "script") {
              const r = viaScript(dir, hit.scripts ?? [], flaggedStart.has(dir));
              if (r) {
                kind = r.kind;
                evidence = `${evidence} → ${r.script}: ${r.command}`;
              }
            } else kind = hit.kind;
            if (kind) {
              const patch = hit.kind !== "script" && hit.fixed !== null ? makePatch(procfile, text, [rangeEdit(text, cmdStart, cmdStart + cmd.length, hit.fixed)]) : undefined;
              emit({
                severity: "medium",
                service: serviceFor(ctx, procfile),
                file: procfile,
                line: lineAt(text, m.index),
                anchor: "web",
                evidence,
                why: WHY,
                fix: { summary: FIX[kind], ...(patch ? { patch } : {}) },
              });
            }
          }
        }
      }
    }
  },
});
