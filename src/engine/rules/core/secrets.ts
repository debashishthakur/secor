// core/secrets (spec sections 8.5 and 9.5.1): a secret in a listed file, or in an added line of git history.
//
// `.env*` semantics fall out of the file listing (section 8.1): `git ls-files --cached --others --exclude-standard`
// lists tracked files (even when .gitignore covers them) and untracked files that are not ignored, so a tracked or
// un-ignored `.env` is scanned and an untracked, gitignored one is not. Outside git the walk honours .gitignore.

import type { Severity } from "../../../types.js";
import { MAX_READ_BYTES, type ProjectContext } from "../../context.js";
import { type DetectorMatch, detectSecrets, isConfigLikeFile } from "../../detectors/index.js";
import { DEFAULT_EXCLUDES, runGit } from "../../files.js";
import { langForFile } from "../../parse.js";
import { redact, redactSecretValue } from "../../redact.js";
import { matchesAny } from "../../util/glob.js";
import { sha256Hex } from "../../util/hash.js";
import { defineRule } from "../types.js";

const WHY = "Anyone who can read this code or its git history can use this secret, and it keeps working until it is rotated.";
const WHY_GOOGLE = "Google API key found: check this key's API restrictions.";
const HUMAN_ACTION = "Rotate this key at the provider, then load it from an environment variable.";

/**
 * `git log --all -p --no-color --no-ext-diff --no-textconv --unified=0 -n 1000` (spec 8.5), plus options that only
 * pin the output format against user config: unescaped UTF-8 paths, a bare "commit <sha>" header, a/ b/ prefixes,
 * and paths relative to the project root when it is a subdirectory of the repository.
 */
export const HISTORY_ARGS = [
  "-c",
  "core.quotePath=false",
  "log",
  "--all",
  "-p",
  "--no-color",
  "--no-ext-diff",
  "--no-textconv",
  "--unified=0",
  "-n",
  "1000",
  "--relative",
  "--format=commit %H",
  "--src-prefix=a/",
  "--dst-prefix=b/",
];

/** `.env.example`, `.env.sample`, `.env.template` (and `.env.local.example` style variants): never findings. */
export function isEnvTemplate(file: string): boolean {
  return /^\.env(?:\.[\w-]+)*\.(?:example|sample|template)$/i.test(file.split("/").pop() ?? "");
}

// ---------------------------------------------------------------- git history parsing

export interface HistoryBlock {
  commit: string;
  /** Path of the file in that commit (project-relative). */
  file: string;
  /** New-file line number of the block's first line. */
  startLine: number;
  /** Consecutive added lines joined with "\n". */
  text: string;
}

const C_ESCAPES: Record<string, number> = { n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11, '"': 34, "\\": 92 };

/** Decode a C-style quoted path from a diff header (`"b/we\"ird.txt"`). */
function unquoteC(quoted: string): string {
  const body = quoted.slice(1, quoted.endsWith('"') ? -1 : undefined);
  const parts: Buffer[] = [];
  let last = 0;
  for (const m of body.matchAll(/\\(?:([0-7]{3})|([\s\S]))/g)) {
    parts.push(Buffer.from(body.slice(last, m.index), "utf8"));
    parts.push(Buffer.from([m[1] ? Number.parseInt(m[1], 8) : (C_ESCAPES[m[2]!] ?? m[2]!.charCodeAt(0) & 0xff)]));
    last = m.index + m[0].length;
  }
  parts.push(Buffer.from(body.slice(last), "utf8"));
  return Buffer.concat(parts).toString("utf8");
}

/** Path from a `+++ ` header: strips the tab git appends to names with spaces, unquotes, drops "b/". */
function diffPath(header: string): string | null {
  let p = header.replace(/\t$/, "");
  if (p === "/dev/null") return null;
  if (p.startsWith('"')) p = unquoteC(p);
  return p.startsWith("b/") ? p.slice(2) : null;
}

/** Added-line blocks from `git log -p --unified=0` output, in log order (newest commit first). */
export function parseGitLog(out: string): HistoryBlock[] {
  const blocks: HistoryBlock[] = [];
  let commit = "";
  let file: string | null = null;
  let inHeader = false;
  let newLine = 0;
  let cur: { start: number; lines: string[] } | null = null;
  const flush = () => {
    if (cur && file !== null && cur.lines.length) blocks.push({ commit, file, startLine: cur.start, text: cur.lines.join("\n") });
    cur = null;
  };
  for (const raw of out.split("\n")) {
    // Body lines always start with "+", "-", " " or "\", so these headers cannot be file content.
    if (raw.startsWith("commit ")) {
      flush();
      commit = raw.slice(7).trim();
      file = null;
      inHeader = false;
      continue;
    }
    if (raw.startsWith("diff --git ")) {
      flush();
      file = null;
      inHeader = true;
      continue;
    }
    if (raw.startsWith("@@")) {
      flush();
      inHeader = false;
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
      newLine = m ? Number(m[1]) : 0;
      continue;
    }
    if (inHeader) {
      // Only here can "+++ " be a header; in a hunk it is an added line starting with "++ ".
      if (raw.startsWith("+++ ")) file = diffPath(raw.slice(4));
      continue;
    }
    if (file === null || newLine <= 0) continue;
    if (raw.startsWith("+")) {
      if (!cur || cur.start + cur.lines.length !== newLine) {
        flush();
        cur = { start: newLine, lines: [] };
      }
      cur.lines.push(raw.slice(1));
      newLine++;
    } else if (raw.startsWith(" ")) {
      flush();
      newLine++;
    }
    // "-" lines and "\ No newline at end of file" do not move the new-file line counter.
  }
  flush();
  return blocks;
}

// ---------------------------------------------------------------- evidence

/** Offset → 1-based line within one text (binary search over line starts). */
function lineIndex(text: string): (offset: number) => number {
  const starts = [0];
  for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

/** The line(s) holding the match, with this secret (and anything else the detectors find) redacted, windowed around it. */
export function secretEvidence(text: string, m: DetectorMatch): string {
  const vs = m.start + m.valueStart;
  const ve = vs + m.value.length;
  const lineStart = text.lastIndexOf("\n", vs - 1) + 1;
  let lineEnd = text.indexOf("\n", ve);
  if (lineEnd < 0) lineEnd = text.length;
  const span = text.slice(lineStart, lineEnd);
  const red = redact(span, [{ ...m, start: vs - lineStart, end: ve - lineStart, valueStart: 0 }]);
  const form = redactSecretValue(m.value, m.prefix);
  const at = Math.max(0, red.indexOf(form));
  const from = Math.max(0, at - 70);
  const to = Math.min(red.length, at + form.length + 70);
  return `${from > 0 ? "…" : ""}${red.slice(from, to).trim()}${to < red.length ? "…" : ""}`;
}

/** Code evidence plus a note, trimmed so the note survives the 200-character evidence limit. */
function withNote(code: string, note: string): string {
  const max = 195 - note.length;
  const chars = [...code];
  return `${chars.length > max ? `${chars.slice(0, max - 1).join("")}…` : code} ${note}`;
}

// ---------------------------------------------------------------- rule

interface Hit {
  file: string;
  line: number;
  endLine: number;
  match: DetectorMatch;
  evidence: string;
  /** History hits: the commit and its position in the log (higher = older). */
  commit?: string;
  order?: number;
  alsoInHistory?: boolean;
}

function hitFor(file: string, text: string, lineOf: (offset: number) => number, m: DetectorMatch, firstLine = 1): Omit<Hit, "commit" | "order"> {
  const vs = m.start + m.valueStart;
  return {
    file,
    line: firstLine + lineOf(vs) - 1,
    endLine: firstLine + lineOf(vs + Math.max(0, m.value.length - 1)) - 1,
    match: m,
    evidence: secretEvidence(text, m),
  };
}

/** File text: code files through the shared cache (other rules parse them), every other file uncached. */
function readText(ctx: ProjectContext, rel: string): string | null {
  return ctx.read(rel, { cache: !!langForFile(rel) });
}

function historyGap(ctx: ProjectContext): string | null {
  if (!ctx.git.available) return "git not available";
  if (!ctx.git.isRepo) return "not a git repository";
  return null;
}

export const secrets = defineRule({
  id: "core/secrets",
  title: "Secret in code or git history",
  pack: "core",
  // Promoted after validation (DECISIONS.md, "Validation and promotion").
  maturity: "stable",
  appliesTo: () => true,
  check(ctx, emit) {
    const key = (file: string, value: string) => `${file}\u0000${value}`;

    // 1. Listed files (ctx.files is sorted). One finding per secret value per file, at its first occurrence.
    const current = new Map<string, Hit>();
    for (const file of ctx.files) {
      if (isEnvTemplate(file)) continue;
      const text = readText(ctx, file);
      if (!text) continue;
      const matches = detectSecrets(text, { configLike: isConfigLikeFile(file) });
      if (!matches.length) continue;
      const lineOf = lineIndex(text);
      for (const m of matches) {
        const k = key(file, m.value);
        if (!current.has(k)) current.set(k, hitFor(file, text, lineOf, m));
      }
    }

    // 2. Added lines in git history.
    const history = new Map<string, Hit>();
    const gap = historyGap(ctx);
    if (gap) ctx.addGap("Git history", gap);
    else {
      const res = runGit(HISTORY_ARGS, ctx.root, 120_000);
      if (!res.ok) ctx.addGap("Git history", "git log failed");
      else {
        const excludes = [...DEFAULT_EXCLUDES, ...ctx.config.exclude];
        const order = new Map<string, number>();
        for (const b of parseGitLog(res.stdout)) {
          if (!order.has(b.commit)) order.set(b.commit, order.size);
          // Same limits as the listing: template env files, excluded paths and blocks over 2 MB are skipped.
          if (isEnvTemplate(b.file) || b.text.length > MAX_READ_BYTES || matchesAny(b.file, excludes)) continue;
          const matches = detectSecrets(b.text, { configLike: isConfigLikeFile(b.file) });
          const lineOf = matches.length ? lineIndex(b.text) : () => 1;
          for (const m of matches) {
            const k = key(b.file, m.value);
            const cur = current.get(k);
            if (cur) {
              cur.alsoInHistory = true;
              continue;
            }
            // The file's current content decides: a value it still holds but that is not a finding there
            // (for example a Firebase config apiKey whose context this one-line hunk lacks) is skipped.
            if (ctx.hasFile(b.file) && (readText(ctx, b.file) ?? "").includes(m.value)) continue;
            const hit: Hit = { ...hitFor(b.file, b.text, lineOf, m, b.startLine), commit: b.commit, order: order.get(b.commit)! };
            const prev = history.get(k);
            // Keep the oldest commit that added it (log lists newest first), then the first line.
            if (!prev || hit.order! > prev.order! || (hit.order === prev.order && hit.line < prev.line)) history.set(k, hit);
          }
        }
      }
    }

    const emitHit = (h: Hit) => {
      const severity: Severity = h.match.severity ?? "critical";
      const inHistoryOnly = h.commit !== undefined;
      const evidence = inHistoryOnly
        ? withNote(h.evidence, `(in git history, commit ${h.commit!.slice(0, 12)})`)
        : h.alsoInHistory
          ? withNote(h.evidence, "(also in git history)")
          : h.evidence;
      emit({
        severity,
        service: "core",
        file: h.file,
        line: h.line,
        endLine: h.endLine,
        anchor: sha256Hex(h.match.value),
        evidence,
        why: h.match.kind === "google-api-key" ? WHY_GOOGLE : WHY,
        fix: {
          summary: inHistoryOnly
            ? "Rotate this key: it stays readable in git history even though the current files no longer contain it."
            : "Rotate this key, remove it from the file, and load it from an environment variable.",
          humanAction: HUMAN_ACTION,
        },
      });
    };
    const byLocation = (a: Hit, b: Hit) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line;
    for (const h of [...current.values()].sort(byLocation)) emitHit(h);
    for (const h of [...history.values()].sort(byLocation)) emitHit(h);
  },
});
