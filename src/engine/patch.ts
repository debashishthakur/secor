// Unified diffs for proposed fixes (spec section 8.8). SECOR never applies them.

export interface LineEdit {
  /** First line to replace (1-based). */
  startLine: number;
  /** Last line to replace (inclusive). Use startLine - 1 to insert before startLine without removing anything. */
  endLine: number;
  newLines: string[];
}

/** Edit that replaces the first occurrence of `from` with `to` on one line. Null when `from` is not on that line. */
export function replaceOnLine(original: string, line: number, from: string, to: string): LineEdit | null {
  const lines = original.split("\n");
  const text = lines[line - 1];
  if (text === undefined || !text.includes(from)) return null;
  return { startLine: line, endLine: line, newLines: [text.replace(from, to)] };
}

/**
 * Unified diff of `edits` against `original` (relative path `file`), with `context` lines of context.
 * Edits must not overlap. Returns "" when nothing changes.
 */
export function unifiedDiff(file: string, original: string, edits: LineEdit[], context = 3): string {
  const hasFinalNewline = original.endsWith("\n");
  const oldLines = (hasFinalNewline ? original.slice(0, -1) : original).split("\n");
  const sorted = [...edits].sort((a, b) => a.startLine - b.startLine);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i]!.startLine <= sorted[i - 1]!.endLine) throw new Error("overlapping edits");
  }
  // Build the new file and a per-line op list.
  type Op = { kind: " " | "-" | "+"; text: string; oldNo: number; newNo: number };
  const ops: Op[] = [];
  let oldNo = 1;
  let newNo = 1;
  let ei = 0;
  while (oldNo <= oldLines.length || ei < sorted.length) {
    const e = sorted[ei];
    if (e && oldNo === e.startLine) {
      for (let k = e.startLine; k <= e.endLine; k++) ops.push({ kind: "-", text: oldLines[k - 1] ?? "", oldNo: k, newNo });
      for (const nl of e.newLines) ops.push({ kind: "+", text: nl, oldNo: e.endLine + 1, newNo: newNo++ });
      oldNo = e.endLine + 1;
      ei++;
      continue;
    }
    if (oldNo > oldLines.length) break;
    ops.push({ kind: " ", text: oldLines[oldNo - 1]!, oldNo, newNo });
    oldNo++;
    newNo++;
  }
  const changed = ops.map((o, i) => (o.kind !== " " ? i : -1)).filter((i) => i >= 0);
  if (changed.length === 0) return "";
  // Group changes into hunks.
  const hunks: [number, number][] = [];
  for (const i of changed) {
    const start = Math.max(0, i - context);
    const end = Math.min(ops.length - 1, i + context);
    const last = hunks[hunks.length - 1];
    if (last && start <= last[1] + 1) last[1] = Math.max(last[1], end);
    else hunks.push([start, end]);
  }
  const out = [`--- a/${file}`, `+++ b/${file}`];
  for (const [s, e] of hunks) {
    const slice = ops.slice(s, e + 1);
    const oldCount = slice.filter((o) => o.kind !== "+").length;
    const newCount = slice.filter((o) => o.kind !== "-").length;
    const firstOld = slice.find((o) => o.kind !== "+")?.oldNo ?? slice[0]!.oldNo;
    const firstNew = slice.find((o) => o.kind !== "-")?.newNo ?? slice[0]!.newNo;
    const oldStart = oldCount === 0 ? firstOld - 1 : firstOld;
    const newStart = newCount === 0 ? firstNew - 1 : firstNew;
    out.push(`@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`);
    for (const o of slice) out.push(`${o.kind}${o.text}`);
  }
  if (!hasFinalNewline) out.push("\\ No newline at end of file");
  return `${out.join("\n")}\n`;
}

/** Apply a unified diff produced by unifiedDiff (used by tests to check patches apply cleanly). */
export function applyEdits(original: string, edits: LineEdit[]): string {
  const hasFinalNewline = original.endsWith("\n");
  const lines = (hasFinalNewline ? original.slice(0, -1) : original).split("\n");
  for (const e of [...edits].sort((a, b) => b.startLine - a.startLine)) lines.splice(e.startLine - 1, e.endLine - e.startLine + 1, ...e.newLines);
  return lines.join("\n") + (hasFinalNewline ? "\n" : "");
}
