// Human output helpers. No colour when stdout is not a TTY (spec 11.1). Text never calls the system "secure".

import type { Band, Severity } from "../types.js";
import { BAND_LABELS } from "../engine/score.js";

const useColor = () => !!process.stdout.isTTY && !process.env.NO_COLOR;

function wrap(code: string, s: string): string {
  return useColor() ? `\x1b[${code}m${s}\x1b[0m` : s;
}

export const c = {
  red: (s: string) => wrap("31", s),
  amber: (s: string) => wrap("33", s),
  green: (s: string) => wrap("32", s),
  dim: (s: string) => wrap("2", s),
  bold: (s: string) => wrap("1", s),
};

export function severityLabel(s: Severity): string {
  const label = s[0]!.toUpperCase() + s.slice(1);
  if (s === "critical") return c.red(label);
  if (s === "high" || s === "medium") return c.amber(label);
  return label;
}

export function bandLabel(b: Band | null): string {
  if (!b) return "n/a";
  const label = BAND_LABELS[b];
  if (b === "fix-before-deploy") return c.red(label);
  if (b === "needs-work") return c.amber(label);
  return c.green(label);
}

export function num(n: number | null): string {
  return n === null ? "—" : String(n);
}

export const SCORE_NOTICE = "This score counts known issues in the checks SECOR ran. It does not measure how hard your system is to attack.";

export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode = 2,
  ) {
    super(message);
  }
}

/** Print JSON to stdout (callers redact before passing). */
export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}
