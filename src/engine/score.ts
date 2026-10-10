// Score, scoring version 1 (spec section 10). All numbers are integers. Changing any number here
// requires a new scoring version.

import type { Band, Finding, ScoreBreakdown, ServiceKind, ServiceUnit, Severity, VetReport } from "../types.js";
import { counted } from "./finding.js";

export const WEIGHTS: Record<Severity, number> = { critical: 25, high: 8, medium: 3, low: 1 };

export function scoreFindings(fs: readonly Finding[]): number {
  const c = fs.filter(counted);
  let s = 100 - c.reduce((sum, f) => sum + WEIGHTS[f.severity], 0);
  if (c.some((f) => f.severity === "critical")) s = Math.min(s, 49);
  else if (c.some((f) => f.severity === "high")) s = Math.min(s, 79);
  return Math.max(s, 0);
}

function under(root: string, file: string): boolean {
  return root === "" || file === root || file.startsWith(`${root}/`);
}

export function kindsOf(f: Finding, units: readonly ServiceUnit[]): Set<ServiceKind> {
  if (f.service !== "core") return new Set([f.service]);
  const containing = units.filter((u) => under(u.root, f.location.file)).map((u) => u.kind);
  return new Set(containing.length ? containing : units.map((u) => u.kind));
}

export function band(n: number | null): Band | null {
  if (n === null) return null;
  if (n <= 49) return "fix-before-deploy";
  if (n <= 79) return "needs-work";
  return "no-known-critical-or-high";
}

export const BAND_LABELS: Record<Band, string> = {
  "fix-before-deploy": "Fix before deploy",
  "needs-work": "Needs work",
  "no-known-critical-or-high": "No critical or high issues known",
};

export interface ServerScoreInput {
  vetted: boolean;
  scoped: boolean;
  transport: "stdio" | "http";
  sandbox: "yes" | "no" | "n/a";
  changed: boolean;
  vetVerdict: VetReport["verdict"] | null;
}

export function serverScore(srv: ServerScoreInput): number {
  let s = 100;
  if (!srv.vetted) s -= 30;
  if (!srv.scoped) s -= 20;
  if (srv.transport === "stdio" && srv.sandbox !== "yes") s -= 25;
  if (srv.changed) s -= 10;
  if (srv.vetVerdict === "high-risk") s = Math.min(s, 49);
  else if (srv.vetVerdict === "review") s = Math.min(s, 79);
  return Math.max(s, 0);
}

export function computeScore(findings: readonly Finding[], units: readonly ServiceUnit[], coveragePercent: number, connect: number | null): ScoreBreakdown {
  const detected = new Set(units.map((u) => u.kind));
  const shipByKind: ScoreBreakdown["shipByKind"] = { api: null, mcp: null, web: null };
  for (const k of ["api", "mcp", "web"] as const) {
    if (!detected.has(k)) continue;
    shipByKind[k] = scoreFindings(findings.filter((f) => kindsOf(f, units).has(k)));
  }
  const shipValues = Object.values(shipByKind).filter((v): v is number => v !== null);
  const ship = shipValues.length ? Math.min(...shipValues) : null;
  const both = [ship, connect].filter((v): v is number => v !== null);
  const overall = both.length ? Math.min(...both) : null;
  return { scoringVersion: 1, overall, band: band(overall), ship, shipByKind, connect, incomplete: coveragePercent < 70 };
}
