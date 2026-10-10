// Human summary of a run (same panels and wording as the dashboard, spec 12.2).

import { counted } from "../engine/finding.js";
import { redact } from "../engine/redact.js";
import { type RunResult, SEVERITIES } from "../types.js";
import { SCORE_NOTICE, bandLabel, c, num, severityLabel } from "./ui.js";

export function printSummary(r: RunResult): void {
  const open = r.findings.filter(counted);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length])) as Record<string, number>;
  const ignored = r.findings.filter((f) => f.status === "ignored").length;
  const advisory = r.findings.filter((f) => f.status === "open" && (f.advisory || f.maturity !== "stable")).length;
  const s = r.score;
  const lines: string[] = [];
  lines.push(c.bold(`SECOR · ${r.project.name} · run ${r.runId} · rules v${r.rulesVersion} · scoring v${s.scoringVersion}`));
  lines.push(`Overall   ${num(s.overall)} / 100   ${bandLabel(s.band)}`);
  lines.push(`Ship      ${num(s.ship)}   API ${num(s.shipByKind.api)} · MCP server ${num(s.shipByKind.mcp)} · Website ${num(s.shipByKind.web)}`);
  lines.push(`Connect   ${num(s.connect)}`);
  lines.push(`Coverage  ${r.coverage.percent}% of applicable checks${s.incomplete ? " · incomplete" : ""}`);
  lines.push(c.dim(SCORE_NOTICE));
  lines.push("");
  lines.push(`Open findings   Critical ${counts.critical} · High ${counts.high} · Medium ${counts.medium} · Low ${counts.low}`);
  lines.push(`Ignored ${ignored}, each with a reason · Advisory ${advisory} (not scored)`);
  lines.push("");
  lines.push("Fix next");
  if (open.length === 0) lines.push("  No counted findings.");
  open.slice(0, 3).forEach((f, i) => lines.push(`  ${i + 1}  ${severityLabel(f.severity)}  ${f.title}  ${f.location.file}:${f.location.line}  ${c.dim(f.id)}`));
  const notScored = r.findings.filter((f) => f.status === "open" && !counted(f));
  if (notScored.length) {
    lines.push("");
    lines.push(`Advisory and experimental findings (not scored, ${notScored.length})`);
    for (const f of notScored.slice(0, 15)) lines.push(`  ${severityLabel(f.severity)}  ${f.title}  ${f.location.file}:${f.location.line}  ${c.dim(f.id)}`);
    if (notScored.length > 15) lines.push(`  … ${notScored.length - 15} more (secor ship --json)`);
  }
  lines.push("");
  lines.push(`Not checked  ${r.coverage.notChecked.map((n) => `${n.area} (${n.reason})`).join(" · ")}`);
  lines.push(c.dim(`Details: secor finding <id>   Units: ${r.units.map((u) => `${u.kind}/${u.framework}${u.root ? ` at ${u.root}` : ""}`).join(", ") || "none detected"}   Entry points: ${r.inventory.length}`));
  process.stdout.write(`${redact(lines.join("\n"))}\n`);
}
