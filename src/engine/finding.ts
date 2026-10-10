// Findings: construction, IDs (spec section 8.7) and ordering.

import { type Finding, SEVERITY_RANK, type ServiceKind, type Severity } from "../types.js";
import { evidence as toEvidence } from "./redact.js";
import { sha256Hex } from "./util/hash.js";

export interface RuleMeta {
  id: string;
  title: string;
  pack: "core" | "api" | "mcp" | "web";
  maturity: "experimental" | "stable";
  source?: { name: string; url: string };
}

export interface FindingInput {
  severity: Severity;
  advisory?: boolean;
  service: ServiceKind | "core";
  file: string;
  line: number;
  endLine?: number;
  /**
   * Stable anchor (spec 8.7), never the line number: the flagged node's text with whitespace collapsed,
   * sha256 of a secret value, `name@version` for dependencies, or a config key path.
   */
  anchor: string;
  /** Raw evidence text; it is redacted, flattened and truncated here. */
  evidence: string;
  why: string;
  fix: Finding["fix"];
  entryPointId?: string;
  probe?: boolean;
  /** Overrides the rule's source for this finding. */
  source?: { name: string; url: string };
}

const anchors = new WeakMap<Finding, { anchor: string }>();

export function findingId(ruleId: string, file: string, anchor: string): string {
  return `${ruleId.replace(/\//g, "-")}-${sha256Hex(`${ruleId}\n${file}\n${anchor}`).slice(0, 12)}`;
}

export function makeFinding(rule: RuleMeta, f: FindingInput): Finding {
  const finding: Finding = {
    id: findingId(rule.id, f.file, f.anchor),
    ruleId: rule.id,
    title: rule.title,
    severity: f.severity,
    advisory: f.advisory ?? false,
    maturity: rule.maturity,
    service: f.service,
    location: { file: f.file, line: f.line, ...(f.endLine !== undefined && f.endLine !== f.line ? { endLine: f.endLine } : {}) },
    ...(f.entryPointId ? { entryPointId: f.entryPointId } : {}),
    evidence: toEvidence(f.evidence),
    why: f.why,
    fix: f.fix,
    ...(f.source ?? rule.source ? { source: f.source ?? rule.source } : {}),
    status: "open",
    ...(f.probe ? { probe: true } : {}),
  };
  anchors.set(finding, { anchor: f.anchor });
  return finding;
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    (a.location.file < b.location.file ? -1 : a.location.file > b.location.file ? 1 : 0) ||
    a.location.line - b.location.line ||
    (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0) ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  );
}

export function sortFindings(fs: Finding[]): Finding[] {
  return [...fs].sort(compareFindings);
}

/**
 * Make IDs unique within one rule's output. Exact duplicates (same ID and line) are dropped; a second
 * occurrence of the same anchor in the same file gets "#2" appended to its anchor (DECISIONS.md).
 */
export function uniqueIds(fs: Finding[]): Finding[] {
  const byId = new Map<string, Finding[]>();
  for (const f of [...fs].sort((a, b) => a.location.line - b.location.line)) {
    const list = byId.get(f.id) ?? [];
    if (list.some((x) => x.location.line === f.location.line && x.location.file === f.location.file)) continue;
    list.push(f);
    byId.set(f.id, list);
  }
  const out: Finding[] = [];
  for (const list of byId.values()) {
    list.forEach((f, i) => {
      if (i > 0) {
        const anchor = anchors.get(f)?.anchor ?? String(f.location.line);
        f.id = findingId(f.ruleId, f.location.file, `${anchor}\n#${i + 1}`);
      }
      out.push(f);
    });
  }
  return out;
}

/** A finding counts toward score and gate (spec 8.4). */
export function counted(f: Finding): boolean {
  return f.status === "open" && !f.advisory && f.maturity === "stable";
}
