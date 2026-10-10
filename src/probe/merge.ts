// Turn probe findings into report findings (spec 9A.5, 9A.6). A probe finding that confirms a matching
// static finding merges into it (keep the static id/location, advisory -> false, append the live proof,
// probe: true). The rest become new experimental probe findings.

import { makeFinding, type RuleMeta } from "../engine/finding.js";
import { evidence as toEvidence } from "../engine/redact.js";
import type { Finding, Pack, ServiceKind } from "../types.js";
import type { ProbeCheckId, ProbeFinding } from "./types.js";

export const PROBE_SOURCE = { name: "probe", url: "secor-design.md#9a" } as const;

/** probe check -> the static rule it confirms (null = no static counterpart; stays a standalone probe finding). */
export const CONFIRMS: Record<ProbeCheckId, string | null> = {
  "open-endpoint": "api/missing-auth",
  "cors-reflection": "api/cors-credentials",
  idor: "api/missing-ownership",
  "privilege-field": "web/client-only-checks",
  "anon-table-read": "web/database-rules",
  "security-headers": "web/security-headers",
  "cookie-flags": "web/cookie-flags",
  "tls-redirect": null,
  "exposed-artifact": null,
};

const TITLES: Record<ProbeCheckId, string> = {
  "open-endpoint": "Endpoint returned data without a session",
  "security-headers": "Security header missing (confirmed live)",
  "tls-redirect": "Site does not redirect to HTTPS",
  "cookie-flags": "Session cookie missing flags (confirmed live)",
  "cors-reflection": "CORS reflects any origin with credentials (confirmed live)",
  "exposed-artifact": "Exposed artifact reachable",
  "anon-table-read": "Table readable with the public anon key (confirmed live)",
  idor: "Record readable across accounts (confirmed live)",
  "privilege-field": "Admin data returned to a non-admin (confirmed live)",
};

const FIXES: Record<ProbeCheckId, string> = {
  "open-endpoint": "Add a login check at the top of the handler and return 401 when there is no session, or declare the route public with a reason.",
  "security-headers": "Add the missing security header to your framework's header configuration.",
  "tls-redirect": "Redirect all HTTP traffic to HTTPS and enable Strict-Transport-Security.",
  "cookie-flags": "Set the session cookie with HttpOnly, Secure and SameSite.",
  "cors-reflection": "List allowed origins explicitly instead of reflecting the request origin with credentials.",
  "exposed-artifact": "Stop serving this file: remove it from the deployed output or block the path at the edge.",
  "anon-table-read": "Enable row-level security with owner-based policies (auth.uid() = user_id) on this table.",
  idor: "Filter the query by the signed-in user's ID, or compare the record's owner before returning it.",
  "privilege-field": "Enforce the role check in the server handler, not only in the UI.",
};

function packFor(service: ServiceKind): Pack {
  return service;
}

function matchesKey(f: Finding, key: string): boolean {
  const hay = `${f.evidence}\n${f.why}\n${f.title}\n${f.location.file}`.toLowerCase();
  return hay.includes(key.toLowerCase());
}

/** Append the live proof to a static finding's evidence, keeping it one line and <= 200 chars. */
function mergedEvidence(staticEvidence: string, proof: string): string {
  const combined = `${staticEvidence} · confirmed live: ${proof}`;
  if (combined.length <= 200) return combined;
  return toEvidence(`confirmed live: ${proof} · ${staticEvidence}`);
}

export interface MergeResult {
  findings: Finding[];
  /** How many probe findings merged into an existing static finding. */
  merged: number;
  /** How many probe findings were added as new standalone findings. */
  added: number;
}

export function mergeProbeFindings(staticFindings: readonly Finding[], probeFindings: readonly ProbeFinding[]): MergeResult {
  const findings: Finding[] = staticFindings.map((f) => ({ ...f }));
  const usedStaticIds = new Set<string>();
  let merged = 0;
  let added = 0;

  for (const pf of probeFindings) {
    const staticRuleId = CONFIRMS[pf.check];
    let target: Finding | undefined;
    if (staticRuleId) {
      const candidates = findings.filter((f) => f.ruleId === staticRuleId && !usedStaticIds.has(f.id));
      target =
        (pf.entryPointId ? candidates.find((f) => f.entryPointId === pf.entryPointId) : undefined) ??
        (pf.matchKey ? candidates.find((f) => matchesKey(f, pf.matchKey!)) : undefined) ??
        candidates[0];
    }
    if (target) {
      usedStaticIds.add(target.id);
      target.advisory = false;
      target.probe = true;
      target.evidence = mergedEvidence(target.evidence, pf.proof);
      merged++;
    } else {
      const meta: RuleMeta = { id: pf.ruleId, title: TITLES[pf.check], pack: packFor(pf.service), maturity: "experimental", source: PROBE_SOURCE };
      findings.push(
        makeFinding(meta, {
          severity: pf.severity,
          ...(pf.advisory ? { advisory: true } : {}),
          service: pf.service,
          file: pf.file,
          line: pf.line,
          anchor: pf.anchor,
          evidence: pf.evidence,
          why: pf.why,
          fix: { summary: FIXES[pf.check] },
          ...(pf.entryPointId ? { entryPointId: pf.entryPointId } : {}),
          probe: true,
        }),
      );
      added++;
    }
  }
  return { findings, merged, added };
}
