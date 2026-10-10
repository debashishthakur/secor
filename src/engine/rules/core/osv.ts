// OSV client and advisory helpers for core/vulnerable-dependency (spec sections 8.5 and 13): POST /v1/querybatch
// (batches of at most 1000, following per-result next_page_token) and GET /v1/vulns/{id}. Only package names,
// ecosystems and versions are sent.

import type { Severity } from "../../../types.js";
import { normalizePyName } from "../../deps.js";
import { type NetClient, mapLimit } from "../../net.js";
import { type VersionEcosystem, highest, lowestAbove } from "../../versions.js";

export const OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch";
export const OSV_VULN = "https://api.osv.dev/v1/vulns/";
export const OSV_BATCH_SIZE = 1000;
/** Upper bound on follow-up pages per batch (a misbehaving server must not loop us forever). */
const MAX_PAGES = 20;
/** Advisory IDs are placed in a URL path; anything else is ignored. */
const VALID_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface OsvQuery {
  ecosystem: VersionEcosystem;
  name: string;
  version: string;
}

export class OsvError extends Error {}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

export function queryKey(q: OsvQuery): string {
  return `${q.ecosystem}\u0000${q.name}\u0000${q.version}`;
}

/** Advisory IDs for each query (keyed by queryKey). Throws OsvError when OSV cannot answer. */
export async function queryOsv(net: NetClient, queries: readonly OsvQuery[]): Promise<Map<string, Set<string>>> {
  const out = new Map<string, Set<string>>();
  for (const q of queries) out.set(queryKey(q), new Set());
  for (let i = 0; i < queries.length; i += OSV_BATCH_SIZE) {
    let pending: { q: OsvQuery; token?: string }[] = queries.slice(i, i + OSV_BATCH_SIZE).map((q) => ({ q }));
    for (let page = 0; pending.length > 0 && page < MAX_PAGES; page++) {
      const body = {
        queries: pending.map(({ q, token }) => ({ package: { ecosystem: q.ecosystem, name: q.name }, version: q.version, ...(token ? { page_token: token } : {}) })),
      };
      let res;
      try {
        res = await net.postJson(OSV_QUERYBATCH, body);
      } catch (e) {
        throw new OsvError(`OSV query failed (${e instanceof Error ? e.message : String(e)})`);
      }
      const results = isObj(res.body) && Array.isArray(res.body.results) ? res.body.results : null;
      if (res.status !== 200 || !results) throw new OsvError(`OSV query failed (HTTP ${res.status})`);
      const next: { q: OsvQuery; token: string }[] = [];
      pending.forEach((p, j) => {
        const r: unknown = results[j];
        if (!isObj(r)) return;
        const ids = out.get(queryKey(p.q))!;
        if (Array.isArray(r.vulns)) for (const v of r.vulns) if (isObj(v) && typeof v.id === "string" && VALID_ID.test(v.id)) ids.add(v.id);
        const token = typeof r.next_page_token === "string" && r.next_page_token ? r.next_page_token : null;
        if (token && token !== p.token) next.push({ q: p.q, token });
      });
      pending = next;
    }
  }
  return out;
}

/** Full advisory documents by ID (null when OSV did not return one), fetched 8 at a time. */
export async function fetchAdvisories(net: NetClient, ids: readonly string[]): Promise<Map<string, Obj | null>> {
  const docs = await mapLimit(ids, 8, async (id) => {
    try {
      const res = await net.getJson(`${OSV_VULN}${encodeURIComponent(id)}`);
      return res.status === 200 && isObj(res.body) ? res.body : null;
    } catch {
      return null;
    }
  });
  return new Map(ids.map((id, i) => [id, docs[i] ?? null]));
}

/** database_specific.severity → finding severity; medium when absent or unknown (spec 8.5). */
export function advisorySeverity(doc: Obj | null): Severity {
  const ds = doc && isObj(doc.database_specific) ? doc.database_specific : null;
  const s = ds && typeof ds.severity === "string" ? ds.severity.toUpperCase() : "";
  switch (s) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    default:
      return "medium"; // MODERATE, MEDIUM, absent
  }
}

export function isWithdrawn(doc: Obj | null): boolean {
  return !!doc && typeof doc.withdrawn === "string" && doc.withdrawn.length > 0;
}

/** `fixed` events from the advisory's ranges for exactly this package (SEMVER / ECOSYSTEM ranges only). */
export function fixedVersionsFor(doc: Obj, ecosystem: VersionEcosystem, name: string): string[] {
  const norm = (n: string) => (ecosystem === "PyPI" ? normalizePyName(n) : n);
  const want = norm(name);
  const out: string[] = [];
  for (const a of Array.isArray(doc.affected) ? doc.affected : []) {
    if (!isObj(a) || !isObj(a.package)) continue;
    if (a.package.ecosystem !== ecosystem || typeof a.package.name !== "string" || norm(a.package.name) !== want) continue;
    for (const r of Array.isArray(a.ranges) ? a.ranges : []) {
      if (!isObj(r) || (r.type !== "SEMVER" && r.type !== "ECOSYSTEM")) continue;
      for (const e of Array.isArray(r.events) ? r.events : []) if (isObj(e) && typeof e.fixed === "string" && e.fixed) out.push(e.fixed);
    }
  }
  return out;
}

export interface FixPlan {
  /** Lowest version that fixes every advisory that has a fix (max over advisories of the lowest fix above current). */
  target: string | null;
  /** Advisories with no fixed version above the current one. */
  unfixed: string[];
  /** Advisories whose details could not be fetched. */
  unknown: string[];
}

export function planFix(ecosystem: VersionEcosystem, name: string, version: string, ids: readonly string[], docs: ReadonlyMap<string, Obj | null>): FixPlan {
  const fixes: string[] = [];
  const unfixed: string[] = [];
  const unknown: string[] = [];
  for (const id of ids) {
    const doc = docs.get(id) ?? null;
    if (!doc) {
      unknown.push(id);
      continue;
    }
    const fix = lowestAbove(ecosystem, version, fixedVersionsFor(doc, ecosystem, name));
    if (fix) fixes.push(fix);
    else unfixed.push(id);
  }
  return { target: highest(ecosystem, fixes), unfixed, unknown };
}

export function fixSummary(name: string, version: string, plan: FixPlan): string {
  const parts: string[] = [];
  if (plan.target) parts.push(`Upgrade ${name} from ${version} to ${plan.target}.`);
  if (plan.unfixed.length) parts.push(plan.target ? `No fixed version yet for ${plan.unfixed.join(", ")}.` : "No fixed version yet");
  if (plan.unknown.length) parts.push(`Advisory details unavailable for ${plan.unknown.join(", ")}; check them at osv.dev.`);
  return parts.join(" ") || "No fixed version yet";
}
