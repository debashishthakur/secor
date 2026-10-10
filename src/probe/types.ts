// Probe internal types (spec 9A).

import type { ServiceKind, Severity } from "../types.js";
import type { IpClass } from "./addresses.js";

export const PROBE_CHECK_IDS = [
  "open-endpoint",
  "security-headers",
  "tls-redirect",
  "cookie-flags",
  "cors-reflection",
  "exposed-artifact",
  "anon-table-read",
  "idor",
  "privilege-field",
] as const;

export type ProbeCheckId = (typeof PROBE_CHECK_IDS)[number];

export type VerifyMethod = "token" | "dns" | "host-api" | "local";

/** A target that has passed the scope guard and ownership check. */
export interface VerifiedTarget {
  /** The URL as supplied (normalised by URL). */
  url: string;
  origin: string;
  host: string;
  protocol: "http:" | "https:";
  port: number;
  /** "private" => loopback/link-local/RFC1918/RFC4193; "public" => proven owned. */
  kind: "private" | "public";
  method: VerifyMethod;
  /** The IP we pin connections to (re-resolved and re-checked before every connection). */
  pinnedIp: string;
  pinnedFamily: 4 | 6;
}

/** A problem Probe confirmed against the live target, before it is turned into / merged into a Finding. */
export interface ProbeFinding {
  check: ProbeCheckId;
  ruleId: string; // "probe/<check>"
  severity: Severity;
  advisory?: boolean;
  service: ServiceKind;
  /** Location for a probe-only finding (entry point file, or the requested path for root checks). */
  file: string;
  line: number;
  /** Stable anchor for the finding ID. */
  anchor: string;
  /** Raw evidence (redacted by makeFinding). */
  evidence: string;
  why: string;
  /** Short human proof appended when merging into a static finding ("... confirmed live: <proof>"). */
  proof: string;
  entryPointId?: string;
  /** Secondary merge key when there is no entryPointId (missing header name, cookie name, table name). */
  matchKey?: string;
}

export class ProbeRefusal extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ProbeRefusal";
  }
}

export interface ClassifiedHost {
  host: string;
  /** null when the host is a DNS name (resolved later). */
  ipClass: IpClass | null;
}
