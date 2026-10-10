// connect_vet support (spec sections 9.2 and 11.2). Vetting itself is src/connect/vet.ts (vetServer); it is loaded
// lazily (it brings in the MCP client) and, if it ever cannot be loaded, the tool answers with an "incomplete" report
// instead of failing.

import type { DiscoveredServer } from "../connect/discover.js";
import type { VetReport } from "../types.js";

export type VetServerFn = (server: DiscoveredServer, opts: { allowUnsandboxed: false; timeoutMs?: number }) => Promise<{ report: VetReport }>;

export const VET_UNAVAILABLE_REASON = "vetting is not available in this SECOR build";

/** Load vetServer from src/connect/vet.ts, or null when that module is missing or does not export it. */
export async function loadVetServer(): Promise<VetServerFn | null> {
  try {
    const { vetServer } = await import("../connect/vet.js");
    return (server, opts) => vetServer(server, { allowUnsandboxed: false, ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}) });
  } catch {
    return null;
  }
}

/** The report connect_vet returns when vetting could not run at all. */
export function incompleteReport(server: DiscoveredServer, reason: string): VetReport {
  return {
    server: server.name,
    source: server.source,
    transport: server.transport,
    sandboxed: false,
    toolCount: 0,
    verdict: "incomplete",
    findings: [],
    incompleteReason: reason,
  };
}

/**
 * Vet one server, sandboxed only: `allowUnsandboxed` is always false here, so without a sandbox the report is
 * "incomplete" (spec 9.2). Nothing is written and the server is not added.
 */
export async function vetSandboxedOnly(server: DiscoveredServer, vet: VetServerFn | null): Promise<VetReport> {
  if (!vet) return incompleteReport(server, VET_UNAVAILABLE_REASON);
  const out = await vet(server, { allowUnsandboxed: false });
  if (!out || typeof out !== "object" || !out.report) return incompleteReport(server, VET_UNAVAILABLE_REASON);
  return out.report;
}
