// core/paid-api-limit (spec sections 8.3 and 8.5): an entry point that calls a paid AI API with no rate limiting.
// High when the entry point is unguarded or declared public, medium when guarded.

import { anchorText, collapse } from "../../ast.js";
import { callsOneLevel, isPaidApiCall } from "../../auth-guards.js";
import type { InventoryEntry } from "../../inventory-types.js";
import type { SyntaxNode } from "../../parse.js";
import { defineRule } from "../types.js";

const WHY = "Anyone who can reach this entry point can call a paid AI API as often as they like, running up your bill or exhausting your quota.";
const FIX = "Add a per-user or per-IP rate limit and a spend cap at the provider.";

function label(e: InventoryEntry): string {
  switch (e.kind) {
    case "http_route":
      return `${e.method ?? "*"} ${e.path ?? ""}`.trim();
    case "server_action":
      return `server action ${e.name ?? ""}`.trim();
    case "page":
      return `page ${e.path ?? ""}`.trim();
    case "mcp_tool":
      return `MCP tool "${e.name ?? ""}"`;
    case "mcp_resource":
      return `MCP resource "${e.name ?? ""}"`;
    case "mcp_prompt":
      return `MCP prompt "${e.name ?? ""}"`;
  }
}

function firstPaidCall(e: InventoryEntry): SyntaxNode | null {
  for (const h of e.internal.handlers) {
    const call = callsOneLevel(h.node, h.pf).find((c) => isPaidApiCall(c, h.pf));
    if (call) return call;
  }
  return null;
}

export const paidApiLimit = defineRule({
  id: "core/paid-api-limit",
  title: "Paid API reachable without a limit",
  pack: "core",
  // Promoted after validation (DECISIONS.md, "Validation and promotion").
  maturity: "stable",
  appliesTo: (ctx) => ctx.inventory.some((e) => e.callsPaidApi),
  check(ctx, emit) {
    // internal.rateLimited covers route/app middleware, handler limits and Next.js middleware.ts (section 8.3).
    for (const e of ctx.inventory) {
      if (!e.callsPaidApi || e.internal.rateLimited) continue;
      const call = firstPaidCall(e);
      emit({
        severity: !e.auth.guarded || e.declaredPublic ? "high" : "medium",
        service: "core",
        file: e.file,
        line: e.line,
        anchor: anchorText(e.internal.registration.node),
        evidence: `${label(e)}: ${call ? collapse(call.text) : collapse(e.internal.registration.node.text)}`,
        why: WHY,
        fix: { summary: FIX },
        entryPointId: e.id,
      });
    }
  },
});
