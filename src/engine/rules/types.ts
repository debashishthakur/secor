// Rule interface (spec section 8.4) and a small helper for writing rules.

import type { Finding, Pack } from "../../types.js";
import type { ProjectContext } from "../context.js";
import { type FindingInput, type RuleMeta, makeFinding } from "../finding.js";

export interface Rule {
  id: string;
  title: string;
  pack: Pack;
  maturity: "experimental" | "stable";
  source?: { name: string; url: string };
  appliesTo(ctx: ProjectContext): boolean;
  run(ctx: ProjectContext): Promise<Finding[]>;
}

/**
 * Thrown by a rule whose inputs are missing (network off, git missing, no lockfile...). The rule counts as
 * applicable but not ran, and `{ area: <area or rule title>, reason }` is added to coverage.notChecked.
 */
export class NotChecked extends Error {
  /** `area` overrides the coverage area (default: the rule title), e.g. "Database rules" (spec 8.5). */
  constructor(
    readonly reason: string,
    readonly area?: string,
  ) {
    super(reason);
    this.name = "NotChecked";
  }
}

export type Emit = (f: FindingInput) => Finding;

export interface RuleSpec extends RuleMeta {
  appliesTo(ctx: ProjectContext): boolean;
  /** Report findings with `emit`. Throw NotChecked when inputs are missing. */
  check(ctx: ProjectContext, emit: Emit): Promise<void> | void;
}

export function defineRule(spec: RuleSpec): Rule {
  const meta: RuleMeta = { id: spec.id, title: spec.title, pack: spec.pack, maturity: spec.maturity, ...(spec.source ? { source: spec.source } : {}) };
  return {
    ...meta,
    appliesTo: (ctx) => spec.appliesTo(ctx),
    async run(ctx) {
      const out: Finding[] = [];
      await spec.check(ctx, (f) => {
        const finding = makeFinding(meta, f);
        out.push(finding);
        return finding;
      });
      return out;
    },
  };
}

export const SOURCES = {
  mcpAuth: { name: "MCP specification, authorization", url: "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization" },
  mcpSecurity: { name: "MCP specification, security best practices", url: "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices" },
  mcpTransports: { name: "MCP specification, transports", url: "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports" },
  owaspMcp: { name: "OWASP MCP Top 10", url: "https://owasp.org/www-project-mcp-top-10/" },
  owaspApi: { name: "OWASP API Security Top 10", url: "https://owasp.org/API-Security/" },
  owaspTop10: { name: "OWASP Top 10", url: "https://owasp.org/Top10/" },
} as const;
