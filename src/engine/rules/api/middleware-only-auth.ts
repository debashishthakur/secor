// api/middleware-only-auth (spec section 8.5): Next.js units whose middleware calls a guard, with entry points
// that rely on it alone (auth.via = "middleware"). One finding per unit, at the middleware file.

import { callsIn, line } from "../../ast.js";
import { nextMiddleware } from "../../adapters/nextjs.js";
import type { ProjectContext } from "../../context.js";
import type { UnitInfo } from "../../detect.js";
import { guardMatcherFor } from "../../inventory.js";
import { SOURCES, defineRule } from "../types.js";
import { entryKey } from "./common.js";

const ID = "api/middleware-only-auth";
const WHY = "These entry points rely only on middleware for authentication; a gap in the matcher or a middleware bypass leaves them open, because the handlers do not check the session themselves.";
const FIX = "Also check the session inside each handler or server action.";

function guardedMiddleware(ctx: ProjectContext, unit: UnitInfo) {
  const guards = guardMatcherFor(ctx);
  const mw = nextMiddleware({ ctx, unit, guards });
  return mw?.guarded ? { mw, guards } : null;
}

export const middlewareOnlyAuth = defineRule({
  id: ID,
  title: "Auth enforced only in Next.js middleware",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspApi,
  appliesTo: (ctx) => ctx.unitsOf("api", "nextjs").some((u) => guardedMiddleware(ctx, u) !== null),
  check(ctx, emit) {
    for (const unit of ctx.unitsOf("api", "nextjs")) {
      const g = guardedMiddleware(ctx, unit);
      if (!g) continue;
      const covered = ctx.inventory.filter((e) => e.internal.unit === unit && e.service === "api" && e.auth.via === "middleware");
      if (!covered.length) continue;
      const pf = ctx.parse(g.mw.file);
      const guardCall = pf ? callsIn(pf.root).find((c) => g.guards.guardCall(c, "nextjs")) : undefined;
      const keys = covered.map(entryKey);
      emit({
        severity: "medium",
        service: "api",
        file: g.mw.file,
        line: guardCall ? line(guardCall) : 1,
        anchor: `middleware:${unit.root}`,
        evidence: `Only ${g.mw.file} checks auth (${g.mw.guard ?? "guard"}) for ${keys.length} entry point${keys.length === 1 ? "" : "s"}: ${keys.join(", ")}`,
        why: WHY,
        fix: { summary: FIX },
      });
    }
  },
});
