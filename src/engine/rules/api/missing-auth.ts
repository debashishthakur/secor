// api/missing-auth (spec section 8.5): HTTP routes and server actions with no login check.

import { args, calleeName, calleePath, callsIn, exportsOf, exprPath, importOf, isCall, kids, topLevel, unwrap } from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import { findingId } from "../../finding.js";
import type { InventoryEntry } from "../../inventory-types.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { SOURCES, defineRule } from "../types.js";
import { apiEntries, entryKey, entryTarget, firstLine, handlerKind, testTemplate } from "./common.js";
import { isWebhookEntry, webhookVerified } from "./webhook-signature.js";

const ID = "api/missing-auth";
const WHY = "Anyone who can reach this entry point can call it without signing in, so the data and actions behind it are open to the internet.";
const FIX = "Call a guard at the top of the handler and return 401 when there is no session, or declare the route public in secor.config.yaml with a reason.";

/** Auth libraries' own login / callback handlers (Auth.js, NextAuth v4, better-auth). */
const AUTH_HANDLER_CALLS = new Set(["NextAuth", "toNextJsHandler", "toNodeHandler", "ExpressAuth"]);
/** Handlers that complete a sign-in (Supabase OAuth / magic-link callbacks). */
const AUTH_CALLBACK = /(?:^|\.)auth\.(?:exchangeCodeForSession|verifyOtp)$/;

/** Value of a top-level `const { a, b } = value` that binds `name`. */
function destructuredDecl(pf: ParsedFile, name: string): SyntaxNode | null {
  for (const stmt of kids(pf.root)) {
    const decl = stmt.type === "export_statement" ? stmt.childForFieldName("declaration") : stmt;
    if (!decl || (decl.type !== "lexical_declaration" && decl.type !== "variable_declaration")) continue;
    for (const d of kids(decl)) {
      const pat = d.childForFieldName("name");
      if (d.type !== "variable_declarator" || pat?.type !== "object_pattern") continue;
      const binds = kids(pat).some((c) => (c.type === "shorthand_property_identifier_pattern" && c.text === name) || (c.type === "pair_pattern" && c.childForFieldName("value")?.text === name));
      if (binds) return d.childForFieldName("value");
    }
  }
  return null;
}

function fromAuthLibrary(pf: ParsedFile, n: SyntaxNode | null, depth = 0): boolean {
  const u = unwrap(n);
  if (!u || depth > 4) return false;
  if (isCall(u)) return AUTH_HANDLER_CALLS.has(calleeName(u));
  if (u.type === "member_expression") {
    const obj = u.childForFieldName("object");
    return /(?:^|\.)handlers$/.test(exprPath(obj)) || fromAuthLibrary(pf, obj, depth + 1);
  }
  if (u.type === "identifier") {
    const decl = topLevel(pf).get(u.text)?.value ?? destructuredDecl(pf, u.text);
    if (decl) return fromAuthLibrary(pf, decl, depth + 1);
    // Auth.js v5: `export const { handlers, auth } = NextAuth(config)` in auth.ts, then `import { handlers } from "@/auth"`.
    return importOf(pf, u.text)?.imported === "handlers";
  }
  return false;
}

/** Login endpoints of auth libraries (DECISIONS: not a finding; they are the sign-in itself). */
export function isAuthLibraryHandler(e: InventoryEntry): boolean {
  const pf = e.internal.registration.pf;
  if (e.framework === "nextjs" && e.kind === "http_route") {
    const name = handlerKind(e) === "pages" ? "default" : (e.method ?? "");
    const value = exportsOf(pf).get(name) ?? destructuredDecl(pf, name);
    if (value && fromAuthLibrary(pf, value)) return true;
  }
  if (e.framework === "express" && e.kind === "http_route") {
    const last = unwrap(args(e.internal.registration.node).at(-1) ?? null);
    if (last && isCall(last) && AUTH_HANDLER_CALLS.has(calleeName(last))) return true;
  }
  return e.internal.handlers.some((h) => callsIn(h.node).some((c) => AUTH_CALLBACK.test(calleePath(c))));
}

const STATIC_CALLS = new Set(["sendFile", "redirect", "status", "join", "resolve", "dirname", "fileURLToPath"]);

/**
 * Express handlers that only serve a static file or redirect (SPA fallback `res.sendFile(index.html)`): these are pages,
 * not API entry points (DECISIONS). Any other call (res.json, a database call, ...) keeps the finding.
 */
function staticOrRedirect(e: InventoryEntry): boolean {
  if (e.framework !== "express" || !e.internal.handlers.length) return false;
  return e.internal.handlers.every((h) => {
    const calls = callsIn(h.node);
    return calls.length > 0 && calls.some((c) => /^(?:sendFile|redirect)$/.test(calleeName(c))) && calls.every((c) => STATIC_CALLS.has(calleeName(c)));
  });
}

/** Webhook receivers authenticate the sender by signature (DECISIONS: a verified webhook is not missing auth). */
function verifiedWebhook(ctx: ProjectContext, e: InventoryEntry): boolean {
  return isWebhookEntry(e) && webhookVerified(ctx, e);
}

export const missingAuth = defineRule({
  id: ID,
  title: "Entry point with no login check",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspApi,
  appliesTo: (ctx) => apiEntries(ctx).length > 0,
  check(ctx, emit) {
    for (const e of apiEntries(ctx)) {
      if (e.auth.guarded || e.declaredPublic || e.internal.middlewareCovered) continue;
      if (e.method === "OPTIONS") continue;
      if (isAuthLibraryHandler(e) || verifiedWebhook(ctx, e) || staticOrRedirect(e)) continue;
      const anchor = entryKey(e);
      const id = findingId(ID, e.file, anchor);
      emit({
        severity: "critical",
        service: "api",
        file: e.file,
        line: e.line,
        anchor,
        evidence: `${entryKey(e)}: ${firstLine(e.internal.registration.node.text)}`,
        why: WHY,
        fix: { summary: FIX, testTemplate: testTemplate(ctx, ID, id, entryTarget(e)) },
        entryPointId: e.id,
      });
    }
  },
});
