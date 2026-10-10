// api/webhook-signature (spec section 8.5): webhook handlers that never verify the provider's signature,
// and Next.js handlers that parse JSON before Stripe's constructEvent (which needs the raw body).

import { anchorText, callee, calleeName, calleePath, callsIn, exportsOf, importOf, importsFrom, isCall, isFunction, isNew, line, references, resolveFunction, resolveLocal, unwrap } from "../../ast.js";
import { callsOneLevel } from "../../auth-guards.js";
import type { ProjectContext } from "../../context.js";
import { findingId } from "../../finding.js";
import type { InventoryEntry } from "../../inventory-types.js";
import type { ParsedFile, SyntaxNode } from "../../parse.js";
import { resolveJsModule } from "../../resolve.js";
import { SOURCES, defineRule } from "../types.js";
import { apiEntries, entryKey, entryTarget, firstLine, handlerKind, requestModel, testTemplate } from "./common.js";

const ID = "api/webhook-signature";
const WHY = "Webhook events must be verified against the provider's signature over the raw request body; without that, anyone can send forged events to this endpoint.";
const FIX = "Verify the signature with the provider's SDK against the raw body.";
const FIX_RAW = "Read the raw body with req.text(), verify it with constructEvent, and only then use the parsed event.";

/** Provider webhook types and signature headers that mark a handler as a webhook receiver. */
const WEBHOOK_HINTS =
  /\bStripe\.(?:Event|DiscriminatedEvent)\b|\bWebhookEvent\b|\bEmitterWebhookEvent\b|\bWebhookRequiredHeaders\b|["'`](?:stripe-signature|svix-id|svix-timestamp|svix-signature|webhook-id|webhook-signature|x-hub-signature(?:-256)?|x-github-event)["'`]/i;
const WEBHOOK_MODULES = /^(?:svix(?:[./][\w./-]+)?|standardwebhooks|@octokit\/webhooks(?:-methods)?|@clerk\/[\w-]+\/webhooks)$/;

/** Applies: the path contains "webhook", or the handler references Stripe, Svix, Clerk or GitHub webhook types. */
export function isWebhookEntry(e: InventoryEntry): boolean {
  if (e.kind !== "http_route") return false;
  if (/webhook/i.test(e.path ?? "")) return true;
  for (const h of e.internal.handlers) {
    if (WEBHOOK_HINTS.test(h.node.text)) return true;
    if (importsFrom(h.pf, WEBHOOK_MODULES).some((b) => references(h.node, b.local))) return true;
  }
  return false;
}

interface ScopedCall {
  call: SyntaxNode;
  pf: ParsedFile;
}

/** Calls made by the handler (and same-file / imported project helpers one level deep) and by its middleware. */
function reachableCalls(ctx: ProjectContext, e: InventoryEntry): ScopedCall[] {
  const out: ScopedCall[] = [];
  const fns: { fn: SyntaxNode; pf: ParsedFile }[] = e.internal.handlers.map((h) => ({ fn: h.node, pf: h.pf }));
  for (const m of e.internal.middleware) {
    const pf = ctx.parse(m.file);
    if (!pf) continue;
    const target = resolveCallable(ctx, pf, m.node);
    if (target) fns.push(target);
    else if (isCall(unwrap(m.node))) out.push({ call: unwrap(m.node)!, pf });
  }
  for (const { fn, pf } of fns) {
    for (const c of callsOneLevel(fn, pf)) {
      out.push({ call: c, pf });
      const imported = importedFunction(ctx, pf, c);
      if (imported) for (const inner of callsIn(imported.fn)) out.push({ call: inner, pf: imported.pf });
    }
  }
  return out;
}

function resolveCallable(ctx: ProjectContext, pf: ParsedFile, n: SyntaxNode): { fn: SyntaxNode; pf: ParsedFile } | null {
  const u = unwrap(n);
  if (!u) return null;
  if (isFunction(u)) return { fn: u, pf };
  if (u.type !== "identifier") return null;
  const local = resolveFunction(pf, u, u);
  if (local) return { fn: local, pf };
  const imp = importOf(pf, u.text);
  if (!imp || pf.lang === "python") return null;
  const file = resolveJsModule(ctx, pf.file, imp.source);
  const tpf = file ? ctx.parse(file) : null;
  const v = tpf ? exportsOf(tpf).get(imp.imported === "*" ? "default" : imp.imported) : null;
  const fn = tpf && v ? resolveFunction(tpf, v) : null;
  return fn && tpf ? { fn, pf: tpf } : null;
}

function importedFunction(ctx: ProjectContext, pf: ParsedFile, call: SyntaxNode): { fn: SyntaxNode; pf: ParsedFile } | null {
  const c = callee(call);
  if (c?.type !== "identifier" || pf.lang === "python" || !importOf(pf, c.text)) return null;
  return resolveCallable(ctx, pf, c);
}

/** Is this a signature-verification call (section 8.5 list, plus Stripe's Python construct_event and Clerk's verifyWebhook)? */
export function isVerifyCall(call: SyntaxNode, pf: ParsedFile): boolean {
  const name = calleeName(call);
  const path = calleePath(call);
  if (name === "constructEvent" && /(?:^|\.)webhooks\.constructEvent$/i.test(path)) return true;
  if (name === "constructEventAsync" || name === "construct_event" || name === "verifyWebhook" || name === "verifyAndReceive") return true;
  if (name === "timingSafeEqual" || name === "compare_digest") return true;
  if (name === "verify") {
    const recv = unwrap(callee(call)?.childForFieldName("object") ?? null);
    if (!recv) return importsFrom(pf, /^@octokit\/webhooks(?:-methods)?$/).length > 0;
    if (isWebhookCtor(recv)) return true;
    if (recv.type === "identifier") {
      const decl = unwrap(resolveLocal(pf, recv.text, call));
      if (decl && isWebhookCtor(decl)) return true;
      if (importsFrom(pf, /^@octokit\/webhooks(?:-methods)?$/).length > 0) return true;
    }
  }
  return false;
}

/** `new Webhook(secret)` (svix / standardwebhooks, JS) or `Webhook(secret)` (Python). */
function isWebhookCtor(n: SyntaxNode): boolean {
  if (isNew(n) || isCall(n)) return /(?:^|\.)Webhook$/.test(calleePath(n));
  return false;
}

/** The handler (or its middleware / helpers) verifies a webhook signature. */
export function webhookVerified(ctx: ProjectContext, e: InventoryEntry): boolean {
  return reachableCalls(ctx, e).some((s) => isVerifyCall(s.call, s.pf));
}

export const webhookSignature = defineRule({
  id: ID,
  title: "Webhook handler without signature verification",
  pack: "api",
  maturity: "experimental",
  source: SOURCES.owaspApi,
  appliesTo: (ctx) => apiEntries(ctx).some(isWebhookEntry),
  check(ctx, emit) {
    for (const e of apiEntries(ctx).filter(isWebhookEntry)) {
      if (!webhookVerified(ctx, e)) {
        const anchor = entryKey(e);
        const id = findingId(ID, e.file, anchor);
        emit({
          severity: "high",
          service: "api",
          file: e.file,
          line: e.line,
          anchor,
          evidence: `${entryKey(e)}: ${firstLine(e.internal.registration.node.text)}`,
          why: WHY,
          fix: { summary: FIX, testTemplate: testTemplate(ctx, ID, id, entryTarget(e)) },
          entryPointId: e.id,
        });
        continue;
      }
      // Next.js route handler: `await req.json()` before constructEvent (the signature covers the raw body).
      if (e.framework !== "nextjs" || handlerKind(e) !== "route") continue;
      for (const h of e.internal.handlers) {
        const m = requestModel(ctx, e, h);
        const calls = callsIn(h.node);
        const construct = calls.find((c) => /^constructEvent(?:Async)?$/.test(calleeName(c)));
        if (!construct) continue;
        const json = calls.find((c) => c.startIndex < construct.startIndex && m.req.some((r) => calleePath(c) === `${r}.json`));
        if (!json) continue;
        emit({
          severity: "medium",
          service: "api",
          file: h.file,
          line: line(json),
          anchor: `${entryKey(e)} ${anchorText(json)}`,
          evidence: `${anchorText(json)} before ${anchorText(construct)}`,
          why: WHY,
          fix: { summary: FIX_RAW },
          entryPointId: e.id,
        });
      }
    }
  },
});
