// Staging heuristic (spec 9A.3). Probe warns and requires extra confirmation when the host does not
// look like a staging / preview / local deployment.

import { classifyIp, isPrivateClass, parseIp, stripBrackets } from "./addresses.js";

const STAGING_WORDS = /(^|[.-])(staging|preview|dev|development|test|qa|sandbox|localhost)([.-]|$)/i;

/** Known preview / ephemeral hosting domains that count as non-production by convention. */
const PREVIEW_SUFFIXES = [".vercel.app", ".netlify.app", ".pages.dev", ".fly.dev", ".onrender.com", ".railway.app", ".web.app", ".firebaseapp.com", ".ngrok.io", ".ngrok-free.app"];

export function looksLikeStaging(host: string): boolean {
  const h = stripBrackets(host).toLowerCase();
  // A loopback / link-local / private IP literal is inherently local, not production.
  const ip = parseIp(h);
  if (ip && isPrivateClass(classifyIp(ip))) return true;
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (STAGING_WORDS.test(h)) return true;
  if (PREVIEW_SUFFIXES.some((s) => h.endsWith(s))) return true;
  return false;
}
