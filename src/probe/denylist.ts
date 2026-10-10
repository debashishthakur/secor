// Built-in denylist of shared infrastructure (spec 9A.2). Hosts here are refused regardless of any
// verification. It targets provider apexes and shared control planes / service endpoints, NOT the
// developer preview deployments (e.g. *.vercel.app) that host-API verification is meant to allow.

import { stripBrackets } from "./addresses.js";

/** Apex domains of major shared platforms. The apex and its "www." are refused. */
export const DENY_APEX: readonly string[] = [
  "github.com",
  "google.com",
  "googleapis.com",
  "amazonaws.com",
  "cloudflare.com",
  "vercel.com",
  "netlify.com",
  "fly.io",
  "supabase.co",
  "stripe.com",
  "openai.com",
  "anthropic.com",
];

/** Suffixes for shared service endpoints (AWS / Google APIs). Any subdomain is refused. */
export const DENY_SUFFIX: readonly string[] = [".amazonaws.com", ".googleapis.com"];

export function isDenylisted(host: string): boolean {
  const h = stripBrackets(host).toLowerCase().replace(/\.$/, "");
  for (const apex of DENY_APEX) {
    if (h === apex || h === `www.${apex}`) return true;
  }
  for (const suffix of DENY_SUFFIX) {
    if (h.endsWith(suffix)) return true;
  }
  return false;
}
