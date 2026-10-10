// Host-API ownership verification (spec 9A.2, route 3). For a Vercel / Netlify / Cloudflare Pages / Fly
// target, the developer supplies their own READ-ONLY API token via an env var; Probe confirms the target
// deployment belongs to that account.
//
// UNVERIFIED (see scratchpad/decisions-probe.md): the exact provider endpoints below drift over time.
// They are read-only GETs and are unit-tested with a mocked fetch. Confirm against current docs before release.

import { stripBrackets } from "./addresses.js";

export type HostProvider = "vercel" | "netlify" | "cloudflare" | "fly";

export interface HostApiResult {
  ok: boolean;
  provider: HostProvider | null;
  /** Human-readable reason when not ok (never contains the token). */
  reason?: string;
}

/** Env var names holding the developer's own read-only token(s). */
export const HOST_API_ENV: Record<HostProvider, string[]> = {
  vercel: ["VERCEL_TOKEN"],
  netlify: ["NETLIFY_AUTH_TOKEN"],
  cloudflare: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
  fly: ["FLY_API_TOKEN"],
};

function hostMatches(candidate: string | undefined | null, target: string): boolean {
  if (!candidate) return false;
  let h = candidate.trim().toLowerCase();
  if (h.includes("://")) {
    try {
      h = new URL(h).hostname;
    } catch {
      return false;
    }
  }
  h = stripBrackets(h).replace(/\.$/, "");
  return h === target;
}

/** Pick the provider implied by the target host, or null if none of the four. */
export function providerForHost(host: string): HostProvider | null {
  const h = stripBrackets(host).toLowerCase();
  if (h.endsWith(".vercel.app")) return "vercel";
  if (h.endsWith(".netlify.app")) return "netlify";
  if (h.endsWith(".pages.dev")) return "cloudflare";
  if (h.endsWith(".fly.dev")) return "fly";
  return null;
}

async function getJson(fetchImpl: typeof fetch, url: string, headers: Record<string, string>): Promise<{ status: number; json: unknown }> {
  const res = await fetchImpl(url, { method: "GET", headers: { accept: "application/json", ...headers }, redirect: "error" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

/**
 * Confirm `host` belongs to the account named by the env token(s). `provider` may be forced (CLI
 * --verify-method host-api on a custom domain); otherwise it is inferred from the host.
 */
export async function verifyByHostApi(host: string, env: NodeJS.ProcessEnv, fetchImpl: typeof fetch, provider?: HostProvider): Promise<HostApiResult> {
  const target = stripBrackets(host).toLowerCase().replace(/\.$/, "");
  const prov = provider ?? providerForHost(host);
  if (!prov) return { ok: false, provider: null, reason: `no host-API provider matches ${host}; pass a Vercel/Netlify/Cloudflare Pages/Fly host or use token/dns` };
  const missing = HOST_API_ENV[prov].filter((name) => !env[name]);
  if (missing.length) return { ok: false, provider: prov, reason: `set ${missing.join(" and ")} to a read-only ${prov} token` };
  try {
    if (prov === "vercel") {
      const team = env.VERCEL_TEAM_ID ? `?teamId=${encodeURIComponent(env.VERCEL_TEAM_ID)}&limit=100` : "?limit=100";
      const { status, json } = await getJson(fetchImpl, `https://api.vercel.com/v6/deployments${team}`, { authorization: `Bearer ${env.VERCEL_TOKEN}` });
      if (status !== 200) return { ok: false, provider: prov, reason: `Vercel API returned ${status}` };
      const deployments = (json as { deployments?: { url?: string; alias?: string[] }[] }).deployments ?? [];
      const found = deployments.some((d) => hostMatches(d.url, target) || (d.alias ?? []).some((a) => hostMatches(a, target)));
      return found ? { ok: true, provider: prov } : { ok: false, provider: prov, reason: `no Vercel deployment for ${host} in this account` };
    }
    if (prov === "netlify") {
      const { status, json } = await getJson(fetchImpl, `https://api.netlify.com/api/v1/sites?per_page=100`, { authorization: `Bearer ${env.NETLIFY_AUTH_TOKEN}` });
      if (status !== 200) return { ok: false, provider: prov, reason: `Netlify API returned ${status}` };
      const sites = (json as { default_domain?: string; ssl_url?: string; url?: string; custom_domain?: string; name?: string }[]) ?? [];
      const found = sites.some((s) => hostMatches(s.default_domain, target) || hostMatches(s.ssl_url, target) || hostMatches(s.url, target) || hostMatches(s.custom_domain, target) || hostMatches(s.name ? `${s.name}.netlify.app` : null, target));
      return found ? { ok: true, provider: prov } : { ok: false, provider: prov, reason: `no Netlify site for ${host} in this account` };
    }
    if (prov === "cloudflare") {
      const acct = env.CLOUDFLARE_ACCOUNT_ID!;
      const { status, json } = await getJson(fetchImpl, `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(acct)}/pages/projects`, {
        authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      });
      if (status !== 200) return { ok: false, provider: prov, reason: `Cloudflare API returned ${status}` };
      const result = (json as { result?: { subdomain?: string; domains?: string[] }[] }).result ?? [];
      const found = result.some((p) => hostMatches(p.subdomain, target) || (p.domains ?? []).some((d) => hostMatches(d, target)));
      return found ? { ok: true, provider: prov } : { ok: false, provider: prov, reason: `no Cloudflare Pages project for ${host} in this account` };
    }
    // fly
    const app = target.endsWith(".fly.dev") ? target.slice(0, -".fly.dev".length) : target;
    const { status } = await getJson(fetchImpl, `https://api.machines.dev/v1/apps/${encodeURIComponent(app)}`, { authorization: `Bearer ${env.FLY_API_TOKEN}` });
    if (status === 200) return { ok: true, provider: prov };
    return { ok: false, provider: prov, reason: `Fly app "${app}" not found in this account (status ${status})` };
  } catch (e) {
    return { ok: false, provider: prov, reason: `host-API check failed: ${(e as Error).message}` };
  }
}
