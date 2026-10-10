// Ownership verification (spec 9A.2): turn a raw target URL into a VerifiedTarget, or refuse. A private
// target is proven by DNS (all addresses private). A public target needs one of: token file, DNS TXT, or
// host API. Passing verifications are cached for 24h (auth-cache).

import { randomBytes } from "node:crypto";
import { cacheAuth, getAnyCachedAuth, getCachedAuth } from "./auth-cache.js";
import type { ConsentIO } from "./consent.js";
import { verifyByHostApi, type HostProvider, providerForHost } from "./host-api.js";
import { rawRequest } from "./http.js";
import { classifyTarget, resolveAndClassify, type Resolver } from "./scope-guard.js";
import { ProbeRefusal, type VerifiedTarget, type VerifyMethod } from "./types.js";

export interface VerifyOptions {
  method?: Exclude<VerifyMethod, "local">;
  resolver: Resolver;
  fetchImpl?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  io?: ConsentIO;
  now?: () => number;
  useCache?: boolean;
  /** Fixed nonce (tests); otherwise random. */
  nonce?: string;
  hostProvider?: HostProvider;
}

function portOf(url: URL): number {
  if (url.port) return parseInt(url.port, 10);
  return url.protocol === "https:" ? 443 : 80;
}

/** Fetch https://<host>/.well-known/secor-verification/<nonce> and require the body to equal the nonce. */
export async function verifyTokenFile(
  params: { protocol: "http:" | "https:"; host: string; pinnedIp: string; family: 4 | 6; port: number },
  nonce: string,
  request: (path: string) => Promise<{ status: number; body: string }> = (path) =>
    rawRequest({ method: "GET", protocol: params.protocol, host: params.host, pinnedIp: params.pinnedIp, family: params.family, port: params.port, path }),
): Promise<boolean> {
  const res = await request(`/.well-known/secor-verification/${nonce}`);
  return res.status >= 200 && res.status < 300 && res.body.trim() === nonce;
}

/** Look for a TXT record `secor-verification=<nonce>` at _secor.<host>. */
export async function verifyDnsTxt(host: string, nonce: string, resolver: Resolver): Promise<boolean> {
  let records: string[][];
  try {
    records = await resolver.resolveTxt(`_secor.${host}`);
  } catch {
    return false;
  }
  const wanted = `secor-verification=${nonce}`;
  return records.some((parts) => parts.join("").trim() === wanted);
}

export async function verifyTarget(rawUrl: string, opts: VerifyOptions): Promise<VerifiedTarget> {
  const now = opts.now ?? Date.now;
  const env = opts.env ?? process.env;
  const useCache = opts.useCache ?? true;
  const parsed = classifyTarget(rawUrl);
  const { url, host } = parsed;
  const origin = url.origin;
  const protocol = url.protocol as "http:" | "https:";
  const port = portOf(url);

  const pin = await resolveAndClassify(host, opts.resolver);
  const base: Omit<VerifiedTarget, "method"> = { url: rawUrl, origin, host, protocol, port, kind: pin.kind, pinnedIp: pin.ip, pinnedFamily: pin.family };

  if (pin.kind === "private") {
    if (useCache) cacheAuth(origin, "local", now());
    return { ...base, method: "local" };
  }

  // Public target: a proof is required.
  const canAsk = !!opts.io?.isTTY && typeof opts.io?.question === "function";

  // Use a cached proof when available.
  if (useCache) {
    const cached = opts.method ? getCachedAuth(origin, opts.method, now()) : getAnyCachedAuth(origin, now());
    if (cached) return { ...base, method: cached.method };
  }

  const method = opts.method;
  if (!method) {
    throw new ProbeRefusal("needs-verification", `${host} is a public host; prove you own it with --verify-method token|dns|host-api`);
  }

  if (method === "host-api") {
    const result = await verifyByHostApi(host, env, opts.fetchImpl ?? fetch, opts.hostProvider ?? providerForHost(host) ?? undefined);
    if (!result.ok) throw new ProbeRefusal("host-api-failed", result.reason ?? "host-API verification failed");
    if (useCache) cacheAuth(origin, "host-api", now());
    return { ...base, method: "host-api" };
  }

  // token / dns both need a nonce the developer serves; without a terminal we cannot guide them.
  const nonce = opts.nonce ?? randomBytes(16).toString("hex");
  if (!canAsk) throw new ProbeRefusal("needs-verification", `cannot run ${method} verification for ${host} without a terminal; run verify-target interactively`);

  if (method === "token") {
    opts.io!.print(`Serve this exact text at https://${host}/.well-known/secor-verification/${nonce}`);
    opts.io!.print(`  body: ${nonce}`);
    await opts.io!.question!("Press enter once it is served... ");
    const ok = await verifyTokenFile({ protocol: "https:", host, pinnedIp: pin.ip, family: pin.family, port }, nonce);
    if (!ok) throw new ProbeRefusal("token-mismatch", `the token file at https://${host}/.well-known/secor-verification/${nonce} did not return the nonce`);
    if (useCache) cacheAuth(origin, "token", now());
    return { ...base, method: "token" };
  }

  // dns
  opts.io!.print(`Add this DNS TXT record and wait for it to propagate:`);
  opts.io!.print(`  _secor.${host}  TXT  secor-verification=${nonce}`);
  await opts.io!.question!("Press enter once it is live... ");
  const ok = await verifyDnsTxt(host, nonce, opts.resolver);
  if (!ok) throw new ProbeRefusal("dns-mismatch", `no TXT record secor-verification=${nonce} at _secor.${host}`);
  if (useCache) cacheAuth(origin, "dns", now());
  return { ...base, method: "dns" };
}
