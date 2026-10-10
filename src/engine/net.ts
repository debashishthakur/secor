// Network access for Ship (spec section 13). Only the allowlisted hosts below may be contacted;
// responses are cached in ~/.secor/cache/ for 24 hours, which makes runs deterministic within that window.

import { join } from "node:path";
import { readJsonFile, writeFileAtomic } from "./util/fsx.js";
import { sha256Hex } from "./util/hash.js";
import { secorHome } from "./util/paths.js";

export const SHIP_ALLOWED_HOSTS = new Set(["api.osv.dev", "registry.npmjs.org", "api.npmjs.org", "pypi.org"]);
const TTL_MS = 24 * 60 * 60 * 1000;
const TIMEOUT_MS = 15_000;

export class NetworkPolicyError extends Error {}

export interface NetResponse {
  status: number;
  body: unknown;
}

interface CacheEntry extends NetResponse {
  at: number;
}

export interface NetClient {
  getJson(url: string): Promise<NetResponse>;
  postJson(url: string, body: unknown): Promise<NetResponse>;
}

function cachePath(key: string): string {
  return join(secorHome(), "cache", `${key}.json`);
}

function assertAllowed(url: string): void {
  const u = new URL(url);
  if (u.protocol !== "https:" || !SHIP_ALLOWED_HOSTS.has(u.hostname)) {
    throw new NetworkPolicyError(`SECOR network policy: ${u.hostname} is not an allowed destination`);
  }
}

export function createNetClient(opts: { now?: () => number; fetchImpl?: typeof fetch } = {}): NetClient {
  const now = opts.now ?? Date.now;
  const doFetch = opts.fetchImpl ?? fetch;
  const request = async (method: "GET" | "POST", url: string, body?: unknown): Promise<NetResponse> => {
    assertAllowed(url);
    const payload = body === undefined ? "" : JSON.stringify(body);
    const key = sha256Hex(`${method} ${url}\n${payload}`);
    const path = cachePath(key);
    try {
      const cached = readJsonFile<CacheEntry>(path);
      if (cached && now() - cached.at < TTL_MS) return { status: cached.status, body: cached.body };
    } catch {
      // unreadable cache entry: refetch
    }
    let lastErr: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await doFetch(url, {
          method,
          headers: { accept: "application/json", ...(body === undefined ? {} : { "content-type": "application/json" }), "user-agent": "secor" },
          body: body === undefined ? undefined : payload,
          redirect: "error",
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        let json: unknown = null;
        const text = await res.text();
        try {
          json = text ? JSON.parse(text) : null;
        } catch {
          json = null;
        }
        const entry: CacheEntry = { at: now(), status: res.status, body: json };
        if (res.status < 500) {
          try {
            writeFileAtomic(path, JSON.stringify(entry));
          } catch {
            // cache is best-effort
          }
        }
        return { status: res.status, body: json };
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  };
  return {
    getJson: (url) => request("GET", url),
    postJson: (url, body) => request("POST", url, body),
  };
}

/** Run `fn` over items with at most `limit` in flight, preserving input order in the result. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]!, i);
    }
  });
  await Promise.all(workers);
  return out;
}
