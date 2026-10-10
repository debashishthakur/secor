// Probe's HTTP client (spec 9A, invariant 13). It connects to a pinned, re-resolved IP with node:http /
// node:https directly (Host header + TLS SNI set to the real host) so fetch can never re-resolve onto a
// different address mid-run. Only GET and OPTIONS are ever sent. Response bodies are read up to a small
// cap, never written to disk, and discarded when the run ends. Global concurrency <= 4, <= 5 req/s,
// backoff on 429/503.

import * as http from "node:http";
import * as https from "node:https";
import { reResolvePin, type Resolver } from "./scope-guard.js";
import { ProbeRefusal, type VerifiedTarget } from "./types.js";

export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_BODY_CAP = 256 * 1024;
export const MAX_CONCURRENCY = 4;
export const MAX_PER_SECOND = 5;
export const RETRY_AFTER_CAP_MS = 30_000;
const MAX_RETRIES = 2;

export type ProbeMethod = "GET" | "OPTIONS";

export interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  setCookie: string[];
  /** Raw response text, capped. Redact before it reaches any output. */
  body: string;
  /** True when the body hit the cap and was truncated. */
  truncated: boolean;
  location: string | null;
}

export interface RawRequestOpts {
  method: ProbeMethod;
  protocol: "http:" | "https:";
  host: string;
  pinnedIp: string;
  family: 4 | 6;
  port: number;
  path: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  bodyCapBytes?: number;
}

function hostHeader(host: string, protocol: string, port: number): string {
  const def = protocol === "https:" ? 443 : 80;
  return port === def ? host : `${host}:${port}`;
}

/** One pinned request. Never follows redirects; returns the Location header verbatim instead. */
export function rawRequest(opts: RawRequestOpts): Promise<RawResponse> {
  if (opts.method !== "GET" && opts.method !== "OPTIONS") {
    return Promise.reject(new ProbeRefusal("bad-method", `Probe only sends GET and OPTIONS, not ${opts.method as string}`));
  }
  const mod = opts.protocol === "https:" ? https : http;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const cap = opts.bodyCapBytes ?? DEFAULT_BODY_CAP;
  const reqOpts: https.RequestOptions = {
    host: opts.pinnedIp,
    port: opts.port,
    path: opts.path,
    method: opts.method,
    family: opts.family,
    setHost: false,
    headers: { host: hostHeader(opts.host, opts.protocol, opts.port), "user-agent": "secor-probe", accept: "*/*", ...opts.headers },
    ...(opts.protocol === "https:" ? { servername: opts.host } : {}),
  };
  return new Promise<RawResponse>((resolve, reject) => {
    const req = mod.request(reqOpts, (res) => {
      const chunks: Buffer[] = [];
      let length = 0;
      let truncated = false;
      res.on("data", (c: Buffer) => {
        if (length >= cap) return;
        if (length + c.length > cap) {
          chunks.push(c.subarray(0, cap - length));
          length = cap;
          truncated = true;
          res.destroy();
        } else {
          chunks.push(c);
          length += c.length;
        }
      });
      const done = () => {
        const setCookie = res.headers["set-cookie"] ?? [];
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          setCookie: Array.isArray(setCookie) ? setCookie : [setCookie],
          body: Buffer.concat(chunks).toString("utf8"),
          truncated,
          location: typeof res.headers.location === "string" ? res.headers.location : null,
        });
      };
      res.on("end", done);
      res.on("close", done);
      res.on("error", reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`request to ${opts.host} timed out after ${timeoutMs}ms`)));
    req.on("error", (e) => reject(e));
    req.end();
  });
}

function parseRetryAfter(value: string | string[] | undefined, now: number): number | null {
  if (!value) return null;
  const v = Array.isArray(value) ? value[0]! : value;
  if (/^\d+$/.test(v.trim())) return parseInt(v.trim(), 10) * 1000;
  const date = Date.parse(v);
  return Number.isNaN(date) ? null : Math.max(date - now, 0);
}

interface ClientOpts {
  maxConcurrency?: number;
  maxPerSecond?: number;
  timeoutMs?: number;
  bodyCapBytes?: number;
  retryAfterCapMs?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

class Semaphore {
  private slots: number;
  private readonly waiters: (() => void)[] = [];
  constructor(max: number) {
    this.slots = max;
  }
  async acquire(): Promise<void> {
    if (this.slots > 0) {
      this.slots--;
      return;
    }
    await new Promise<void>((r) => this.waiters.push(r));
  }
  release(): void {
    const w = this.waiters.shift();
    if (w) w();
    else this.slots++;
  }
}

/**
 * A scheduled client bound to one verified target. Re-resolves + re-pins before every connection
 * (DNS-rebinding guard) and enforces the global traffic caps. `requests` records method+url only
 * (never bodies) for tests and the printed plan.
 */
export class ProbeClient {
  readonly requests: { method: string; url: string }[] = [];
  private readonly sem: Semaphore;
  private readonly maxPerSecond: number;
  private readonly timeoutMs: number;
  private readonly bodyCapBytes: number;
  private readonly retryAfterCapMs: number;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private starts: number[] = [];
  private rateLock: Promise<void> = Promise.resolve();

  constructor(
    private readonly target: VerifiedTarget,
    private readonly resolver: Resolver,
    opts: ClientOpts = {},
  ) {
    this.sem = new Semaphore(opts.maxConcurrency ?? MAX_CONCURRENCY);
    this.maxPerSecond = opts.maxPerSecond ?? MAX_PER_SECOND;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.bodyCapBytes = opts.bodyCapBytes ?? DEFAULT_BODY_CAP;
    this.retryAfterCapMs = opts.retryAfterCapMs ?? RETRY_AFTER_CAP_MS;
    this.now = opts.now ?? Date.now;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  private async rateGate(): Promise<void> {
    const prev = this.rateLock;
    let release!: () => void;
    this.rateLock = new Promise<void>((r) => (release = r));
    await prev;
    try {
      for (;;) {
        const now = this.now();
        this.starts = this.starts.filter((t) => now - t < 1000);
        if (this.starts.length < this.maxPerSecond) {
          this.starts.push(now);
          return;
        }
        await this.sleep(1000 - (now - this.starts[0]!) + 1);
      }
    } finally {
      release();
    }
  }

  /** Send a request to `path` (relative to the target origin). Enforces caps, re-pin and backoff. */
  async request(method: ProbeMethod, path: string, opts: { headers?: Record<string, string> } = {}): Promise<RawResponse> {
    await this.sem.acquire();
    try {
      await this.rateGate();
      const url = `${this.target.origin}${path.startsWith("/") ? path : `/${path}`}`;
      this.requests.push({ method, url });
      let attempt = 0;
      for (;;) {
        const pin = await reResolvePin(this.target, this.resolver);
        const res = await rawRequest({
          method,
          protocol: this.target.protocol,
          host: this.target.host,
          pinnedIp: pin.ip,
          family: pin.family,
          port: this.target.port,
          path: path.startsWith("/") ? path : `/${path}`,
          ...(opts.headers ? { headers: opts.headers } : {}),
          timeoutMs: this.timeoutMs,
          bodyCapBytes: this.bodyCapBytes,
        });
        if ((res.status === 429 || res.status === 503) && attempt < MAX_RETRIES) {
          const wait = parseRetryAfter(res.headers["retry-after"], this.now());
          await this.sleep(Math.min(wait ?? 1000 * (attempt + 1), this.retryAfterCapMs));
          attempt++;
          continue;
        }
        return res;
      }
    } finally {
      this.sem.release();
    }
  }
}
