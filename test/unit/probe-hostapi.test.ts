import { describe, expect, it } from "vitest";
import { providerForHost, verifyByHostApi } from "../../src/probe/host-api.js";

type FetchLog = { url: string; auth?: string };

function mockFetch(routes: Record<string, { status: number; body: unknown }>, log: FetchLog[] = []): typeof fetch {
  return ((url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    log.push({ url, auth: headers.authorization });
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    const r = key ? routes[key]! : { status: 404, body: {} };
    return Promise.resolve({
      status: r.status,
      json: () => Promise.resolve(r.body),
    } as Response);
  }) as unknown as typeof fetch;
}

describe("providerForHost", () => {
  it("maps preview domains to their provider", () => {
    expect(providerForHost("my-app.vercel.app")).toBe("vercel");
    expect(providerForHost("x.netlify.app")).toBe("netlify");
    expect(providerForHost("y.pages.dev")).toBe("cloudflare");
    expect(providerForHost("z.fly.dev")).toBe("fly");
    expect(providerForHost("staging.myapp.com")).toBeNull();
  });
});

describe("verifyByHostApi", () => {
  it("fails fast when the token env var is missing", async () => {
    const r = await verifyByHostApi("my-app.vercel.app", {}, mockFetch({}));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/VERCEL_TOKEN/);
  });

  it("Vercel: confirms a deployment belonging to the account", async () => {
    const log: FetchLog[] = [];
    const f = mockFetch({ "https://api.vercel.com/v6/deployments": { status: 200, body: { deployments: [{ url: "other.vercel.app" }, { url: "my-app.vercel.app" }] } } }, log);
    const ok = await verifyByHostApi("my-app.vercel.app", { VERCEL_TOKEN: "secret" }, f);
    expect(ok.ok).toBe(true);
    expect(log[0]!.auth).toBe("Bearer secret");
    const no = await verifyByHostApi("not-mine.vercel.app", { VERCEL_TOKEN: "secret" }, f);
    expect(no.ok).toBe(false);
  });

  it("Netlify: matches default_domain / ssl_url", async () => {
    const f = mockFetch({ "https://api.netlify.com/api/v1/sites": { status: 200, body: [{ ssl_url: "https://my-site.netlify.app" }] } });
    expect((await verifyByHostApi("my-site.netlify.app", { NETLIFY_AUTH_TOKEN: "t" }, f)).ok).toBe(true);
    expect((await verifyByHostApi("someone-else.netlify.app", { NETLIFY_AUTH_TOKEN: "t" }, f)).ok).toBe(false);
  });

  it("Cloudflare Pages: matches a project subdomain", async () => {
    const f = mockFetch({ "https://api.cloudflare.com/client/v4/accounts/acct/pages/projects": { status: 200, body: { result: [{ subdomain: "proj.pages.dev", domains: ["www.example.com"] }] } } });
    expect((await verifyByHostApi("proj.pages.dev", { CLOUDFLARE_API_TOKEN: "t", CLOUDFLARE_ACCOUNT_ID: "acct" }, f)).ok).toBe(true);
    expect((await verifyByHostApi("evil.pages.dev", { CLOUDFLARE_API_TOKEN: "t", CLOUDFLARE_ACCOUNT_ID: "acct" }, f)).ok).toBe(false);
  });

  it("Fly: confirms the app exists in the account", async () => {
    const f = mockFetch({ "https://api.machines.dev/v1/apps/my-app": { status: 200, body: { name: "my-app" } } });
    expect((await verifyByHostApi("my-app.fly.dev", { FLY_API_TOKEN: "t" }, f)).ok).toBe(true);
    const f404 = mockFetch({});
    expect((await verifyByHostApi("ghost.fly.dev", { FLY_API_TOKEN: "t" }, f404)).ok).toBe(false);
  });
});
