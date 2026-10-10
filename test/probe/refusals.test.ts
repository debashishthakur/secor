// Required abuse / refusal tests (spec 9A.8, M6b): these MUST pass before any check is wired in.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ProbeClient } from "../../src/probe/http.js";
import { reResolvePin } from "../../src/probe/scope-guard.js";
import { ProbeRefusal, type VerifiedTarget } from "../../src/probe/types.js";
import { verifyTarget, verifyTokenFile } from "../../src/probe/verify.js";
import { fakeResolver, tempHome, v4, type TempHome } from "./helpers.js";

const code = async (fn: () => Promise<unknown>): Promise<string> => {
  try {
    await fn();
    return "<no refusal>";
  } catch (e) {
    return e instanceof ProbeRefusal ? e.code : `<${(e as Error).name}: ${(e as Error).message}>`;
  }
};

describe("Probe refusals (9A.8)", () => {
  let h: TempHome;
  beforeEach(() => {
    h = tempHome();
  });
  afterEach(() => h.restore());

  it("refuses a public URL with no verification", async () => {
    const resolver = fakeResolver({ lookup: v4("93.184.216.34") });
    expect(await code(() => verifyTarget("https://staging.example.com/", { resolver }))).toBe("needs-verification");
  });

  it("aborts a target that verifies then re-resolves to a public IP", async () => {
    let n = 0;
    const resolver = fakeResolver({
      lookup: () => {
        n++;
        return n === 1 ? v4("127.0.0.1") : v4("93.184.216.34");
      },
    });
    // First resolution: private -> verifies as a local target.
    const target = await verifyTarget("http://staging.localtest:3000/", { resolver });
    expect(target.kind).toBe("private");
    // Any later connection re-resolves and must abort on the now-public address.
    const client = new ProbeClient(target, resolver, { maxPerSecond: 50 });
    expect(await code(() => client.request("GET", "/"))).toBe("rebind");
  });

  it("refuses cloud metadata addresses in every form", async () => {
    const resolver = fakeResolver({ lookup: v4("127.0.0.1") });
    for (const u of [
      "http://169.254.169.254/",
      "http://2852039166/",
      "http://0xa9fea9fe/",
      "http://[::ffff:169.254.169.254]/",
      "http://[fd00:ec2::254]/",
      "http://100.100.100.200/",
      "http://metadata.google.internal/",
      "http://169.254.170.2/v2/credentials/x",
      "http://169.254.170.23/",
      "http://[fd00:ec2::23]/",
    ]) {
      expect(await code(() => verifyTarget(u, { resolver })), u).toBe("metadata");
    }
  });

  it("a verified public target keeps connecting to its pinned IP when DNS changes mid-run", async () => {
    let n = 0;
    const resolver = fakeResolver({
      lookup: () => {
        n++;
        return n === 1 ? v4("93.184.216.34") : v4("10.0.0.5");
      },
    });
    const target: VerifiedTarget = {
      url: "https://staging.example.com/",
      origin: "https://staging.example.com",
      host: "staging.example.com",
      protocol: "https:",
      port: 443,
      kind: "public",
      pinnedIp: "93.184.216.34",
      pinnedFamily: 4,
      method: "token",
    } as VerifiedTarget;
    expect(await reResolvePin(target, resolver)).toEqual({ ip: "93.184.216.34", family: 4 });
    expect(await reResolvePin(target, resolver)).toEqual({ ip: "93.184.216.34", family: 4 });
  });

  it("a verified public target aborts when its host starts resolving to a metadata address", async () => {
    const resolver = fakeResolver({ lookup: v4("169.254.169.254") });
    const target = { host: "staging.example.com", kind: "public", pinnedIp: "93.184.216.34", pinnedFamily: 4 } as VerifiedTarget;
    expect(await code(() => reResolvePin(target, resolver))).toBe("metadata");
  });

  it("aborts if a host resolves to a metadata address", async () => {
    const resolver = fakeResolver({ lookup: v4("169.254.169.254") });
    expect(await code(() => verifyTarget("http://sneaky.localtest/", { resolver }))).toBe("metadata");
  });

  it("refuses denylisted shared-infrastructure hosts", async () => {
    const resolver = fakeResolver({ lookup: v4("140.82.112.3") });
    for (const u of ["https://github.com/", "https://api.github.com.googleapis.com/", "https://s3.amazonaws.com/b", "https://supabase.co/"]) {
      expect(["denylist"]).toContain(await code(() => verifyTarget(u, { resolver })));
    }
  });

  it("refuses a non-TTY run with no human confirmation (no unattended mode)", async () => {
    // obtainConsent is the gate; a non-TTY stdin cannot provide the required confirmation.
    const { obtainConsent } = await import("../../src/probe/consent.js");
    const io = { isTTY: false, print: () => {} };
    expect(await code(() => obtainConsent(io, { host: "localhost", iOwnThisTarget: true, plan: ["GET /"] }))).toBe("no-confirmation-unattended");
  });

  it("refuses token verification when the served body is wrong, accepts the exact nonce", async () => {
    const params = { protocol: "https:" as const, host: "staging.example.com", pinnedIp: "93.184.216.34", family: 4 as const, port: 443 };
    const wrong = await verifyTokenFile(params, "the-nonce", () => Promise.resolve({ status: 200, body: "not-the-nonce" }));
    expect(wrong).toBe(false);
    const empty = await verifyTokenFile(params, "the-nonce", () => Promise.resolve({ status: 404, body: "the-nonce" }));
    expect(empty).toBe(false);
    const right = await verifyTokenFile(params, "the-nonce", () => Promise.resolve({ status: 200, body: "the-nonce\n" }));
    expect(right).toBe(true);
  });

  it("the full public-token path caches and does not re-prove within 24h", async () => {
    // Prove once through verifyTarget (interactive io + injected token file), then confirm the cache hit.
    const resolver = fakeResolver({ lookup: v4("93.184.216.34") });
    const io = { isTTY: true, print: () => {}, question: () => Promise.resolve("") };
    // Seed the auth cache directly via a private verification shortcut is not possible for public;
    // instead verify with host-api mocked to succeed.
    const okFetch = ((url: string) => Promise.resolve({ status: 200, json: () => Promise.resolve({ deployments: [{ url: "app.vercel.app" }] }) } as Response)) as unknown as typeof fetch;
    const t1 = await verifyTarget("https://app.vercel.app/", { resolver, method: "host-api", env: { VERCEL_TOKEN: "x" }, fetchImpl: okFetch, io });
    expect(t1.method).toBe("host-api");
    // Second run with no method relies on the cached proof.
    const t2 = await verifyTarget("https://app.vercel.app/", { resolver, io });
    expect(t2.kind).toBe("public");
    expect(t2.method).toBe("host-api");
  });
});
