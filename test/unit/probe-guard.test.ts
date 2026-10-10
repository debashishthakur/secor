import { describe, expect, it } from "vitest";
import { isDenylisted } from "../../src/probe/denylist.js";
import { ProbeClient } from "../../src/probe/http.js";
import { classifyTarget, reResolvePin, resolveAndClassify } from "../../src/probe/scope-guard.js";
import { ProbeRefusal, type VerifiedTarget } from "../../src/probe/types.js";
import { fakeResolver, v4 } from "../probe/helpers.js";

const refusalCode = async (fn: () => Promise<unknown> | unknown): Promise<string> => {
  try {
    await fn();
    return "<no refusal>";
  } catch (e) {
    return e instanceof ProbeRefusal ? e.code : `<${(e as Error).name}>`;
  }
};

describe("isDenylisted", () => {
  it("refuses platform apexes and service endpoints, not preview subdomains", () => {
    for (const h of ["github.com", "www.github.com", "google.com", "googleapis.com", "s3.amazonaws.com", "cloudflare.com", "vercel.com", "netlify.com", "fly.io", "supabase.co", "stripe.com", "openai.com", "anthropic.com", "storage.googleapis.com"]) {
      expect(isDenylisted(h), h).toBe(true);
    }
    for (const h of ["my-app.vercel.app", "preview-abc.netlify.app", "thing.pages.dev", "app.fly.dev", "abcd.supabase.co", "staging.myapp.com"]) {
      expect(isDenylisted(h), h).toBe(false);
    }
  });
});

describe("classifyTarget", () => {
  it("refuses non-http schemes", async () => {
    expect(await refusalCode(() => classifyTarget("ftp://x/"))).toBe("bad-scheme");
    expect(await refusalCode(() => classifyTarget("file:///etc/passwd"))).toBe("bad-scheme");
  });
  it("refuses metadata hosts in any form", async () => {
    for (const u of ["http://169.254.169.254/", "http://2852039166/", "http://0xa9fea9fe/", "http://metadata.google.internal/", "http://100.100.100.200/", "http://[fd00:ec2::254]/"]) {
      expect(await refusalCode(() => classifyTarget(u)), u).toBe("metadata");
    }
  });
  it("refuses denylisted shared infra", async () => {
    expect(await refusalCode(() => classifyTarget("https://github.com/"))).toBe("denylist");
    expect(await refusalCode(() => classifyTarget("https://s3.amazonaws.com/bucket"))).toBe("denylist");
  });
  it("accepts a literal loopback and a plain host", () => {
    expect(classifyTarget("http://127.0.0.1:3000/").literalClass).toBe("loopback");
    expect(classifyTarget("https://staging.myapp.com/").literalClass).toBeNull();
  });
});

describe("resolveAndClassify", () => {
  it("marks all-private resolutions private and anything public public", async () => {
    expect((await resolveAndClassify("127.0.0.1", fakeResolver({}))).kind).toBe("private");
    expect((await resolveAndClassify("localhost", fakeResolver({ lookup: v4("127.0.0.1") }))).kind).toBe("private");
    expect((await resolveAndClassify("staging.myapp.com", fakeResolver({ lookup: v4("93.184.216.34") }))).kind).toBe("public");
  });
  it("refuses when any resolved address is metadata", async () => {
    expect(await refusalCode(() => resolveAndClassify("evil.test", fakeResolver({ lookup: v4("169.254.169.254") })))).toBe("metadata");
  });
  it("refuses when a host does not resolve", async () => {
    expect(await refusalCode(() => resolveAndClassify("nothing.test", fakeResolver({ lookup: [] })))).toBe("no-resolve");
  });
});

describe("reResolvePin (DNS-rebinding guard)", () => {
  const privateTarget: VerifiedTarget = {
    url: "http://staging.test:3000/",
    origin: "http://staging.test:3000",
    host: "staging.test",
    protocol: "http:",
    port: 3000,
    kind: "private",
    method: "local",
    pinnedIp: "127.0.0.1",
    pinnedFamily: 4,
  };

  it("aborts when a private target now resolves to a public address", async () => {
    const resolver = fakeResolver({ lookup: v4("93.184.216.34") });
    expect(await refusalCode(() => reResolvePin(privateTarget, resolver))).toBe("rebind");
  });
  it("aborts when a target now resolves to metadata", async () => {
    const resolver = fakeResolver({ lookup: v4("169.254.169.254") });
    expect(await refusalCode(() => reResolvePin(privateTarget, resolver))).toBe("metadata");
  });
  it("keeps pinning a still-private address", async () => {
    const resolver = fakeResolver({ lookup: v4("127.0.0.1") });
    expect(await reResolvePin(privateTarget, resolver)).toEqual({ ip: "127.0.0.1", family: 4 });
  });

  it("a ProbeClient request aborts once the host rebinds to a public IP", async () => {
    let calls = 0;
    const resolver = fakeResolver({
      lookup: () => {
        calls++;
        return calls <= 1 ? v4("127.0.0.1") : v4("93.184.216.34");
      },
    });
    // First call establishes nothing (client re-resolves on each request); force the public answer.
    const client = new ProbeClient(privateTarget, resolver, { maxPerSecond: 50 });
    // Drain the first (private) answer so the next request sees the rebinding.
    await reResolvePin(privateTarget, resolver);
    expect(await refusalCode(() => client.request("GET", "/"))).toBe("rebind");
  });
});
