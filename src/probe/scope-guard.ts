// The scope guard (spec 9A.2): classify a target, resolve + pin its IP, and enforce the DNS-rebinding
// guard before every connection. No flag, config or env disables any of this.

import { promises as dnsPromises } from "node:dns";
import { classifyIp, isMetadataHost, isPrivateClass, type IpClass, parseIp } from "./addresses.js";
import { isDenylisted } from "./denylist.js";
import { ProbeRefusal, type VerifiedTarget } from "./types.js";

/** Pluggable name resolution, so tests can simulate rebinding / metadata without real DNS. */
export interface Resolver {
  lookup(host: string): Promise<{ address: string; family: number }[]>;
  resolveTxt(host: string): Promise<string[][]>;
}

export const nodeResolver: Resolver = {
  lookup: (host) => dnsPromises.lookup(host, { all: true }),
  resolveTxt: (host) => dnsPromises.resolveTxt(host),
};

export interface ParsedTarget {
  url: URL;
  host: string;
  /** The IP class of a literal-IP host, or null for a DNS name (resolved later). */
  literalClass: IpClass | null;
}

/** Parse + statically guard a target URL. Refuses bad schemes, metadata hosts and denylisted hosts. */
export function classifyTarget(rawUrl: string): ParsedTarget {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ProbeRefusal("bad-url", `not a valid URL: ${rawUrl}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ProbeRefusal("bad-scheme", `Probe only supports http(s) targets, not ${url.protocol}`);
  }
  const host = url.hostname;
  if (isMetadataHost(host)) throw new ProbeRefusal("metadata", `${host} is a cloud metadata address and is always refused`);
  if (isDenylisted(host)) throw new ProbeRefusal("denylist", `${host} is on the shared-infrastructure denylist and is always refused`);
  const ip = parseIp(host);
  const literalClass = ip ? classifyIp(ip) : null;
  if (literalClass === "metadata") throw new ProbeRefusal("metadata", `${host} is a cloud metadata address and is always refused`);
  return { url, host, literalClass };
}

interface ResolvedAddr {
  ip: string;
  family: 4 | 6;
  cls: IpClass;
}

async function resolveAddresses(host: string, resolver: Resolver): Promise<ResolvedAddr[]> {
  const literal = parseIp(host);
  if (literal) return [{ ip: literal.canonical, family: literal.family, cls: classifyIp(literal) }];
  const addrs = await resolver.lookup(host);
  return addrs.map((a) => {
    const ip = parseIp(a.address);
    const family: 4 | 6 = ip ? ip.family : a.family === 6 ? 6 : 4;
    const canonical = ip ? ip.canonical : a.address;
    return { ip: canonical, family, cls: ip ? classifyIp(ip) : "public" };
  });
}

export interface ResolvedPin {
  kind: "private" | "public";
  ip: string;
  family: 4 | 6;
}

/**
 * Resolve the host and decide whether it is a private target (all addresses private) or a public one,
 * and pick the IP to pin. Refuses if any address is a metadata address.
 */
export async function resolveAndClassify(host: string, resolver: Resolver): Promise<ResolvedPin> {
  const addrs = await resolveAddresses(host, resolver);
  if (addrs.length === 0) throw new ProbeRefusal("no-resolve", `${host} does not resolve to any address`);
  const meta = addrs.find((a) => a.cls === "metadata");
  if (meta) throw new ProbeRefusal("metadata", `${host} resolves to the cloud metadata address ${meta.ip} and is always refused`);
  const allPrivate = addrs.every((a) => isPrivateClass(a.cls));
  const kind = allPrivate ? "private" : "public";
  const chosen = allPrivate ? addrs[0]! : (addrs.find((a) => a.cls === "public") ?? addrs[0]!);
  return { kind, ip: chosen.ip, family: chosen.family };
}

/**
 * Re-resolve immediately before a connection and return the IP to connect to. Aborts the run if the host
 * now resolves to a metadata address (any target) or to a public address (a private target: DNS rebinding).
 * A public target always connects to its pinned, verified IP.
 */
export async function reResolvePin(target: VerifiedTarget, resolver: Resolver): Promise<{ ip: string; family: 4 | 6 }> {
  const addrs = await resolveAddresses(target.host, resolver);
  if (addrs.length === 0) throw new ProbeRefusal("no-resolve", `${target.host} no longer resolves; aborting`);
  const meta = addrs.find((a) => a.cls === "metadata");
  if (meta) throw new ProbeRefusal("metadata", `${target.host} now resolves to a cloud metadata address (${meta.ip}); aborting`);
  if (target.kind === "private") {
    const pub = addrs.find((a) => !isPrivateClass(a.cls));
    if (pub) throw new ProbeRefusal("rebind", `${target.host} now resolves to the public address ${pub.ip}; aborting (DNS-rebinding guard)`);
    return { ip: addrs[0]!.ip, family: addrs[0]!.family };
  }
  // A public target's ownership was proven through the pinned IP (the token file is fetched from it), so every
  // request goes to that IP. Never fall back to whatever DNS returns now: that could be an unproven or internal address.
  return { ip: target.pinnedIp, family: target.pinnedFamily };
}
