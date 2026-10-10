// IP address parsing and classification for the Probe scope guard (spec 9A.2).
//
// Security-critical: this decides whether a target counts as loopback/private (allowed) or public
// (needs ownership proof), and it always refuses cloud-metadata addresses. We canonicalise every host
// ourselves - inet_aton-style numeric IPv4 (decimal / hex / octal / short forms), bracket-stripped IPv6,
// and IPv4-mapped IPv6 - so a metadata address in any form is caught regardless of how it reached us.

export type IpClass = "loopback" | "linklocal" | "private" | "metadata" | "public";

/** Cloud metadata IPs that are ALWAYS refused (checked before the private/link-local allow). */
export const METADATA_IPS: readonly string[] = [
  "169.254.169.254", // AWS / GCP / Azure / OCI / DigitalOcean / OpenStack instance metadata
  "fd00:ec2::254", // AWS IMDS over IPv6
  "169.254.170.2", // AWS ECS task metadata and credentials
  "169.254.170.23", // AWS EKS Pod Identity agent (credentials)
  "fd00:ec2::23", // AWS EKS Pod Identity agent over IPv6
  "100.100.100.200", // Alibaba Cloud metadata
];

/** Host names that always resolve to a metadata endpoint and are refused by name. */
export const METADATA_HOSTS: readonly string[] = ["metadata.google.internal"];

export interface ParsedIp {
  /** Canonical dotted-quad (v4) or lower-case colon form / embedded dotted-quad (v6). */
  canonical: string;
  family: 4 | 6;
}

/** Strip one pair of surrounding brackets from an IPv6 host taken from a URL ("[::1]" -> "::1"). */
export function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * Parse a bare IPv4 in any inet_aton form (1-4 parts, each decimal / 0x-hex / 0-octal) to a dotted quad.
 * Returns null when the host is not a numeric IPv4 (e.g. a DNS name or an IPv6 literal).
 */
export function parseNumericIPv4(host: string): string | null {
  if (!/^[0-9a-fA-FxX.]+$/.test(host) || host.endsWith(".")) return null;
  const parts = host.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    if (p === "") return null;
    let n: number;
    if (/^0[xX][0-9a-fA-F]+$/.test(p)) n = parseInt(p.slice(2), 16);
    else if (/^0[0-7]+$/.test(p)) n = parseInt(p, 8);
    else if (/^(0|[1-9][0-9]*)$/.test(p)) n = parseInt(p, 10);
    else return null;
    if (!Number.isFinite(n) || n < 0) return null;
    nums.push(n);
  }
  // inet_aton: the final part fills the remaining low-order bytes; earlier parts are one byte each.
  const n = nums.length;
  for (let i = 0; i < n - 1; i++) if (nums[i]! > 255) return null;
  const last = nums[n - 1]!;
  const lastBytes = 4 - (n - 1);
  if (last >= 2 ** (8 * lastBytes)) return null;
  let value = last >>> 0;
  for (let i = 0; i < n - 1; i++) value += nums[i]! * 2 ** (8 * (3 - i));
  value = value >>> 0;
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

/** Expand an IPv6 string (with "::" compression and optional embedded IPv4) to 16 bytes, or null. */
export function ipv6ToBytes(input: string): number[] | null {
  let s = input.trim().toLowerCase();
  if (s.includes("%")) s = s.slice(0, s.indexOf("%")); // drop zone id
  if (s === "") return null;
  // Split off an embedded IPv4 tail (e.g. ::ffff:1.2.3.4) into two 16-bit groups.
  let tailBytes: number[] = [];
  const lastColon = s.lastIndexOf(":");
  const tail = lastColon >= 0 ? s.slice(lastColon + 1) : s;
  if (tail.includes(".")) {
    const v4 = parseNumericIPv4(tail);
    if (!v4) return null;
    tailBytes = v4.split(".").map((x) => parseInt(x, 10));
    s = s.slice(0, lastColon + 1); // keep trailing colon so the group count stays right
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const toGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (g === "") return null;
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const left = toGroups(halves[0]!.replace(/:$/, ""));
  const right = halves.length === 2 ? toGroups(halves[1]!.replace(/:$/, "")) : [];
  if (left === null || right === null) return null;
  const v4Groups: number[] = [];
  if (tailBytes.length === 4) {
    v4Groups.push((tailBytes[0]! << 8) | tailBytes[1]!, (tailBytes[2]! << 8) | tailBytes[3]!);
  }
  const groups: number[] = halves.length === 2 ? fillCompressed(left, [...right, ...v4Groups]) : [...left, ...v4Groups];
  if (groups === null || groups.length !== 8) return null;
  const bytes: number[] = [];
  for (const g of groups) {
    if (g < 0 || g > 0xffff) return null;
    bytes.push((g >> 8) & 255, g & 255);
  }
  return bytes;
}

function fillCompressed(left: number[], right: number[]): number[] {
  const missing = 8 - left.length - right.length;
  if (missing < 0) return [];
  return [...left, ...Array<number>(missing).fill(0), ...right];
}

function bytesToV6Canonical(bytes: number[]): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((((bytes[i]! << 8) | bytes[i + 1]!) >>> 0).toString(16));
  return groups.join(":");
}

/** Parse a host (already bracket-stripped is fine; brackets are stripped here too) into an IP, or null for a name. */
export function parseIp(host: string): ParsedIp | null {
  const h = stripBrackets(host);
  if (h.includes(":")) {
    const bytes = ipv6ToBytes(h);
    if (!bytes) return null;
    // IPv4-mapped (::ffff:a.b.c.d): expose the embedded v4 so metadata/private checks see it.
    if (bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
      return { canonical: bytes.slice(12).join("."), family: 4 };
    }
    return { canonical: bytesToV6Canonical(bytes), family: 6 };
  }
  const v4 = parseNumericIPv4(h);
  return v4 ? { canonical: v4, family: 4 } : null;
}

function v4InCidr(ip: string, net: string, bits: number): boolean {
  const toInt = (s: string) => s.split(".").reduce((acc, p) => ((acc << 8) + parseInt(p, 10)) >>> 0, 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (toInt(ip) & mask) === (toInt(net) & mask);
}

/** Classify a parsed IP. Metadata takes precedence over every other class. */
export function classifyIp(ip: ParsedIp): IpClass {
  if (ip.family === 4) {
    if (METADATA_IPS.includes(ip.canonical)) return "metadata";
    if (v4InCidr(ip.canonical, "127.0.0.0", 8)) return "loopback";
    if (v4InCidr(ip.canonical, "169.254.0.0", 16)) return "linklocal";
    if (v4InCidr(ip.canonical, "10.0.0.0", 8) || v4InCidr(ip.canonical, "172.16.0.0", 12) || v4InCidr(ip.canonical, "192.168.0.0", 16)) return "private";
    return "public";
  }
  const bytes = ipv6ToBytes(ip.canonical);
  if (!bytes) return "public";
  if (METADATA_IPS.some((m) => sameV6(m, bytes))) return "metadata";
  if (bytes.slice(0, 15).every((b) => b === 0) && bytes[15] === 1) return "loopback"; // ::1
  if (bytes[0] === 0xfe && (bytes[1]! & 0xc0) === 0x80) return "linklocal"; // fe80::/10
  if ((bytes[0]! & 0xfe) === 0xfc) return "private"; // fc00::/7 ULA
  return "public";
}

function sameV6(a: string, bytes: number[]): boolean {
  const ab = ipv6ToBytes(a);
  return !!ab && ab.length === bytes.length && ab.every((b, i) => b === bytes[i]);
}

/** True when the host is an exact metadata IP (any numeric form) or a metadata host name. */
export function isMetadataHost(host: string): boolean {
  const h = stripBrackets(host).toLowerCase().replace(/\.$/, "");
  if (METADATA_HOSTS.includes(h)) return true;
  const ip = parseIp(h);
  return ip ? classifyIp(ip) === "metadata" : false;
}

/** An IP class that Probe may connect to as a private/local target (metadata excluded). */
export function isPrivateClass(cls: IpClass): boolean {
  return cls === "loopback" || cls === "linklocal" || cls === "private";
}
