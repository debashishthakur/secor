import { describe, expect, it } from "vitest";
import { classifyIp, isMetadataHost, isPrivateClass, parseIp, parseNumericIPv4 } from "../../src/probe/addresses.js";

describe("parseNumericIPv4 (inet_aton forms)", () => {
  it("parses dotted, decimal, hex and octal forms to a dotted quad", () => {
    expect(parseNumericIPv4("127.0.0.1")).toBe("127.0.0.1");
    expect(parseNumericIPv4("2852039166")).toBe("169.254.169.254");
    expect(parseNumericIPv4("0xa9fea9fe")).toBe("169.254.169.254");
    expect(parseNumericIPv4("0xA9FEA9FE")).toBe("169.254.169.254");
    expect(parseNumericIPv4("169.254.43518")).toBe("169.254.169.254"); // 3-part form
    expect(parseNumericIPv4("0251.0376.0251.0376")).toBe("169.254.169.254"); // octal
  });

  it("returns null for host names and malformed input", () => {
    expect(parseNumericIPv4("example.com")).toBeNull();
    expect(parseNumericIPv4("localhost")).toBeNull();
    expect(parseNumericIPv4("abc.def")).toBeNull();
    expect(parseNumericIPv4("256.1.1.1")).toBeNull();
    expect(parseNumericIPv4("1.2.3.4.5")).toBeNull();
  });
});

describe("parseIp + classifyIp", () => {
  const cls = (host: string) => {
    const ip = parseIp(host);
    return ip ? classifyIp(ip) : null;
  };

  it("classifies loopback / link-local / RFC1918 / RFC4193 as their class", () => {
    expect(cls("127.0.0.1")).toBe("loopback");
    expect(cls("10.1.2.3")).toBe("private");
    expect(cls("172.16.5.5")).toBe("private");
    expect(cls("172.32.0.1")).toBe("public"); // just outside 172.16/12
    expect(cls("192.168.0.1")).toBe("private");
    expect(cls("169.254.1.2")).toBe("linklocal");
    expect(cls("8.8.8.8")).toBe("public");
    expect(cls("::1")).toBe("loopback");
    expect(cls("fe80::1")).toBe("linklocal");
    expect(cls("fc00::1")).toBe("private");
    expect(cls("fd12:3456::1")).toBe("private");
    expect(cls("2001:4860:4860::8888")).toBe("public");
  });

  it("maps IPv4-mapped IPv6 to the embedded v4", () => {
    expect(parseIp("::ffff:169.254.169.254")).toEqual({ canonical: "169.254.169.254", family: 4 });
    expect(parseIp("::ffff:a9fe:a9fe")).toEqual({ canonical: "169.254.169.254", family: 4 });
    const loop = parseIp("[::1]")!;
    expect(loop.family).toBe(6);
    expect(classifyIp(loop)).toBe("loopback");
  });

  it("classifies all metadata forms as metadata, ahead of link-local/ULA", () => {
    expect(cls("169.254.169.254")).toBe("metadata");
    expect(cls("2852039166")).toBe("metadata");
    expect(cls("0xa9fea9fe")).toBe("metadata");
    expect(cls("::ffff:169.254.169.254")).toBe("metadata");
    expect(cls("100.100.100.200")).toBe("metadata");
    expect(cls("fd00:ec2::254")).toBe("metadata");
  });
});

describe("isMetadataHost", () => {
  it("refuses metadata IPs in any form and the metadata host name", () => {
    for (const h of ["169.254.169.254", "2852039166", "0xa9fea9fe", "::ffff:169.254.169.254", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal", "metadata.google.internal.", "[fd00:ec2::254]"]) {
      expect(isMetadataHost(h), h).toBe(true);
    }
  });
  it("does not flag ordinary private or public hosts", () => {
    for (const h of ["127.0.0.1", "10.0.0.1", "169.254.1.2", "example.com", "staging.myapp.com"]) {
      expect(isMetadataHost(h), h).toBe(false);
    }
  });
});

describe("isPrivateClass", () => {
  it("treats loopback / link-local / private as connectable, public / metadata as not", () => {
    expect(isPrivateClass("loopback")).toBe(true);
    expect(isPrivateClass("linklocal")).toBe(true);
    expect(isPrivateClass("private")).toBe(true);
    expect(isPrivateClass("public")).toBe(false);
    expect(isPrivateClass("metadata")).toBe(false);
  });
});
