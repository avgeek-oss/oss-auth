import { describe, expect, it } from "vitest";
import {
  ipLimitKey,
  normaliseIp,
  parseTrustedProxies,
  resolveClientIp,
} from "../../src/rate-limits/index.js";

describe("normaliseIp", () => {
  it("canonicalises IPv4 and IPv6, and unwraps mapped, bracketed and ported forms", () => {
    const cases: [string, string | null][] = [
      ["203.0.113.7", "203.0.113.7"],
      [" 203.0.113.7 ", "203.0.113.7"],
      ["203.0.113.7:5432", "203.0.113.7"],
      ["2001:DB8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"],
      ["2001:db8:0:0:0:0:0:1", "2001:0db8:0000:0000:0000:0000:0000:0001"],
      ["[2001:db8::1]:443", "2001:0db8:0000:0000:0000:0000:0000:0001"],
      ["[2001:db8::1]", "2001:0db8:0000:0000:0000:0000:0000:0001"],
      ["fe80::1%eth0", "fe80:0000:0000:0000:0000:0000:0000:0001"],
      ["::", "0000:0000:0000:0000:0000:0000:0000:0000"],
      ["::1", "0000:0000:0000:0000:0000:0000:0000:0001"],
      ["::ffff:203.0.113.7", "203.0.113.7"],
      ["::ffff:cb00:7107", "203.0.113.7"],
      ["64:ff9b::203.0.113.7", "0064:ff9b:0000:0000:0000:0000:cb00:7107"],
      ["unknown", null],
      ["_hidden", null],
      ["999.1.1.1", null],
      ["", null],
    ];
    for (const [input, expected] of cases)
      expect(normaliseIp(input), input).toBe(expected);
  });
});

describe("ipLimitKey", () => {
  it("keys IPv4 on the address and IPv6 on the /64", () => {
    expect(ipLimitKey("203.0.113.7")).toBe("203.0.113.7");
    expect(ipLimitKey("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(ipLimitKey("2001:db8:1:2::1")).toBe("2001:0db8:0001:0002::/64");
    expect(ipLimitKey("2001:db8:1:2:ffff:ffff:ffff:ffff")).toBe(
      "2001:0db8:0001:0002::/64",
    );
    expect(ipLimitKey("2001:db8:1:3::1")).toBe("2001:0db8:0001:0003::/64");
    expect(ipLimitKey("garbage")).toBe("unknown");
  });
});

describe("parseTrustedProxies", () => {
  it("accepts addresses and CIDRs of both families and names a bad entry", () => {
    const list = parseTrustedProxies([
      "10.0.0.0/8",
      "192.0.2.1",
      "fd00::/8",
      "::1",
    ]);
    expect(list.check("10.9.8.7", "ipv4")).toBe(true);
    expect(list.check("192.0.2.1", "ipv4")).toBe(true);
    expect(list.check("192.0.2.2", "ipv4")).toBe(false);
    expect(list.check("fd12::1", "ipv6")).toBe(true);
    for (const bad of [
      "10.0.0.0/33",
      "fd00::/129",
      "example.com",
      "10.0.0.0/x",
    ])
      expect(() => parseTrustedProxies([bad])).toThrow(bad);
  });
});

describe("resolveClientIp", () => {
  const trusted = parseTrustedProxies(["10.0.0.0/8", "2001:db8:ffff::/48"]);

  it("uses the socket peer and ignores forwarding headers from an untrusted one", () => {
    expect(
      resolveClientIp({
        peer: "198.51.100.9",
        trusted,
        xForwardedFor: "1.2.3.4",
        forwarded: "for=5.6.7.8",
      }),
    ).toBe("198.51.100.9");
    expect(resolveClientIp({ peer: undefined, trusted })).toBeNull();
  });

  it("walks X-Forwarded-For from the right, skipping trusted hops", () => {
    // A client-written "1.2.3.4" sits left of what the proxies appended.
    expect(
      resolveClientIp({
        peer: "10.0.0.2",
        trusted,
        xForwardedFor: "1.2.3.4, 203.0.113.7, 10.0.0.1",
      }),
    ).toBe("203.0.113.7");
    expect(
      resolveClientIp({
        peer: "::ffff:10.0.0.2",
        trusted,
        xForwardedFor: "203.0.113.7",
      }),
    ).toBe("203.0.113.7");
    // Only trusted hops: the leftmost is the best we know.
    expect(
      resolveClientIp({
        peer: "10.0.0.2",
        trusted,
        xForwardedFor: "10.0.0.5, 10.0.0.1",
      }),
    ).toBe("10.0.0.5");
    // No header from a trusted proxy: the proxy itself.
    expect(resolveClientIp({ peer: "10.0.0.2", trusted })).toBe("10.0.0.2");
    // A garbage hop ends the walk at the last address a proxy vouched for.
    expect(
      resolveClientIp({
        peer: "10.0.0.2",
        trusted,
        xForwardedFor: "evil, 10.0.0.1",
      }),
    ).toBe("10.0.0.1");
  });

  it("prefers Forwarded, with quoted IPv6, ports and obfuscated hops", () => {
    expect(
      resolveClientIp({
        peer: "2001:db8:ffff::2",
        trusted,
        forwarded:
          'for=1.2.3.4;proto=https, for="[2001:db8:1:2::7]:4711";by=10.0.0.1, For=10.0.0.3',
        xForwardedFor: "9.9.9.9",
      }),
    ).toBe("2001:0db8:0001:0002:0000:0000:0000:0007");
    expect(
      resolveClientIp({
        peer: "10.0.0.2",
        trusted,
        forwarded: "for=_hidden, for=10.0.0.3",
      }),
    ).toBe("10.0.0.3");
  });
});
