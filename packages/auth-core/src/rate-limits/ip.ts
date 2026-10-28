import { BlockList, isIP } from "node:net";

/**
 * An address in canonical form: dotted IPv4, or fully expanded lower-case
 * IPv6 (eight four-digit groups). IPv4-mapped IPv6 becomes IPv4. Accepts
 * brackets, an IPv4 port, or an IPv6 zone, and drops them. `null` when it is
 * not an address.
 */
export function normaliseIp(value: string): string | null {
  let text = value.trim();
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(text);
  if (bracketed?.[1]) text = bracketed[1];
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(text))
    text = text.slice(0, text.lastIndexOf(":"));
  text = text.replace(/%.*$/, "");
  const kind = isIP(text);
  if (kind === 4) return text.split(".").map(Number).join(".");
  if (kind !== 6) return null;
  const expanded = expandIpv6(text.toLowerCase());
  const mapped = "0000:0000:0000:0000:0000:ffff:";
  if (!expanded.startsWith(mapped)) return expanded;
  const [high = 0, low = 0] = expanded
    .slice(mapped.length)
    .split(":")
    .map((group) => Number.parseInt(group, 16));
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

function expandIpv6(address: string): string {
  // A trailing dotted quad becomes two groups.
  let text = address;
  const quad = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (quad) {
    const [a = 0, b = 0, c = 0, d = 0] = quad.slice(1).map(Number);
    text = `${text.slice(0, quad.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = "", tail] = text.split("::");
  const left = head === "" ? [] : head.split(":");
  const right = tail === undefined || tail === "" ? [] : tail.split(":");
  const middle =
    tail === undefined ? [] : Array(8 - left.length - right.length).fill("0");
  return [...left, ...middle, ...right]
    .map((group) => group.padStart(4, "0"))
    .join(":");
}

/**
 * The value a per-IP limit keys on: the IPv4 address, or the /64 prefix of
 * an IPv6 address, since one host usually holds a whole /64.
 */
export function ipLimitKey(address: string): string {
  const normal = normaliseIp(address);
  if (normal === null) return "unknown";
  if (!normal.includes(":")) return normal;
  return `${normal.split(":").slice(0, 4).join(":")}::/64`;
}

/**
 * Parses CIDRs or bare addresses into a {@link BlockList}.
 *
 * @throws `TypeError` naming the first entry that is not one.
 */
export function parseTrustedProxies(entries: readonly string[]): BlockList {
  const list = new BlockList();
  for (const entry of entries) {
    const [address = "", bits] = entry.split("/");
    const normal = normaliseIp(address);
    if (normal === null)
      throw new TypeError(`${entry} is not an address or CIDR`);
    const family = normal.includes(":") ? "ipv6" : "ipv4";
    const max = family === "ipv6" ? 128 : 32;
    const prefix = bits === undefined ? max : Number(bits);
    if (!/^\d{1,3}$/.test(bits ?? String(max)) || prefix > max)
      throw new TypeError(`${entry} has an invalid prefix length`);
    list.addSubnet(normal, prefix, family);
  }
  return list;
}

function inList(list: BlockList, address: string): boolean {
  return list.check(address, address.includes(":") ? "ipv6" : "ipv4");
}

/** The `for=` values of a `Forwarded` header (RFC 7239), in order. */
function forwardedFor(header: string): string[] {
  const out: string[] = [];
  for (const element of header.split(",")) {
    for (const pair of element.split(";")) {
      const [name, ...rest] = pair.split("=");
      if (name?.trim().toLowerCase() !== "for") continue;
      out.push(
        rest
          .join("=")
          .trim()
          .replace(/^"(.*)"$/, "$1"),
      );
    }
  }
  return out;
}

/**
 * The client's address. The socket peer is the client unless it is a
 * trusted proxy; then the forwarding chain (`Forwarded`, else
 * `X-Forwarded-For`) is walked from the right, skipping trusted hops, and
 * the first untrusted address is the client. Anything a client could have
 * written further left is ignored. Returns `null` when the peer is unknown.
 */
export function resolveClientIp(input: {
  readonly peer: string | null | undefined;
  readonly trusted: BlockList;
  readonly forwarded?: string | null | undefined;
  readonly xForwardedFor?: string | null | undefined;
}): string | null {
  const peer = input.peer ? normaliseIp(input.peer) : null;
  if (peer === null) return null;
  if (!inList(input.trusted, peer)) return peer;
  const chain = input.forwarded
    ? forwardedFor(input.forwarded)
    : (input.xForwardedFor ?? "").split(",").map((s) => s.trim());
  let client = peer;
  for (let i = chain.length - 1; i >= 0; i--) {
    const hop = normaliseIp(chain[i] ?? "");
    // An unparseable or obfuscated hop ends the walk at the last address a
    // trusted proxy vouched for.
    if (hop === null) return client;
    client = hop;
    if (!inList(input.trusted, hop)) return hop;
  }
  return client;
}
