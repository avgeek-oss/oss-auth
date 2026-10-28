import { BlockList, isIP } from "node:net";

/**
 * The longest text {@link normaliseIp} considers. The longest valid form,
 * a bracketed IPv6 address with an IPv4 tail, a zone and a port, is about
 * 60 characters; anything longer is rejected before it is parsed, so
 * client-written headers cost time in proportion to their length at most.
 */
const MAX_ADDRESS_LENGTH = 64;

/** Which forwarding header a trusted proxy sets. */
export type TrustedProxyHeader = "x-forwarded-for" | "forwarded";

/** The forwarding headers {@link resolveClientIp} understands. */
export const TRUSTED_PROXY_HEADERS: readonly TrustedProxyHeader[] = [
  "x-forwarded-for",
  "forwarded",
];

/** True when `text` is 1 to `max` ASCII digits. */
function isDigits(text: string, max: number): boolean {
  if (text.length === 0 || text.length > max) return false;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 48 || code > 57) return false;
  }
  return true;
}

/**
 * An address in canonical form: dotted IPv4, or fully expanded lower-case
 * IPv6 (eight four-digit groups). IPv4-mapped IPv6 becomes IPv4. Accepts
 * brackets, an IPv4 port, or an IPv6 zone, and drops them. `null` when it is
 * not an address, or is longer than any address could be.
 */
export function normaliseIp(value: string): string | null {
  if (value.length > MAX_ADDRESS_LENGTH * 4) return null;
  let text = value.trim();
  if (text.length === 0 || text.length > MAX_ADDRESS_LENGTH) return null;
  if (text.startsWith("[")) {
    // [address] or [address]:port
    const close = text.indexOf("]");
    if (close < 0) return null;
    const rest = text.slice(close + 1);
    if (rest !== "" && !(rest.startsWith(":") && isDigits(rest.slice(1), 5)))
      return null;
    text = text.slice(1, close);
  } else {
    // address:port, for IPv4 only: an IPv6 address has more than one colon.
    const colon = text.indexOf(":");
    if (
      colon >= 0 &&
      colon === text.lastIndexOf(":") &&
      isDigits(text.slice(colon + 1), 5)
    )
      text = text.slice(0, colon);
  }
  const zone = text.indexOf("%");
  if (zone >= 0) text = text.slice(0, zone);
  const kind = isIP(text);
  if (kind === 4) return text.split(".").map(Number).join(".");
  if (kind !== 6) return null;
  const expanded = expandIpv6(text.toLowerCase());
  if (expanded === null) return null;
  const mapped = "0000:0000:0000:0000:0000:ffff:";
  if (!expanded.startsWith(mapped)) return expanded;
  const [high = 0, low = 0] = expanded
    .slice(mapped.length)
    .split(":")
    .map((group) => Number.parseInt(group, 16));
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

/** Expands an address `isIP` accepted as IPv6 to eight four-digit groups. */
function expandIpv6(address: string): string | null {
  let text = address;
  // A trailing dotted quad becomes two groups.
  if (text.includes(".")) {
    const colon = text.lastIndexOf(":");
    const parts = text.slice(colon + 1).split(".");
    if (parts.length !== 4 || !parts.every((part) => isDigits(part, 3)))
      return null;
    const [a = 0, b = 0, c = 0, d = 0] = parts.map(Number);
    text = `${text.slice(0, colon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = "", tail] = text.split("::");
  const left = head === "" ? [] : head.split(":");
  const right = tail === undefined || tail === "" ? [] : tail.split(":");
  const missing = 8 - left.length - right.length;
  if (tail === undefined ? missing !== 0 : missing < 1) return null;
  const middle = tail === undefined ? [] : Array<string>(missing).fill("0");
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
    const slash = entry.indexOf("/");
    const address = slash < 0 ? entry : entry.slice(0, slash);
    const bits = slash < 0 ? undefined : entry.slice(slash + 1);
    const normal = normaliseIp(address);
    if (normal === null)
      throw new TypeError(`${entry} is not an address or CIDR`);
    const family = normal.includes(":") ? "ipv6" : "ipv4";
    const max = family === "ipv6" ? 128 : 32;
    if (bits !== undefined && !isDigits(bits, 3))
      throw new TypeError(`${entry} has an invalid prefix length`);
    const prefix = bits === undefined ? max : Number(bits);
    if (prefix > max)
      throw new TypeError(`${entry} has an invalid prefix length`);
    list.addSubnet(normal, prefix, family);
  }
  return list;
}

function inList(list: BlockList, address: string): boolean {
  return list.check(address, address.includes(":") ? "ipv6" : "ipv4");
}

/**
 * One hop per element of a `Forwarded` header (RFC 7239), in order: the
 * element's `for=` value, or `null` when the element has no `for`, more
 * than one, or one that is not an address (such as `unknown` or an
 * obfuscated `_hidden`).
 */
function forwardedHops(header: string): (string | null)[] {
  return header.split(",").map((element) => {
    let found: string | null = null;
    let count = 0;
    for (const pair of element.split(";")) {
      const equals = pair.indexOf("=");
      if (equals < 0) continue;
      if (pair.slice(0, equals).trim().toLowerCase() !== "for") continue;
      count++;
      let value = pair.slice(equals + 1).trim();
      if (value.length >= 2 && value.startsWith('"') && value.endsWith('"'))
        value = value.slice(1, -1);
      found = value;
    }
    return count === 1 && found !== null ? normaliseIp(found) : null;
  });
}

/** One hop per entry of an `X-Forwarded-For` header, in order. */
function xForwardedForHops(header: string): (string | null)[] {
  return header.split(",").map((entry) => normaliseIp(entry));
}

/**
 * The client's address. The socket peer is the client unless it is a
 * trusted proxy; then the chain in the one configured forwarding header
 * (`header`, `x-forwarded-for` by default) is walked from the right,
 * skipping trusted hops, and the first untrusted address is the client. The
 * other forwarding header is ignored entirely, and so is anything a client
 * could have written further left. A hop that is not an address ends the
 * walk at the last address a trusted proxy vouched for. Returns `null` when
 * the peer is unknown.
 */
export function resolveClientIp(input: {
  readonly peer: string | null | undefined;
  readonly trusted: BlockList;
  readonly header?: TrustedProxyHeader;
  readonly forwarded?: string | null | undefined;
  readonly xForwardedFor?: string | null | undefined;
}): string | null {
  const peer = input.peer ? normaliseIp(input.peer) : null;
  if (peer === null) return null;
  if (!inList(input.trusted, peer)) return peer;
  const header = input.header ?? "x-forwarded-for";
  const value = header === "forwarded" ? input.forwarded : input.xForwardedFor;
  if (!value) return peer;
  const chain =
    header === "forwarded" ? forwardedHops(value) : xForwardedForHops(value);
  let client = peer;
  for (let i = chain.length - 1; i >= 0; i--) {
    const hop = chain[i] ?? null;
    if (hop === null) return client;
    client = hop;
    if (!inList(input.trusted, hop)) return hop;
  }
  return client;
}
