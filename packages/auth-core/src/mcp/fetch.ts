import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { isIP } from "node:net";

/** A resolved address, as `dns.lookup` returns it. */
export interface ResolvedAddress {
  readonly address: string;
  readonly family: number;
}

/** A response from {@link MetadataFetchOptions.transport}. */
export interface TransportResponse {
  readonly status: number;
  /** Header names in lower case. */
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: AsyncIterable<Uint8Array>;
}

/** How client metadata documents are fetched. Tests replace the network. */
export interface MetadataFetchOptions {
  /** The whole fetch, DNS included, in milliseconds. Default 3000. */
  readonly timeoutMs?: number;
  /** The largest document accepted, in bytes. Default 5120. */
  readonly maxBytes?: number;
  /** Resolves a host name to every address. Default `dns.lookup`. */
  readonly resolve?: (host: string) => Promise<readonly ResolvedAddress[]>;
  /**
   * Requests `url` from `address` without following redirects. The default
   * is `node:https` with the lookup pinned to `address`, so the certificate
   * is still checked against the host name.
   */
  readonly transport?: (
    url: URL,
    address: ResolvedAddress,
    signal: AbortSignal,
  ) => Promise<TransportResponse>;
}

/** Why a metadata document could not be used. Safe to show the client. */
export class MetadataFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MetadataFetchError";
  }
}

const octets = (address: string) => address.split(".").map(Number);

/**
 * True for a globally routable unicast address. Private, loopback,
 * link-local, shared (CGNAT), multicast, documentation, benchmarking and
 * other special-use ranges are refused, as are IPv4-mapped and translated
 * IPv6 forms of them.
 */
export function isPublicAddress(address: string): boolean {
  const kind = isIP(address);
  if (kind === 4) {
    const [a = 0, b = 0, c = 0] = octets(address);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  if (kind !== 6) return false;
  const lower = address.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped?.[1]) return isPublicAddress(mapped[1]);
  const [first = 0, second = 0] = lower
    .split(":")
    .map((group) => Number.parseInt(group || "0", 16));
  // Global unicast (2000::/3) only, without documentation (2001:db8::/32),
  // Teredo and other IETF protocol space (2001::/23), or 6to4 (2002::/16).
  return (
    first >= 0x2000 &&
    first <= 0x3fff &&
    first !== 0x2002 &&
    !(first === 0x2001 && (second < 0x200 || second === 0xdb8))
  );
}

async function defaultResolve(host: string): Promise<ResolvedAddress[]> {
  return lookup(host, { all: true, verbatim: true });
}

function defaultTransport(
  url: URL,
  address: ResolvedAddress,
  signal: AbortSignal,
): Promise<TransportResponse> {
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: "GET",
        headers: { accept: "application/json" },
        agent: false,
        signal,
        // Connect to the address that was checked, not a second lookup.
        lookup: (_host, options, callback) => {
          if (options.all) callback(null, [address]);
          else callback(null, address.address, address.family);
        },
      },
      (res) =>
        resolve({
          status: res.statusCode ?? 0,
          headers: Object.fromEntries(
            Object.entries(res.headers).map(([k, v]) => [
              k.toLowerCase(),
              Array.isArray(v) ? v.join(", ") : v,
            ]),
          ),
          body: res,
        }),
    );
    req.on("error", reject);
    req.end();
  });
}

/** The `max-age` of a `Cache-Control` header, or 0 when it forbids caching. */
export function cacheSeconds(header: string | undefined): number {
  if (header === undefined) return 0;
  const directives = header.toLowerCase();
  if (/(^|[\s,])(no-store|no-cache|private)([\s,=]|$)/.test(directives))
    return 0;
  const match = /(?:^|[\s,])max-age\s*=\s*"?(\d{1,10})"?/.exec(directives);
  return match?.[1] ? Number(match[1]) : 0;
}

/**
 * Fetches a JSON document from an `https` URL defensively, for OAuth client
 * metadata documents:
 *
 * - the host must be a name, not an IP literal, on port 443;
 * - every address it resolves to must be public, and the connection is
 *   pinned to the first one;
 * - redirects are refused, the response must be 200 with an
 *   `application/json` content type, and the body at most `maxBytes`;
 * - DNS, connection and body together must finish within `timeoutMs`.
 *
 * Returns the parsed JSON and how long it may be cached, in seconds.
 *
 * @throws {@link MetadataFetchError}
 */
export async function fetchMetadataDocument(
  url: URL,
  options: MetadataFetchOptions = {},
): Promise<{ value: unknown; cacheSeconds: number }> {
  const timeoutMs = options.timeoutMs ?? 3000;
  const maxBytes = options.maxBytes ?? 5120;
  if (
    url.protocol !== "https:" ||
    (url.port !== "" && url.port !== "443") ||
    url.username !== "" ||
    url.password !== "" ||
    isIP(url.hostname.replace(/^\[|\]$/g, "")) !== 0
  )
    throw new MetadataFetchError(
      "Client metadata must be at an https URL on a host name, on the default port.",
    );
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new MetadataFetchError("Fetching the client metadata timed out."));
    }, timeoutMs);
  });
  // The races below observe the rejection; this keeps a late one quiet.
  deadline.catch(() => {});
  const race = <T>(work: Promise<T>) => Promise.race([work, deadline]);
  try {
    let addresses: readonly ResolvedAddress[];
    try {
      addresses = await race((options.resolve ?? defaultResolve)(url.hostname));
    } catch (error) {
      if (error instanceof MetadataFetchError) throw error;
      throw new MetadataFetchError(
        "The client metadata host does not resolve.",
      );
    }
    const first = addresses[0];
    if (!first || addresses.some((a) => !isPublicAddress(a.address)))
      throw new MetadataFetchError(
        "Client metadata must be hosted on a public address.",
      );
    let response: TransportResponse;
    try {
      response = await race(
        (options.transport ?? defaultTransport)(url, first, controller.signal),
      );
    } catch (error) {
      if (error instanceof MetadataFetchError) throw error;
      throw new MetadataFetchError("The client metadata could not be fetched.");
    }
    if (response.status !== 200)
      throw new MetadataFetchError(
        response.status >= 300 && response.status < 400
          ? "Client metadata must be served directly, without a redirect."
          : `The client metadata request answered ${response.status}.`,
      );
    if (
      !/^application\/json\s*(;|$)/i.test(
        response.headers["content-type"] ?? "",
      )
    )
      throw new MetadataFetchError(
        "Client metadata must be served as application/json.",
      );
    const declared = Number(response.headers["content-length"] ?? "0");
    if (declared > maxBytes)
      throw new MetadataFetchError(
        `Client metadata is larger than ${maxBytes} bytes.`,
      );
    const read = async () => {
      const chunks: Uint8Array[] = [];
      let size = 0;
      for await (const chunk of response.body) {
        size += chunk.byteLength;
        if (size > maxBytes) {
          controller.abort();
          throw new MetadataFetchError(
            `Client metadata is larger than ${maxBytes} bytes.`,
          );
        }
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    };
    let bytes: Buffer;
    try {
      bytes = await race(read());
    } catch (error) {
      if (error instanceof MetadataFetchError) throw error;
      throw new MetadataFetchError("The client metadata could not be read.");
    }
    let value: unknown;
    try {
      value = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } catch {
      throw new MetadataFetchError("Client metadata is not valid JSON.");
    }
    return {
      value,
      cacheSeconds: cacheSeconds(response.headers["cache-control"]),
    };
  } finally {
    clearTimeout(timer);
  }
}
