import { describe, expect, it } from "vitest";
import {
  cacheSeconds,
  fetchMetadataDocument,
  isPublicAddress,
  MetadataFetchError,
  type MetadataFetchOptions,
  type ResolvedAddress,
  type TransportResponse,
} from "../../src/mcp/index.js";

const URL_OK = new URL("https://client.example.com/oauth/metadata.json");
const PUBLIC: ResolvedAddress = { address: "93.184.216.34", family: 4 };

async function* chunks(...parts: string[]): AsyncIterable<Uint8Array> {
  for (const part of parts) yield Buffer.from(part);
}

/** A transport that answers with `response`, recording the calls. */
function serve(
  response: Partial<TransportResponse> & { body?: AsyncIterable<Uint8Array> },
) {
  const calls: { url: string; address: string }[] = [];
  const transport: NonNullable<MetadataFetchOptions["transport"]> = async (
    url,
    address,
  ) => {
    calls.push({ url: url.href, address: address.address });
    return {
      status: 200,
      headers: { "content-type": "application/json" },
      body: chunks('{"ok":true}'),
      ...response,
    };
  };
  return { transport, calls };
}

async function refusal(
  url: URL,
  options: MetadataFetchOptions,
): Promise<string> {
  try {
    await fetchMetadataDocument(url, options);
  } catch (error) {
    expect(error).toBeInstanceOf(MetadataFetchError);
    return (error as Error).message;
  }
  throw new Error("expected a refusal");
}

describe("isPublicAddress", () => {
  it("accepts global unicast and refuses private, loopback, link-local and special ranges", () => {
    for (const address of [
      "93.184.216.34",
      "8.8.8.8",
      "2606:4700::1111",
      "2a00:1450::1",
    ])
      expect(isPublicAddress(address)).toBe(true);
    for (const address of [
      "0.0.0.0",
      "10.1.2.3",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "100.64.0.1",
      "192.0.0.8",
      "192.0.2.1",
      "198.18.0.1",
      "198.51.100.7",
      "203.0.113.9",
      "224.0.0.1",
      "255.255.255.255",
      "::",
      "::1",
      "fe80::1",
      "fc00::1",
      "fd12:3456::1",
      "ff02::1",
      "::ffff:10.0.0.1",
      "::ffff:127.0.0.1",
      "2001:db8::1",
      "2001::1",
      "2002:c000:0204::1",
      "64:ff9b::a00:1",
      "not-an-address",
    ])
      expect(isPublicAddress(address), address).toBe(false);
  });
});

describe("cacheSeconds", () => {
  it("reads max-age and refuses no-store, no-cache and private", () => {
    expect(cacheSeconds(undefined)).toBe(0);
    expect(cacheSeconds("public, max-age=600")).toBe(600);
    expect(cacheSeconds('max-age="60"')).toBe(60);
    expect(cacheSeconds("no-store")).toBe(0);
    expect(cacheSeconds("max-age=600, no-cache")).toBe(0);
    expect(cacheSeconds("private, max-age=600")).toBe(0);
    expect(cacheSeconds("s-maxage=60")).toBe(0);
  });
});

describe("fetchMetadataDocument", () => {
  const resolvesTo =
    (...addresses: string[]) =>
    async () =>
      addresses.map((address) => ({
        address,
        family: address.includes(":") ? 6 : 4,
      }));

  it("fetches JSON from the checked address and reports how long to cache it", async () => {
    const { transport, calls } = serve({
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "max-age=3600",
      },
    });
    expect(
      await fetchMetadataDocument(URL_OK, {
        resolve: resolvesTo(PUBLIC.address, "93.184.216.35"),
        transport,
      }),
    ).toEqual({ value: { ok: true }, cacheSeconds: 3600 });
    expect(calls).toEqual([{ url: URL_OK.href, address: PUBLIC.address }]);
  });

  it("refuses non-https URLs, other ports, credentials and IP literals before any lookup", async () => {
    let lookups = 0;
    const options: MetadataFetchOptions = {
      resolve: async () => {
        lookups++;
        return [PUBLIC];
      },
      transport: serve({}).transport,
    };
    for (const url of [
      "http://client.example.com/meta.json",
      "https://client.example.com:8443/meta.json",
      "https://user:pass@client.example.com/meta.json",
      "https://93.184.216.34/meta.json",
      "https://[2606:4700::1111]/meta.json",
    ])
      expect(await refusal(new URL(url), options)).toMatch(
        /https URL on a host name/,
      );
    expect(lookups).toBe(0);
  });

  it("refuses names that resolve to any private, loopback or link-local address", async () => {
    for (const addresses of [
      ["10.0.0.5"],
      ["127.0.0.1"],
      ["169.254.169.254"],
      ["::1"],
      ["fd00::1"],
      ["::ffff:192.168.0.1"],
      [PUBLIC.address, "10.0.0.5"],
      [],
    ]) {
      const { transport, calls } = serve({});
      expect(
        await refusal(URL_OK, { resolve: resolvesTo(...addresses), transport }),
      ).toMatch(/public address/);
      expect(calls).toEqual([]);
    }
  });

  it("refuses a real lookup of localhost", async () => {
    expect(
      await refusal(new URL("https://localhost/meta.json"), {
        transport: serve({}).transport,
      }),
    ).toMatch(/public address|does not resolve/);
  });

  it("refuses redirects, errors, other content types and oversized documents", async () => {
    const resolve = resolvesTo(PUBLIC.address);
    expect(
      await refusal(URL_OK, {
        resolve,
        transport: serve({
          status: 302,
          headers: { location: "http://169.254.169.254/" },
        }).transport,
      }),
    ).toMatch(/without a redirect/);
    expect(
      await refusal(URL_OK, {
        resolve,
        transport: serve({ status: 404 }).transport,
      }),
    ).toMatch(/answered 404/);
    for (const type of [
      "text/html",
      "application/jsonp",
      "",
      "text/plain; charset=utf-8",
    ])
      expect(
        await refusal(URL_OK, {
          resolve,
          transport: serve({ headers: { "content-type": type } }).transport,
        }),
      ).toMatch(/application\/json/);
    expect(
      await refusal(URL_OK, {
        resolve,
        transport: serve({
          headers: {
            "content-type": "application/json",
            "content-length": "5121",
          },
        }).transport,
      }),
    ).toMatch(/larger than 5120/);
    // A body that streams past the limit without declaring its length.
    expect(
      await refusal(URL_OK, {
        resolve,
        transport: serve({ body: chunks("[", "1,".repeat(3000), "1]") })
          .transport,
      }),
    ).toMatch(/larger than 5120/);
    expect(
      await refusal(URL_OK, {
        resolve,
        transport: serve({ body: chunks("{not json") }).transport,
      }),
    ).toMatch(/not valid JSON/);
  });

  it("gives up after the timeout, whether DNS, the connection or the body is slow", async () => {
    const never = new Promise<never>(() => {});
    const started = Date.now();
    expect(
      await refusal(URL_OK, { timeoutMs: 150, resolve: () => never }),
    ).toMatch(/timed out/);
    expect(
      await refusal(URL_OK, {
        timeoutMs: 150,
        resolve: resolvesTo(PUBLIC.address),
        transport: () => never,
      }),
    ).toMatch(/timed out/);
    let aborted = false;
    expect(
      await refusal(URL_OK, {
        timeoutMs: 150,
        resolve: resolvesTo(PUBLIC.address),
        transport: async (_url, _address, signal) => {
          signal.addEventListener("abort", () => {
            aborted = true;
          });
          return {
            status: 200,
            headers: { "content-type": "application/json" },
            body: (async function* () {
              yield Buffer.from("{");
              await never;
            })(),
          };
        },
      }),
    ).toMatch(/timed out/);
    expect(aborted).toBe(true);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("uses three seconds and 5 KB by default", async () => {
    expect(
      await refusal(URL_OK, {
        resolve: resolvesTo(PUBLIC.address),
        transport: serve({ body: chunks("x".repeat(5121)) }).transport,
      }),
    ).toMatch(/larger than 5120/);
  });
});
