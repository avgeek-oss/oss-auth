import { afterEach, describe, expect, it } from "vitest";
import type { MetadataFetchOptions } from "../../src/mcp/index.js";
import { databaseUrl } from "../postgres/support.js";
import { WEB } from "../hono/support.js";
import {
  CONFIDENTIAL_CLIENT,
  PUBLIC_CLIENT,
  PUBLIC_REDIRECT,
  pkce,
  rows,
  startMcp,
  type McpStack,
} from "./support.js";

const stacks: McpStack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});
async function stack(...args: Parameters<typeof startMcp>) {
  const s = await startMcp(...args);
  stacks.push(s);
  return s;
}

const CIMD = "https://agent.example.com/oauth/client.json";
const CIMD_REDIRECT = "https://agent.example.com/oauth/callback";

/** A metadata fetcher serving `documents` by URL, counting requests. */
function documents(
  served: Record<string, { body: unknown; cacheControl?: string }>,
  resolveTo = "93.184.216.34",
) {
  const calls: string[] = [];
  const options: MetadataFetchOptions = {
    resolve: async () => [{ address: resolveTo, family: 4 }],
    transport: async (url) => {
      calls.push(url.href);
      const doc = served[url.href];
      if (!doc)
        return {
          status: 404,
          headers: { "content-type": "application/json" },
          body: (async function* () {})(),
        };
      return {
        status: 200,
        headers: {
          "content-type": "application/json",
          ...(doc.cacheControl ? { "cache-control": doc.cacheControl } : {}),
        },
        body: (async function* () {
          yield Buffer.from(JSON.stringify(doc.body));
        })(),
      };
    },
  };
  return { options, calls };
}

describe.skipIf(!databaseUrl)("MCP authorization server", () => {
  it("publishes RFC 8414 metadata and RFC 9728 metadata for each resource", async () => {
    const s = await stack();
    const as = await fetch(`${s.api}/.well-known/oauth-authorization-server`);
    expect(await as.json()).toEqual({
      issuer: s.api,
      authorization_endpoint: `${s.api}/oauth/authorize`,
      token_endpoint: `${s.api}/oauth/token`,
      revocation_endpoint: `${s.api}/oauth/revoke`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
      revocation_endpoint_auth_methods_supported: [
        "none",
        "client_secret_basic",
      ],
      scopes_supported: ["viewer", "member", "admin"],
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: true,
    });
    for (const [path, name] of [
      ["/mcp", "Posted MCP"],
      ["/v1", "Posted API"],
    ])
      expect(
        await (
          await fetch(`${s.api}/.well-known/oauth-protected-resource${path}`)
        ).json(),
      ).toEqual({
        resource: `${s.api}${path}`,
        authorization_servers: [s.api],
        scopes_supported: ["viewer", "member", "admin"],
        bearer_methods_supported: ["header"],
        resource_name: name,
      });
    expect(
      (await fetch(`${s.api}/.well-known/oauth-protected-resource/other`))
        .status,
    ).toBe(404);
    expect((await s.form("/oauth/register", {})).status).toBe(404);
  });

  it("refuses a missing or unknown client and an unregistered redirect without redirecting", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const { challenge } = pkce();
    const good = {
      response_type: "code",
      client_id: PUBLIC_CLIENT,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: s.resource,
      state: "xyz",
    };
    const shown = async (params: Record<string, string>) => {
      const response = await ada.authorize(params);
      expect(response.status).toBe(400);
      expect(response.headers.get("location")).toBeNull();
      return response.json();
    };
    const { client_id: _c, ...noClient } = good;
    void _c;
    expect(await shown(noClient)).toEqual({
      error: "invalid_request",
      error_description: "client_id is required.",
      iss: s.api,
    });
    expect(await shown({ ...good, client_id: "nobody" })).toMatchObject({
      error: "invalid_client",
      iss: s.api,
    });
    const { redirect_uri: _r, ...noRedirect } = good;
    void _r;
    expect(await shown(noRedirect)).toMatchObject({
      error: "invalid_request",
      iss: s.api,
    });
    for (const redirect of [
      "http://127.0.0.1/other",
      "https://evil.example.com/callback",
      "http://evil.example.com/callback",
      `${PUBLIC_REDIRECT}#x`,
      "http://localhost:7778/callback",
    ])
      expect(await shown({ ...good, redirect_uri: redirect })).toMatchObject({
        error: "invalid_request",
        error_description: "redirect_uri is not registered for this client.",
        iss: s.api,
      });
    expect(
      await shown({
        ...good,
        redirect_uri: "https://ci.example.com/oauth/callback",
      }),
    ).toMatchObject({ error: "invalid_request" });
    const repeated = await ada.browser.fetch(
      `${s.api}/oauth/authorize?${new URLSearchParams(good).toString()}&state=again`,
    );
    expect(repeated.status).toBe(400);
  });

  it("redirects every other error back to the client with state and iss", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const { challenge } = pkce();
    const good: Record<string, string> = {
      response_type: "code",
      client_id: PUBLIC_CLIENT,
      redirect_uri: "http://127.0.0.1:43123/callback",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: s.resource,
      state: "xyz",
    };
    const without = (key: string) =>
      Object.fromEntries(Object.entries(good).filter(([k]) => k !== key));
    const cases: [Record<string, string>, string][] = [
      [without("response_type"), "invalid_request"],
      [{ ...good, response_type: "token" }, "unsupported_response_type"],
      [without("code_challenge_method"), "invalid_request"],
      [{ ...good, code_challenge_method: "plain" }, "invalid_request"],
      [without("code_challenge"), "invalid_request"],
      [{ ...good, code_challenge: "short" }, "invalid_request"],
      [without("resource"), "invalid_target"],
      [{ ...good, resource: `${s.api}/other` }, "invalid_target"],
      [
        { ...good, resource: "https://elsewhere.example.com/mcp" },
        "invalid_target",
      ],
      [{ ...good, scope: "read write" }, "invalid_scope"],
    ];
    for (const [params, error] of cases) {
      const response = await ada.authorize(params);
      expect(response.status).toBe(302);
      const target = new URL(response.headers.get("location") ?? "");
      expect(target.origin + target.pathname).toBe(
        "http://127.0.0.1:43123/callback",
      );
      expect(Object.fromEntries(target.searchParams)).toEqual({
        error,
        error_description: expect.any(String),
        state: "xyz",
        iss: s.api,
      });
    }
    // The loopback port may vary: the good request goes on to consent.
    const ok = await ada.authorize(good);
    expect(new URL(ok.headers.get("location") ?? "").origin).toBe(WEB);
  });

  it("sends a person without a session to sign in, then to the consent page", async () => {
    const s = await stack();
    const { createBrowser } = await import("../../src/testing/index.js");
    const browser = createBrowser();
    const { challenge } = pkce();
    const query = new URLSearchParams({
      response_type: "code",
      client_id: PUBLIC_CLIENT,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: s.resource,
    });
    const first = await browser.fetch(
      `${s.api}/oauth/authorize?${query.toString()}`,
    );
    expect(first.status).toBe(302);
    const signIn = new URL(first.headers.get("location") ?? "");
    expect(signIn.origin + signIn.pathname).toBe(`${s.api}/auth/sign-in`);
    const returnTo = signIn.searchParams.get("returnTo") ?? "";
    expect(returnTo).toMatch(/^\/oauth\/consent\?request=/);
    s.mock.setLogin({ sub: "ada" });
    const landed = await browser.follow(signIn.href, {
      stopAt: (url) => url.origin === WEB,
    });
    expect(landed.url).toBe(`${WEB}${returnTo}`);
    const id = new URL(landed.url).searchParams.get("request") ?? "";
    const consent = await browser.fetch(`${s.api}/oauth/consent/${id}`, {
      headers: { origin: WEB },
    });
    expect(consent.status).toBe(200);
  });

  describe("client metadata documents", () => {
    const document = {
      client_id: CIMD,
      client_name: "Example Agent",
      redirect_uris: [CIMD_REDIRECT],
      logo_uri: "https://agent.example.com/logo.png",
      token_endpoint_auth_method: "none",
    };
    const request = (s: McpStack, extra: Record<string, string> = {}) => ({
      response_type: "code",
      client_id: CIMD,
      redirect_uri: CIMD_REDIRECT,
      code_challenge: pkce().challenge,
      code_challenge_method: "S256",
      resource: s.resource,
      ...extra,
    });

    it("accepts a document whose client_id is its URL, and caches it for its max-age, at most a day", async () => {
      const served = documents({
        [CIMD]: { body: document, cacheControl: "max-age=600" },
      });
      const s = await stack({ metadataFetch: served.options });
      const ada = await s.person("ada");
      const first = await ada.authorize(request(s));
      expect(new URL(first.headers.get("location") ?? "").origin).toBe(WEB);
      await ada.authorize(request(s));
      expect(served.calls).toEqual([CIMD]);
      s.advance(601);
      await ada.authorize(request(s));
      expect(served.calls).toEqual([CIMD, CIMD]);

      const id = new URL(
        (await ada.authorize(request(s))).headers.get("location") ?? "",
      ).searchParams.get("request");
      const consent = (await (
        await ada.call(`/oauth/consent/${id ?? ""}`)
      ).json()) as Record<string, unknown>;
      expect(consent.client).toEqual({
        id: CIMD,
        name: "Example Agent",
        logoUri: "https://agent.example.com/logo.png",
        kind: "metadata",
        redirectUri: CIMD_REDIRECT,
        redirectHost: "agent.example.com",
        localhost: false,
      });

      const long = documents({
        [CIMD]: { body: document, cacheControl: "max-age=9999999" },
      });
      const t = await stack({ metadataFetch: long.options });
      await (await t.person("ada")).authorize(request(t));
      const [row] = await rows<{ seconds: number }>(
        t,
        `SELECT extract(epoch FROM expires_at - now())::int AS "seconds"
         FROM {schema}.oauth_clients WHERE client_id = $1`,
        [CIMD],
      );
      expect(row?.seconds).toBeLessThanOrEqual(86400);
      expect(row?.seconds).toBeGreaterThan(86000);
    });

    it("refuses a document with another client_id, a redirect it does not list, or a private host", async () => {
      const mismatched = documents({
        [CIMD]: {
          body: {
            ...document,
            client_id: "https://agent.example.com/other.json",
          },
        },
      });
      const s = await stack({ metadataFetch: mismatched.options });
      const ada = await s.person("ada");
      const shown = async (params: Record<string, string>) => {
        const response = await ada.authorize(params);
        expect(response.status).toBe(400);
        return response.json();
      };
      expect(await shown(request(s))).toMatchObject({
        error: "invalid_client",
        error_description: expect.stringMatching(
          /client_id must equal the URL/,
        ),
        iss: s.api,
      });

      const listed = documents({ [CIMD]: { body: document } });
      const t = await stack({ metadataFetch: listed.options });
      const grace = await t.person("grace");
      const refused = await grace.authorize(
        request(t, {
          redirect_uri: "https://agent.example.com/other-callback",
        }),
      );
      expect(refused.status).toBe(400);
      expect(await refused.json()).toMatchObject({ error: "invalid_request" });

      const confidential = documents({
        [CIMD]: {
          body: {
            ...document,
            token_endpoint_auth_method: "client_secret_basic",
          },
        },
      });
      const u = await stack({ metadataFetch: confidential.options });
      expect(
        await (await (await u.person("ada")).authorize(request(u))).json(),
      ).toMatchObject({ error: "invalid_client" });

      const internal = documents({ [CIMD]: { body: document } }, "10.0.0.7");
      const v = await stack({ metadataFetch: internal.options });
      expect(
        await (await (await v.person("ada")).authorize(request(v))).json(),
      ).toMatchObject({
        error: "invalid_client",
        error_description: expect.stringMatching(/public address/),
      });
      expect(internal.calls).toEqual([]);

      // Not a document URL at all: a root path, or plain http.
      for (const clientId of [
        "https://agent.example.com/",
        "http://agent.example.com/c.json",
      ])
        expect(
          await (
            await (
              await v.person("ada")
            ).authorize(request(v, { client_id: clientId }))
          ).json(),
        ).toMatchObject({ error: "invalid_client" });
    });
  });

  it("registers clients dynamically only when legacy DCR is on", async () => {
    const s = await stack({ env: { POSTED_OAUTH_LEGACY_DCR: "true" } });
    const metadata = (await (
      await fetch(`${s.api}/.well-known/oauth-authorization-server`)
    ).json()) as Record<string, unknown>;
    expect(metadata.registration_endpoint).toBe(`${s.api}/oauth/register`);
    const registered = await fetch(`${s.api}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Old Client",
        redirect_uris: ["http://127.0.0.1/cb"],
      }),
    });
    expect(registered.status).toBe(201);
    const body = (await registered.json()) as { client_id: string };
    expect(body).toMatchObject({
      client_id: expect.stringMatching(/^dcr_/),
      token_endpoint_auth_method: "none",
    });
    const ada = await s.person("ada");
    const tokens = await ada.tokens({
      client: body.client_id,
      redirectUri: "http://127.0.0.1:9999/cb",
    });
    expect((await s.bearer("/mcp", tokens.access_token)).status).toBe(200);
    const bad = await fetch(`${s.api}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Bad",
        redirect_uris: ["http://evil.example/cb"],
      }),
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({
      error: "invalid_client_metadata",
    });

    // Turned off, the registered client stops resolving.
    const off = await stack();
    expect((await off.form("/oauth/register", {})).status).toBe(404);
    expect(CONFIDENTIAL_CLIENT).toBeDefined();
  });
});
