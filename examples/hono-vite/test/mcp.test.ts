import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
import {
  auth,
  type OAuthClientProvider,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  OAuthClientInformationMixed,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadAuthConfig } from "@avgeek-oss/auth-core";
import { fromPg, migrate, quoteIdent } from "@avgeek-oss/auth-core/postgres";
import {
  createBrowser,
  startMockProvider,
  type MockProvider,
} from "@avgeek-oss/auth-core/testing";
import { createExampleApp } from "../src/app.ts";

const databaseUrl = process.env.AUTH_TEST_DATABASE_URL;
const WEB = "http://localhost:5173";
// Registered as http://127.0.0.1/callback; a native client picks its port.
const REDIRECT = "http://127.0.0.1:47123/callback";

/** An in-memory OAuth client for the SDK: a pre-registered public client. */
class TestClientProvider implements OAuthClientProvider {
  readonly authorizations: URL[] = [];
  private saved: OAuthTokens | undefined;
  private verifier = "";
  private info: OAuthClientInformationMixed = { client_id: "example-cli" };

  get redirectUrl() {
    return REDIRECT;
  }
  get clientMetadata() {
    return { client_name: "SDK test", redirect_uris: [REDIRECT] };
  }
  clientInformation() {
    return this.info;
  }
  saveClientInformation(info: OAuthClientInformationMixed) {
    this.info = info;
  }
  tokens() {
    return this.saved;
  }
  saveTokens(tokens: OAuthTokens) {
    this.saved = tokens;
  }
  redirectToAuthorization(url: URL) {
    this.authorizations.push(url);
  }
  saveCodeVerifier(verifier: string) {
    this.verifier = verifier;
  }
  codeVerifier() {
    return this.verifier;
  }
}

// The MCP SDK's own OAuth client against the reference app and the mock
// OpenID provider: discovery, a pre-registered client, PKCE, consent, a
// tool call, refresh and revocation.
describe.skipIf(!databaseUrl)("reference app with an MCP client", () => {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  const sql = fromPg(pool);
  const schema = `example_mcp_${Date.now()}`;
  const server = createServer();
  let api = "";
  let mock: MockProvider;

  beforeAll(async () => {
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    api = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    mock = await startMockProvider({
      users: [
        {
          sub: "ada",
          email: "ada@example.com",
          name: "Ada",
          groups: ["example-admins"],
        },
      ],
      redirectUris: [`${api}/auth/callback`],
      postLogoutRedirectUris: [`${WEB}/`],
    });
    const config = loadAuthConfig("example", {
      EXAMPLE_SECRET: "e".repeat(32),
      EXAMPLE_OIDC_ISSUER: mock.issuer,
      EXAMPLE_OIDC_CLIENT_ID: mock.clientId,
      EXAMPLE_OIDC_CLIENT_SECRET: mock.clientSecret,
      EXAMPLE_OIDC_ROLE_CLAIMS: "groups",
      EXAMPLE_OIDC_ROLE_MAP: JSON.stringify({ "example-admins": "admin" }),
      EXAMPLE_OIDC_SCOPES: "openid email profile groups",
      EXAMPLE_WEB_ORIGIN: WEB,
      EXAMPLE_API_ORIGIN: api,
      EXAMPLE_AUTH_SCHEMA: schema,
      EXAMPLE_OAUTH_CLIENTS: JSON.stringify([
        {
          client_id: "example-cli",
          client_name: "Example CLI",
          redirect_uris: ["http://127.0.0.1/callback"],
        },
      ]),
    });
    await migrate(sql, { schema });
    const { app } = createExampleApp({ config, sql });
    server.on("request", getRequestListener(app.fetch));
  });
  afterAll(async () => {
    await mock.close();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await sql.query(`DROP SCHEMA IF EXISTS ${quoteIdent(schema)} CASCADE`);
    await pool.end();
  });

  it("authorizes, calls a tool, refreshes and is revoked", async () => {
    const mcpUrl = new URL(`${api}/mcp`);
    const provider = new TestClientProvider();

    // 1. Unauthenticated: the SDK discovers the server from the 401 and
    //    asks for the person to authorize.
    const first = new Client({ name: "sdk-test", version: "1.0.0" });
    await expect(
      first.connect(
        new StreamableHTTPClientTransport(mcpUrl, { authProvider: provider }),
      ),
    ).rejects.toThrow();
    expect(provider.authorizations).toHaveLength(1);
    const authorizeUrl = provider.authorizations[0] ?? new URL(api);
    expect(authorizeUrl.origin + authorizeUrl.pathname).toBe(
      `${api}/oauth/authorize`,
    );
    expect(Object.fromEntries(authorizeUrl.searchParams)).toMatchObject({
      response_type: "code",
      client_id: "example-cli",
      redirect_uri: REDIRECT,
      code_challenge_method: "S256",
      resource: `${api}/mcp`,
    });

    // 2. The person signs in at the provider and approves on the consent
    //    page; the test plays the page.
    const browser = createBrowser();
    mock.setLogin({ sub: "ada", amr: ["mfa"] });
    const toWeb = (url: URL) => url.origin === WEB;
    const atConsent = await browser.follow(authorizeUrl.href, {
      stopAt: toWeb,
    });
    const page = new URL(atConsent.url);
    expect(page.pathname).toBe("/oauth/consent");
    const consentApi = `${api}/oauth/consent/${page.searchParams.get("request") ?? ""}`;
    const shown = (await (
      await browser.fetch(consentApi, { headers: { origin: WEB } })
    ).json()) as {
      client: { name: string; redirectHost: string; localhost: boolean };
    };
    expect(shown.client).toMatchObject({
      name: "Example CLI",
      redirectHost: "127.0.0.1:47123",
      localhost: true,
    });
    const decided = (await (
      await browser.fetch(consentApi, {
        method: "POST",
        headers: {
          origin: WEB,
          "x-requested-with": "fetch",
          "content-type": "application/json",
        },
        body: JSON.stringify({ decision: "approve", ceiling: "member" }),
      })
    ).json()) as { redirectUri: string };
    const callback = new URL(decided.redirectUri);
    expect(callback.origin + callback.pathname).toBe(REDIRECT);
    // RFC 9207: the client checks iss before redeeming the code.
    expect(callback.searchParams.get("iss")).toBe(api);
    const code = callback.searchParams.get("code") ?? "";

    // 3. The SDK redeems the code with its verifier, then connects.
    await new StreamableHTTPClientTransport(mcpUrl, {
      authProvider: provider,
    }).finishAuth(code);
    const issued = provider.tokens();
    expect(issued).toMatchObject({ token_type: "Bearer", scope: "member" });
    const client = new Client({ name: "sdk-test", version: "1.0.0" });
    await client.connect(
      new StreamableHTTPClientTransport(mcpUrl, { authProvider: provider }),
    );
    expect((await client.listTools()).tools.map((t) => t.name)).toEqual([
      "echo",
      "whoami",
    ]);
    expect(
      await client.callTool({ name: "echo", arguments: { text: "hello" } }),
    ).toMatchObject({ content: [{ type: "text", text: "hello" }] });
    expect(
      await client.callTool({ name: "whoami", arguments: {} }),
    ).toMatchObject({
      content: [{ type: "text", text: "Ada (member)" }],
    });

    // 4. Refresh: the SDK rotates the refresh token, and calls keep working.
    expect(await auth(provider, { serverUrl: mcpUrl })).toBe("AUTHORIZED");
    const refreshed = provider.tokens();
    expect(refreshed?.refresh_token).not.toBe(issued?.refresh_token);
    expect(refreshed?.access_token).not.toBe(issued?.access_token);
    expect(
      await client.callTool({ name: "echo", arguments: { text: "again" } }),
    ).toMatchObject({ content: [{ type: "text", text: "again" }] });

    // 5. Revocation: the family ends, the refresh fails, and the SDK falls
    //    back to asking for a new authorization.
    const revoked = await fetch(`${api}/oauth/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: refreshed?.refresh_token ?? "",
        client_id: "example-cli",
      }).toString(),
    });
    expect(revoked.status).toBe(200);
    await expect(
      client.callTool({ name: "echo", arguments: { text: "late" } }),
    ).rejects.toThrow();
    expect(provider.authorizations).toHaveLength(2);
    await client.close();
  });
});
