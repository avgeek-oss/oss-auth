import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
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

// The whole flow through the reference app's API, as the page drives it.
describe.skipIf(!databaseUrl)("reference app", () => {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  const sql = fromPg(pool);
  const schema = `example_${Date.now()}`;
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
      backchannelLogoutUri: `${api}/auth/backchannel-logout`,
    });
    const config = loadAuthConfig("example", {
      EXAMPLE_SECRET: "e".repeat(32),
      // The self-check has its own tests; here it would only add noise.
      EXAMPLE_SELF_CHECK: "false",
      EXAMPLE_OIDC_ISSUER: mock.issuer,
      EXAMPLE_OIDC_CLIENT_ID: mock.clientId,
      EXAMPLE_OIDC_CLIENT_SECRET: mock.clientSecret,
      EXAMPLE_OIDC_ROLE_CLAIMS: "groups",
      EXAMPLE_OIDC_ROLE_MAP: JSON.stringify({ "example-admins": "admin" }),
      EXAMPLE_OIDC_SCOPES: "openid email profile groups",
      EXAMPLE_WEB_ORIGIN: WEB,
      EXAMPLE_API_ORIGIN: api,
      EXAMPLE_AUTH_SCHEMA: schema,
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

  it("signs in, steps up for the sensitive action and signs out", async () => {
    const browser = createBrowser();
    const page = { origin: WEB, "x-requested-with": "fetch" };
    const toWeb = (url: URL) => url.origin === WEB;

    expect((await browser.fetch(`${api}/api/me`)).status).toBe(401);

    mock.setLogin({
      sub: "ada",
      amr: ["mfa"],
      authTime: Math.floor(Date.now() / 1000) - 120,
    });
    const signedIn = await browser.follow(`${api}/auth/sign-in?returnTo=/`, {
      stopAt: toWeb,
    });
    expect(signedIn.url).toBe(`${WEB}/`);
    expect(await (await browser.fetch(`${api}/api/me`)).json()).toEqual({
      name: "Ada",
      role: "admin",
    });

    // Signed in two minutes ago at the provider: too old for this action.
    const refused = await browser.fetch(`${api}/api/sensitive`, {
      method: "POST",
      headers: page,
    });
    expect(refused.status).toBe(401);
    const { error } = (await refused.json()) as {
      error: { code: string; stepUpUrl: string };
    };
    expect(error.code).toBe("step_up_required");

    mock.setLogin({ sub: "ada", amr: ["mfa"] });
    const steppedUp = await browser.follow(`${error.stepUpUrl}?returnTo=/`, {
      stopAt: toWeb,
    });
    expect(steppedUp.url).toBe(`${WEB}/`);
    const done = await browser.fetch(`${api}/api/sensitive`, {
      method: "POST",
      headers: page,
    });
    expect(done.status).toBe(200);
    expect(await done.json()).toMatchObject({ done: true });

    const out = await browser.fetch(`${api}/auth/sign-out`, {
      method: "POST",
      headers: page,
    });
    const { endSessionUrl } = (await out.json()) as { endSessionUrl: string };
    expect(endSessionUrl.startsWith(mock.issuer)).toBe(true);
    expect((await browser.fetch(`${api}/api/me`)).status).toBe(401);
  });
});
