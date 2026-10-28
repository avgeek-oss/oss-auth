import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AUTH_ERROR_CODES as CORE_CODES,
  AuthRequestError,
  loadAuthConfig,
  type AuthRequestErrorCode,
} from "@avgeek-oss/auth-core";
import { fromPg, migrate, quoteIdent } from "@avgeek-oss/auth-core/postgres";
import {
  createBrowser,
  startMockProvider,
  type Browser,
  type MockProvider,
} from "@avgeek-oss/auth-core/testing";
import {
  AUTH_ERROR_CODES,
  AuthClientError,
  createAuthClient,
  readAuthRedirectError,
  type ApiKey,
  type AuthClient,
  type AuthSession,
  type ConnectedApp,
  type ConsentRequest,
  type FetchLike,
  type IssuedApiKey,
  type Role,
} from "@avgeek-oss/auth-client";
import { createExampleApp } from "../src/app.ts";

// The contract between @avgeek-oss/auth-client and the auth API: the client
// against the reference app's real API, the mock provider and Postgres. If
// auth-core changes a JSON shape, a path or an error, this fails.

const databaseUrl = process.env.AUTH_TEST_DATABASE_URL;
const WEB = "http://localhost:5173";

// ---------------------------------------------------------------------------
// Shapes. Each is typed against the client's wire type, so a field added to
// or removed from a type must be added here too; at run time the server's
// JSON must have exactly these fields, of these kinds.

type Kind =
  | "string"
  | "string|null"
  | "number"
  | "boolean"
  | "role"
  | "role|null"
  | "string[]"
  | "object"
  | "object|null";
type Shape<T> = { readonly [K in keyof T]-?: Kind | Shape<T[K]> };

const ROLE_SET = new Set<unknown>(["viewer", "member", "admin"]);
function matches(value: unknown, kind: Kind): boolean {
  switch (kind) {
    case "string":
      return typeof value === "string";
    case "string|null":
      return value === null || typeof value === "string";
    case "number":
      return typeof value === "number";
    case "boolean":
      return typeof value === "boolean";
    case "role":
      return ROLE_SET.has(value);
    case "role|null":
      return value === null || ROLE_SET.has(value);
    case "string[]":
      return Array.isArray(value) && value.every((v) => typeof v === "string");
    case "object":
      return (
        typeof value === "object" && value !== null && !Array.isArray(value)
      );
    case "object|null":
      return value === null || matches(value, "object");
  }
}

/** Asserts `value` has exactly `shape`'s fields, recursively. */
function expectShape<T>(value: T, shape: Shape<T>, path = "body"): void {
  expect(typeof value, path).toBe("object");
  const record = value as Record<string, unknown>;
  expect(Object.keys(record).sort(), path).toEqual(Object.keys(shape).sort());
  for (const [key, expected] of Object.entries(shape) as [
    string,
    Kind | object,
  ][]) {
    if (typeof expected === "string")
      expect(
        matches(record[key], expected),
        `${path}.${key}: ${JSON.stringify(record[key])} is not ${expected}`,
      ).toBe(true);
    else expectShape(record[key], expected as Shape<unknown>, `${path}.${key}`);
  }
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const SESSION_SHAPE: Shape<AuthSession> = {
  user: {
    id: "string",
    role: "role",
    email: "string|null",
    displayName: "string|null",
  },
  role: "role",
  ext: "object",
  session: { authenticatedAt: "string", expiresAt: "string", amr: "string[]" },
};
const API_KEY_SHAPE: Shape<ApiKey> = {
  id: "string",
  name: "string",
  ceiling: "role",
  workspace: "string|null",
  createdAt: "string",
  expiresAt: "string|null",
  lastUsedAt: "string|null",
  replacedBy: "string|null",
  graceUntil: "string|null",
};
const ISSUED_SHAPE: Shape<IssuedApiKey> = {
  key: "string",
  apiKey: API_KEY_SHAPE,
};
const APP_SHAPE: Shape<ConnectedApp> = {
  id: "string",
  clientId: "string",
  clientName: "string",
  logoUri: "string|null",
  ceiling: "role",
  resources: "string[]",
  restrictions: "object|null",
  createdAt: "string",
  lastUsedAt: "string|null",
};
const CONSENT_SHAPE: Shape<ConsentRequest> = {
  client: {
    id: "string",
    name: "string",
    logoUri: "string|null",
    kind: "string",
    redirectUri: "string",
    redirectHost: "string",
    localhost: "boolean",
  },
  resource: { uri: "string", name: "string|null" },
  scope: "role|null",
  ceilings: "string[]",
  defaultCeiling: "role",
  expiresAt: "string",
};

// ---------------------------------------------------------------------------
// The stack: two instances of the reference app (the second with a tight
// limit on API key writes), one mock provider and one database.

interface Instance {
  api: string;
  server: Server;
  schema: string;
}

const failure = async (promise: Promise<unknown>): Promise<AuthClientError> => {
  const outcome = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(outcome).toBeInstanceOf(AuthClientError);
  return outcome as AuthClientError;
};

describe.skipIf(!databaseUrl)("auth-client against the reference app", () => {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  const sql = fromPg(pool);
  const stamp = Date.now();
  let mock: MockProvider;
  let main: Instance;
  let limited: Instance;

  async function listen(): Promise<{ server: Server; api: string }> {
    const server = createServer();
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    return {
      server,
      api: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    };
  }

  async function start(
    instance: { server: Server; api: string },
    schema: string,
    env: Record<string, string> = {},
  ): Promise<Instance> {
    const config = loadAuthConfig("example", {
      EXAMPLE_SECRET: "e".repeat(32),
      EXAMPLE_OIDC_ISSUER: mock.issuer,
      EXAMPLE_OIDC_CLIENT_ID: mock.clientId,
      EXAMPLE_OIDC_CLIENT_SECRET: mock.clientSecret,
      EXAMPLE_OIDC_ROLE_CLAIMS: "groups",
      EXAMPLE_OIDC_ROLE_MAP: JSON.stringify({
        "example-admins": "admin",
        "example-members": "member",
      }),
      EXAMPLE_OIDC_SCOPES: "openid email profile groups",
      EXAMPLE_WEB_ORIGIN: WEB,
      EXAMPLE_API_ORIGIN: instance.api,
      EXAMPLE_AUTH_SCHEMA: schema,
      EXAMPLE_OAUTH_CLIENTS: JSON.stringify([
        {
          client_id: "example-cli",
          client_name: "Example CLI",
          redirect_uris: ["http://127.0.0.1/callback"],
        },
      ]),
      ...env,
    });
    await migrate(sql, { schema });
    const { app } = createExampleApp({ config, sql });
    instance.server.on("request", getRequestListener(app.fetch));
    return { ...instance, schema };
  }

  beforeAll(async () => {
    const a = await listen();
    const b = await listen();
    mock = await startMockProvider({
      users: [
        {
          sub: "ada",
          email: "ada@example.com",
          name: "Ada",
          groups: ["example-admins"],
        },
        {
          sub: "grace",
          email: "grace@example.com",
          name: "Grace",
          groups: ["example-members"],
        },
        { sub: "eve", email: "eve@example.com", name: "Eve", groups: [] },
      ],
      redirectUris: [`${a.api}/auth/callback`, `${b.api}/auth/callback`],
      postLogoutRedirectUris: [`${WEB}/`],
    });
    main = await start(a, `example_client_${stamp}`);
    limited = await start(b, `example_client_limits_${stamp}`, {
      EXAMPLE_RATE_LIMITS: JSON.stringify({
        "api-keys.write": { limit: 2, periodSeconds: 60 },
      }),
    });
  });
  afterAll(async () => {
    await mock.close();
    for (const instance of [main, limited]) {
      instance.server.closeAllConnections();
      await new Promise<void>((resolve) =>
        instance.server.close(() => resolve()),
      );
      await sql.query(
        `DROP SCHEMA IF EXISTS ${quoteIdent(instance.schema)} CASCADE`,
      );
    }
    await pool.end();
  });

  /** A page on the web origin: a cookie jar, and a client that records its requests. */
  function page(instance = main, origin = WEB, csrfHeader?: string) {
    const browser = createBrowser();
    const sent: {
      method: string;
      url: string;
      headers: Record<string, string>;
    }[] = [];
    // The browser adds Origin to a cross-origin request; the cookie jar
    // stands in for credentials: "include".
    const fetch: FetchLike = (url, init) => {
      sent.push({ method: init.method ?? "GET", url, headers: init.headers });
      expect(init.credentials).toBe("include");
      return browser.fetch(url, {
        ...init,
        headers: { ...init.headers, origin },
      });
    };
    const client = createAuthClient({
      apiOrigin: instance.api,
      fetch,
      ...(csrfHeader ? { csrfHeader } : {}),
    });
    return { browser, client, sent };
  }

  const toWeb = (url: URL) => url.origin === WEB;

  async function signIn(
    p: { browser: Browser; client: AuthClient },
    sub: string,
    options: { authTime?: number; returnTo?: string } = {},
  ) {
    mock.setLogin({
      sub,
      amr: ["mfa"],
      ...(options.authTime ? { authTime: options.authTime } : {}),
    });
    return p.browser.follow(p.client.signInUrl(options.returnTo ?? "/"), {
      stopAt: toWeb,
    });
  }

  it("has the same error codes as auth-core's request errors", () => {
    const requestCodes = CORE_CODES.filter(
      (code) =>
        new AuthRequestError(code as AuthRequestErrorCode, "").status !==
        undefined,
    );
    expect([...AUTH_ERROR_CODES].sort()).toEqual([...requestCodes].sort());
  });

  it("signs in to returnTo, reads the session, and signs out", async () => {
    const p = page();
    expect(await p.client.getSession()).toBeNull();
    const landed = await signIn(p, "ada", {
      returnTo: "/settings?tab=keys#new",
    });
    expect(landed.url).toBe(`${WEB}/settings?tab=keys#new`);
    const session = await p.client.getSession();
    expect(session).not.toBeNull();
    expectShape(session, SESSION_SHAPE);
    expect(session).toMatchObject({
      user: { role: "admin", email: "ada@example.com", displayName: "Ada" },
      role: "admin",
      ext: {},
      session: { amr: ["mfa"] },
    });
    expect(session?.session.authenticatedAt).toMatch(ISO);
    expect(session?.session.expiresAt).toMatch(ISO);

    const logout = await p.client.signOut();
    expect(logout?.startsWith(mock.issuer)).toBe(true);
    expect(await p.client.getSession()).toBeNull();
    // Signing out without a session still answers.
    expect(typeof (await p.client.signOut())).toBe("string");
  });

  it("sends the CSRF header on every request but GET, and the API needs it", async () => {
    const p = page();
    await signIn(p, "grace");
    await p.client.apiKeys.list();
    const { apiKey } = await p.client.apiKeys.create({
      name: "csrf",
      ceiling: "viewer",
    });
    await p.client.apiKeys.revoke(apiKey.id);
    expect(
      p.sent.map((r) => [r.method, "x-requested-with" in r.headers]),
    ).toEqual([
      ["GET", false],
      ["POST", true],
      ["DELETE", true],
    ]);
    // Without the header, the same request is refused.
    const bare = await p.browser.fetch(`${main.api}/auth/api-keys`, {
      method: "POST",
      headers: { origin: WEB, "content-type": "application/json" },
      body: JSON.stringify({ name: "x", ceiling: "viewer" }),
    });
    expect(bare.status).toBe(403);
    // A client set up with another header name gets the same refusal, typed.
    const wrong = page(main, WEB, "x-csrf-token");
    await signIn(wrong, "grace");
    expect(
      await failure(
        wrong.client.apiKeys.create({ name: "x", ceiling: "viewer" }),
      ),
    ).toMatchObject({ code: "csrf_header_missing", status: 403 });
    // And a page on another origin is refused whatever it sends.
    const elsewhere = page(main, "https://evil.example");
    await signIn(elsewhere, "grace");
    expect(await failure(elsewhere.client.signOut())).toMatchObject({
      code: "origin_invalid",
      status: 403,
    });
  });

  it("manages API keys: create, list, rotate with grace, revoke", async () => {
    const p = page();
    await signIn(p, "grace");
    const issued = await p.client.apiKeys.create({
      name: "CI",
      ceiling: "member",
      expiresInSeconds: 86400,
    });
    expectShape(issued, ISSUED_SHAPE);
    expect(issued.key.startsWith("example_")).toBe(true);
    expect(issued.apiKey).toMatchObject({
      name: "CI",
      ceiling: "member",
      workspace: null,
    });
    expect(issued.apiKey.createdAt).toMatch(ISO);

    // The key works as a bearer credential.
    const me = await fetch(`${main.api}/api/me`, {
      headers: { authorization: `Bearer ${issued.key}` },
    });
    expect(await me.json()).toEqual({ name: "Grace", role: "member" });

    const listed = await p.client.apiKeys.list();
    expect(listed.map((k) => k.id)).toContain(issued.apiKey.id);
    for (const key of listed) expectShape(key, API_KEY_SHAPE);

    const rotated = await p.client.apiKeys.rotate(issued.apiKey.id, {
      graceSeconds: 3600,
    });
    expectShape(rotated, ISSUED_SHAPE);
    expect(rotated.key).not.toBe(issued.key);
    const old = (await p.client.apiKeys.list()).find(
      (k) => k.id === issued.apiKey.id,
    );
    expect(old).toMatchObject({ replacedBy: rotated.apiKey.id });
    expect(old?.graceUntil).toMatch(ISO);

    expect(await p.client.apiKeys.revoke(rotated.apiKey.id)).toBeUndefined();
    expect((await p.client.apiKeys.list()).map((k) => k.id)).not.toContain(
      rotated.apiKey.id,
    );
    expect(
      await failure(p.client.apiKeys.revoke(rotated.apiKey.id)),
    ).toMatchObject({ code: "not_found", status: 404 });
    expect(
      await failure(
        p.client.apiKeys.create({ name: "x", ceiling: "owner" as Role }),
      ),
    ).toMatchObject({ code: "invalid_request", status: 400 });
  });

  it("asks for step-up on an admin key, and succeeds after the round trip", async () => {
    const p = page();
    // Signed in 20 minutes ago at the provider: too long for an admin key.
    await signIn(p, "ada", { authTime: Math.floor(Date.now() / 1000) - 1200 });
    const refused = await failure(
      p.client.apiKeys.create({ name: "admin", ceiling: "admin" }),
    );
    expect(refused).toMatchObject({ code: "step_up_required", status: 401 });
    expect(refused.stepUpUrl).toBe(p.client.stepUpUrl());
    expect(Object.keys(refused.details)).toEqual(["stepUpUrl"]);

    // What useStepUp does: the client's step-up URL with the page as returnTo.
    mock.setLogin({ sub: "ada", amr: ["mfa"] });
    const back = await p.browser.follow(
      p.client.stepUpUrl("/settings/keys?new=admin"),
      {
        stopAt: toWeb,
      },
    );
    expect(back.url).toBe(`${WEB}/settings/keys?new=admin`);
    const issued = await p.client.apiKeys.create({
      name: "admin",
      ceiling: "admin",
    });
    expect(issued.apiKey.ceiling).toBe("admin");
  });

  it("reports failed sign-ins and step-ups on the page's URL", async () => {
    const eve = page();
    const denied = await signIn(eve, "eve");
    expect(readAuthRedirectError(denied.url)).toEqual({
      code: "sign_in_denied",
      reason: "no_role",
    });
    expect(await eve.client.getSession()).toBeNull();

    const ada = page();
    await signIn(ada, "ada");
    mock.setLogin({ sub: "ada", amr: ["pwd"] });
    const failed = await ada.browser.follow(ada.client.stepUpUrl("/"), {
      stopAt: toWeb,
    });
    expect(readAuthRedirectError(failed.url)).toEqual({
      code: "step_up_failed",
      reason: "mfa_missing",
    });
  });

  it("answers rate limits with rate_limited and retryAfterSeconds", async () => {
    const p = page(limited);
    await signIn(p, "grace");
    await p.client.apiKeys.create({ name: "1", ceiling: "viewer" });
    await p.client.apiKeys.create({ name: "2", ceiling: "viewer" });
    const error = await failure(
      p.client.apiKeys.create({ name: "3", ceiling: "viewer" }),
    );
    expect(error).toMatchObject({ code: "rate_limited", status: 429 });
    expect(error.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(error.retryAfterSeconds).toBeLessThanOrEqual(30);
    expect(error.message).toMatch(/Too many requests/);
  });

  it("drives consent, then lists and disconnects the connected app", async () => {
    const p = page();
    await signIn(p, "grace");
    const authorize = async (state: string) => {
      const verifier = randomBytes(32).toString("base64url");
      const query = new URLSearchParams({
        response_type: "code",
        client_id: "example-cli",
        redirect_uri: "http://127.0.0.1:47123/callback",
        code_challenge: createHash("sha256")
          .update(verifier)
          .digest("base64url"),
        code_challenge_method: "S256",
        resource: `${main.api}/mcp`,
        scope: "member",
        state,
      });
      const consent = await p.browser.follow(
        `${main.api}/oauth/authorize?${query}`,
        {
          stopAt: toWeb,
        },
      );
      const url = new URL(consent.url);
      expect(url.pathname).toBe("/oauth/consent");
      return url.searchParams.get("request") ?? "";
    };

    const id = await authorize("s1");
    const request = await p.client.consent.get(id);
    expectShape(request, CONSENT_SHAPE);
    expect(request).toMatchObject({
      client: {
        id: "example-cli",
        name: "Example CLI",
        kind: "configured",
        redirectHost: "127.0.0.1:47123",
        localhost: true,
      },
      resource: { uri: `${main.api}/mcp`, name: "Reference app MCP" },
      scope: "member",
      ceilings: ["viewer", "member"],
      defaultCeiling: "member",
    });

    const approved = await p.client.consent.decide(id, {
      approve: true,
      ceiling: "viewer",
    });
    expect(Object.keys(approved)).toEqual(["redirectUri"]);
    const back = new URL(approved.redirectUri);
    expect(back.origin + back.pathname).toBe("http://127.0.0.1:47123/callback");
    expect(back.searchParams.get("state")).toBe("s1");
    expect(back.searchParams.get("iss")).toBe(main.api);
    expect(back.searchParams.get("code")).toBeTruthy();
    // A request is decided once.
    expect(await failure(p.client.consent.get(id))).toMatchObject({
      code: "not_found",
    });
    // Above the person's role: refused.
    const high = await authorize("s2");
    expect(
      await failure(
        p.client.consent.decide(high, { approve: true, ceiling: "admin" }),
      ),
    ).toMatchObject({ code: "forbidden", status: 403 });
    const denied = await p.client.consent.decide(high, { approve: false });
    expect(new URL(denied.redirectUri).searchParams.get("error")).toBe(
      "access_denied",
    );

    const apps = await p.client.connectedApps.list();
    expect(apps).toHaveLength(1);
    for (const app of apps) expectShape(app, APP_SHAPE);
    expect(apps[0]).toMatchObject({
      clientId: "example-cli",
      clientName: "Example CLI",
      ceiling: "viewer",
      resources: [`${main.api}/mcp`],
      restrictions: null,
      lastUsedAt: null,
    });
    expect(
      await p.client.connectedApps.revoke(apps[0]?.id ?? ""),
    ).toBeUndefined();
    expect(await p.client.connectedApps.list()).toEqual([]);
    expect(
      await failure(p.client.connectedApps.revoke(apps[0]?.id ?? "")),
    ).toMatchObject({
      code: "not_found",
    });
  });

  it("lets admins list and revoke other people's keys and connected apps, and nobody else", async () => {
    const grace = page();
    await signIn(grace, "grace");
    const graceId = (await grace.client.getSession())?.user.id ?? "";
    const { apiKey } = await grace.client.apiKeys.create({
      name: "for admin",
      ceiling: "viewer",
    });
    const ada = page();
    await signIn(ada, "ada");
    const adaId = (await ada.client.getSession())?.user.id ?? "";

    const keys = await ada.client.admin.apiKeys.list(graceId);
    expect(keys.map((k) => k.id)).toContain(apiKey.id);
    for (const key of keys) expectShape(key, API_KEY_SHAPE);
    expect(await ada.client.admin.connectedApps.list(graceId)).toEqual([]);
    await ada.client.admin.apiKeys.revoke(apiKey.id);
    expect((await grace.client.apiKeys.list()).map((k) => k.id)).not.toContain(
      apiKey.id,
    );

    expect(await failure(grace.client.admin.apiKeys.list(adaId))).toMatchObject(
      {
        code: "forbidden",
        status: 403,
      },
    );
    expect(
      await failure(grace.client.admin.connectedApps.list(adaId)),
    ).toMatchObject({
      code: "forbidden",
    });
    expect(
      await failure(ada.client.admin.apiKeys.list("not-a-uuid")),
    ).toMatchObject({
      code: "invalid_request",
    });
  });

  it("is unauthenticated everywhere without a session", async () => {
    const p = page();
    for (const call of [
      () => p.client.apiKeys.list(),
      () => p.client.apiKeys.create({ name: "x", ceiling: "viewer" }),
      () => p.client.connectedApps.list(),
      () => p.client.consent.get("x"),
    ])
      expect(await failure(call())).toMatchObject({
        code: "unauthenticated",
        status: 401,
      });
  });
});
