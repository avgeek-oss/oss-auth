import { afterEach, describe, expect, it } from "vitest";
import type { MetadataFetchOptions } from "../../src/mcp/index.js";
import { createScim } from "../../src/scim/index.js";
import { databaseUrl } from "../postgres/support.js";
import { rows, startStack, type Stack } from "../hono/support.js";
import {
  CONFIDENTIAL_CLIENT,
  CONFIDENTIAL_SECRET,
  PUBLIC_CLIENT,
  PUBLIC_REDIRECT,
  pkce,
  startMcp,
  type McpStack,
} from "../mcp/support.js";

const stacks: Stack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});
async function mcp(
  limits: Record<string, unknown>,
  extra: Parameters<typeof startMcp>[0] = {},
): Promise<McpStack> {
  const s = await startMcp({
    ...extra,
    env: { POSTED_RATE_LIMITS: JSON.stringify(limits), ...extra.env },
  });
  stacks.push(s);
  return s;
}
const per = (limit: number, periodSeconds = 60) => ({ limit, periodSeconds });

/** Asserts a 429 in the expected shape and returns its body. */
async function limited(
  response: Response,
  shape: "json" | "oauth" | "scim" | "plain",
) {
  expect(response.status).toBe(429);
  expect(response.headers.get("retry-after")).toMatch(/^[1-9]\d*$/);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("location")).toBeNull();
  const text = await response.text();
  if (shape === "plain") {
    expect(response.headers.get("content-type")).toMatch(/^text\/plain/);
    expect(text).toMatch(/Too many requests/);
    return text;
  }
  const body = JSON.parse(text) as Record<string, unknown>;
  if (shape === "json")
    expect(body).toEqual({
      error: {
        code: "rate_limited",
        message: expect.stringMatching(/Too many/),
      },
    });
  if (shape === "oauth")
    expect(body).toEqual({
      error: "temporarily_unavailable",
      error_description: expect.stringMatching(/Too many/),
    });
  if (shape === "scim") {
    expect(response.headers.get("content-type")).toMatch(
      /^application\/scim\+json/,
    );
    expect(body).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "429",
      detail: expect.stringMatching(/Too many/),
    });
  }
  return body;
}

const authorizeQuery = (s: McpStack, extra: Record<string, string> = {}) =>
  new URLSearchParams({
    response_type: "code",
    client_id: PUBLIC_CLIENT,
    redirect_uri: PUBLIC_REDIRECT,
    code_challenge: pkce().challenge,
    code_challenge_method: "S256",
    resource: s.resource,
    ...extra,
  }).toString();

describe.skipIf(!databaseUrl)("rate limits over HTTP", () => {
  it("limits sign-in, callback and step-up together with a plain 429, then recovers", async () => {
    const s = await mcp({ oidc: per(3) });
    for (let i = 0; i < 3; i++)
      expect(
        (await fetch(`${s.api}/auth/sign-in`, { redirect: "manual" })).status,
      ).toBe(302);
    for (const path of [
      "/auth/sign-in",
      "/auth/callback?code=x&state=y",
      "/auth/step-up",
    ]) {
      const response = await fetch(`${s.api}${path}`, { redirect: "manual" });
      await limited(response, "plain");
      expect(response.headers.get("retry-after")).toBe("20");
    }
    s.advance(20);
    expect(
      (await fetch(`${s.api}/auth/sign-in`, { redirect: "manual" })).status,
    ).toBe(302);
    expect(
      (await fetch(`${s.api}/auth/sign-in`, { redirect: "manual" })).status,
    ).toBe(429);
  });

  it("limits back-channel logout with JSON", async () => {
    const s = await mcp({ "oidc.backchannel-logout": per(2) });
    const post = () =>
      fetch(`${s.api}/auth/backchannel-logout`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "logout_token=x",
      });
    expect((await post()).status).toBe(400);
    expect((await post()).status).toBe(400);
    await limited(await post(), "json");
  });

  it("limits /oauth/authorize with a plain 429, never a redirect", async () => {
    const s = await mcp({ "oauth.authorize": per(2) });
    const ada = await s.person("ada");
    for (let i = 0; i < 2; i++)
      expect(
        (
          await ada.authorize(
            Object.fromEntries(new URLSearchParams(authorizeQuery(s))),
          )
        ).status,
      ).toBe(302);
    await limited(
      await ada.browser.fetch(`${s.api}/oauth/authorize?${authorizeQuery(s)}`),
      "plain",
    );
  });

  it("limits /oauth/token per IP and per client with the OAuth error shape", async () => {
    const s = await mcp({
      "oauth.token.ip": per(3),
      "oauth.token.client": per(100),
    });
    for (let i = 0; i < 3; i++)
      expect(
        (
          await s.form("/oauth/token", {
            grant_type: "password",
            client_id: PUBLIC_CLIENT,
          })
        ).body,
      ).toMatchObject({ error: "unsupported_grant_type" });
    const response = await fetch(`${s.api}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=password",
    });
    await limited(response, "oauth");

    const t = await mcp({ "oauth.token.client": per(2) });
    for (let i = 0; i < 2; i++)
      expect(
        (
          await t.form("/oauth/token", {
            grant_type: "password",
            client_id: PUBLIC_CLIENT,
          })
        ).status,
      ).toBe(400);
    expect(
      (
        await t.form("/oauth/token", {
          grant_type: "password",
          client_id: PUBLIC_CLIENT,
        })
      ).status,
    ).toBe(429);
    expect(
      (
        await t.form(
          "/oauth/token",
          { grant_type: "password" },
          { id: CONFIDENTIAL_CLIENT, secret: CONFIDENTIAL_SECRET },
        )
      ).status,
    ).toBe(400);
  });

  it("counts only failed grants per client and IP, and valid exchanges never", async () => {
    const s = await mcp({ "oauth.token.failures": per(2) });
    const ada = await s.person("ada");
    // Valid exchanges and refreshes do not count.
    const tokens = [];
    for (let i = 0; i < 3; i++) tokens.push(await ada.tokens());
    const bad = () =>
      s.form("/oauth/token", {
        grant_type: "refresh_token",
        client_id: PUBLIC_CLIENT,
        refresh_token: "wrong",
      });
    expect((await bad()).body).toMatchObject({ error: "invalid_grant" });
    expect((await bad()).body).toMatchObject({ error: "invalid_grant" });
    // Now even a good refresh from this client and IP waits.
    const refresh = await fetch(`${s.api}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: PUBLIC_CLIENT,
        refresh_token: tokens[0]?.refresh_token ?? "",
      }).toString(),
    });
    await limited(refresh, "oauth");
    // Another client from the same IP is unaffected.
    const grace = await s.person("grace");
    await grace.tokens({ client: CONFIDENTIAL_CLIENT });
    s.advance(30);
    expect(
      (
        await s.form("/oauth/token", {
          grant_type: "refresh_token",
          client_id: PUBLIC_CLIENT,
          refresh_token: tokens[1]?.refresh_token ?? "",
        })
      ).status,
    ).toBe(200);
  });

  it("limits /oauth/revoke and legacy registration with the OAuth error shape", async () => {
    const s = await mcp(
      { "oauth.revoke": per(1), "oauth.register": per(1, 3600) },
      { env: { POSTED_OAUTH_LEGACY_DCR: "true" } },
    );
    expect(
      (await s.form("/oauth/revoke", { token: "x", client_id: PUBLIC_CLIENT }))
        .status,
    ).toBe(200);
    await limited(
      await fetch(`${s.api}/oauth/revoke`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "token=x&client_id=posted-cli",
      }),
      "oauth",
    );
    const register = () =>
      fetch(`${s.api}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "Old",
          redirect_uris: ["http://127.0.0.1/cb"],
        }),
      });
    expect((await register()).status).toBe(201);
    const second = await register();
    await limited(second, "oauth");
  });

  it("limits consent decisions and API key writes per user", async () => {
    const s = await mcp({ "oauth.consent": per(1), "api-keys.write": per(2) });
    const ada = await s.person("ada");
    await ada.connect();
    const second = await ada.authorize(
      Object.fromEntries(new URLSearchParams(authorizeQuery(s))),
    );
    const id =
      new URL(second.headers.get("location") ?? "").searchParams.get(
        "request",
      ) ?? "";
    const decided = await ada.call(`/oauth/consent/${id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ decision: "deny" }),
    });
    await limited(decided, "json");
    // Another person is unaffected.
    const grace = await s.person("grace");
    await grace.connect();

    const create = () =>
      ada.call("/auth/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "k", ceiling: "viewer" }),
      });
    const first = (await (await create()).json()) as { apiKey: { id: string } };
    const rotated = await ada.call(`/auth/api-keys/${first.apiKey.id}/rotate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(rotated.status).toBe(201);
    await limited(await create(), "json");
  });

  it("counts only invalid bearer credentials, so valid ones from the same IP keep working", async () => {
    const s = await mcp({ "bearer.invalid": per(3) });
    const ada = await s.person("ada");
    const created = (await (
      await ada.call("/auth/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "k", ceiling: "viewer" }),
      })
    ).json()) as { key: string };
    const oauth = await ada.tokens();
    const withKey = (key: string) =>
      fetch(`${s.api}/api/me`, { headers: { authorization: `Bearer ${key}` } });
    const wrongKey = `${created.key.slice(0, -1)}${created.key.endsWith("A") ? "B" : "A"}`;
    for (let i = 0; i < 2; i++)
      expect((await withKey(wrongKey)).status).toBe(401);
    expect((await s.bearer("/mcp", "not-a-token")).status).toBe(401);
    // The budget is spent: invalid keys and tokens now get 429 ...
    await limited(await withKey(wrongKey), "json");
    await limited(await s.bearer("/mcp", "still-not-a-token"), "json");
    // ... and valid ones still pass, however many.
    for (let i = 0; i < 5; i++) {
      expect((await withKey(created.key)).status).toBe(200);
      expect((await s.bearer("/mcp", oauth.access_token)).status).toBe(200);
    }
    // No bearer at all is not a failure.
    expect((await fetch(`${s.api}/mcp`, { method: "POST" })).status).toBe(401);
  });

  describe("client metadata fetches", () => {
    const host = (name: string) =>
      `https://${name}.example.com/oauth/client.json`;
    function documents(...urls: string[]) {
      const calls: string[] = [];
      const options: MetadataFetchOptions = {
        resolve: async () => [{ address: "93.184.216.34", family: 4 }],
        transport: async (url) => {
          calls.push(url.href);
          return {
            status: urls.includes(url.href) ? 200 : 404,
            headers: {
              "content-type": "application/json",
              "cache-control": "max-age=600",
            },
            body: (async function* () {
              yield Buffer.from(
                JSON.stringify({
                  client_id: url.href,
                  client_name: "Agent",
                  redirect_uris: [new URL("/cb", url).href],
                }),
              );
            })(),
          };
        },
      };
      return { options, calls };
    }
    const authorize = async (s: McpStack, clientId: string) =>
      fetch(
        `${s.api}/oauth/authorize?${authorizeQuery(s, {
          client_id: clientId,
          redirect_uri: new URL("/cb", clientId).href,
        })}`,
        { redirect: "manual" },
      );
    const many = { "oauth.authorize": per(100) };

    it("caps fetches per IP, and cache hits do not count", async () => {
      const docs = [host("a"), host("b"), host("c")];
      const served = documents(...docs);
      const s = await mcp(
        { ...many, "oauth.metadata.ip": per(2) },
        { metadataFetch: served.options },
      );
      for (let i = 0; i < 5; i++)
        expect((await authorize(s, docs[0] ?? "")).status).toBe(302);
      expect(served.calls).toHaveLength(1);
      expect((await authorize(s, docs[1] ?? "")).status).toBe(302);
      await limited(await authorize(s, docs[2] ?? ""), "plain");
      expect(served.calls).toHaveLength(2);
      // Cached clients keep working after the cap.
      expect((await authorize(s, docs[0] ?? "")).status).toBe(302);
    });

    it("caps fetches per document host and in all", async () => {
      const sameHost = documents(
        "https://a.example.com/one.json",
        "https://a.example.com/two.json",
        "https://a.example.com/three.json",
        host("b"),
      );
      const s = await mcp(
        {
          ...many,
          "oauth.metadata.ip": per(100),
          "oauth.metadata.host": per(2),
        },
        { metadataFetch: sameHost.options },
      );
      expect(
        (await authorize(s, "https://a.example.com/one.json")).status,
      ).toBe(302);
      expect(
        (await authorize(s, "https://a.example.com/two.json")).status,
      ).toBe(302);
      await limited(
        await authorize(s, "https://a.example.com/three.json"),
        "plain",
      );
      expect((await authorize(s, host("b"))).status).toBe(302);

      const hosts = documents(host("a"), host("b"), host("c"));
      const t = await mcp(
        {
          ...many,
          "oauth.metadata.ip": per(100),
          "oauth.metadata.global": per(2),
        },
        { metadataFetch: hosts.options },
      );
      expect((await authorize(t, host("a"))).status).toBe(302);
      expect((await authorize(t, host("b"))).status).toBe(302);
      await limited(await authorize(t, host("c")), "plain");
      expect(hosts.calls).toHaveLength(2);
    });
  });

  it("limits SCIM per token with the SCIM error schema", async () => {
    const TOKEN = "scim-token-".repeat(4);
    const s = await mcp(
      { scim: per(3) },
      { env: { POSTED_SCIM_TOKENS: TOKEN } },
    );
    const scim = createScim({
      config: s.config,
      sql: s.sql,
      rateLimiter: s.auth.rateLimiter,
    });
    const get = (token = TOKEN) =>
      scim.request("/ServiceProviderConfig", {
        headers: { authorization: `Bearer ${token}` },
      });
    for (let i = 0; i < 3; i++) expect((await get()).status).toBe(200);
    await limited(await get(), "scim");
    // A wrong token is a 401, not this token's budget.
    expect((await get("wrong-token-".repeat(4))).status).toBe(401);
  });

  it(
    "lets an authentik full sync of 500 users and 50 groups through the default SCIM limit",
    { timeout: 120_000 },
    async () => {
      const TOKEN = "scim-token-".repeat(4);
      const s = await mcp(
        {},
        { env: { POSTED_SCIM_TOKENS: TOKEN, POSTED_ROLE_SOURCE: "scim" } },
      );
      // The default policy, with its own limiter, as an app would mount it.
      const scim = createScim({ config: s.config, sql: s.sql });
      const statuses = new Map<number, number>();
      const call = async (method: string, path: string, body: unknown) => {
        const response = await scim.request(path, {
          method,
          headers: {
            authorization: `Bearer ${TOKEN}`,
            "content-type": "application/scim+json",
          },
          body: JSON.stringify(body),
        });
        statuses.set(response.status, (statuses.get(response.status) ?? 0) + 1);
        return (await response.json()) as { id: string };
      };
      const user = (i: number) => ({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: `user${i}@example.com`,
        name: {
          formatted: `User ${i}`,
          givenName: "User",
          familyName: String(i),
        },
        displayName: `User ${i}`,
        active: true,
        emails: [
          { value: `user${i}@example.com`, type: "other", primary: true },
        ],
        externalId: `ak-user-${i}`,
      });
      const ids: string[] = [];
      for (let i = 0; i < 500; i++)
        ids.push((await call("POST", "/Users", user(i))).id);
      const group = (g: number) => ({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: g === 0 ? "posted-admins" : `team-${g}`,
        externalId: `ak-group-${g}`,
        members: ids.slice(g * 10, g * 10 + 10).map((value) => ({ value })),
      });
      const groupIds: string[] = [];
      for (let g = 0; g < 50; g++)
        groupIds.push((await call("POST", "/Groups", group(g))).id);
      // The full sync, in the same minute as the provisioning: every user
      // and every group again.
      for (let i = 0; i < 500; i++)
        await call("PUT", `/Users/${ids[i] ?? ""}`, user(i));
      for (let g = 0; g < 50; g++)
        await call("PUT", `/Groups/${groupIds[g] ?? ""}`, group(g));
      expect(Object.fromEntries(statuses)).toEqual({ 200: 550, 201: 550 });
    },
  );

  it("takes the client IP from trusted proxies only, and keys IPv6 on the /64", async () => {
    const signIn = (s: Stack, forwardedFor: string) =>
      fetch(`${s.api}/auth/sign-in`, {
        redirect: "manual",
        headers: { "x-forwarded-for": forwardedFor },
      });
    const trusting = await mcp(
      { oidc: per(1) },
      { env: { POSTED_TRUSTED_PROXIES: "127.0.0.1" } },
    );
    expect((await signIn(trusting, "198.51.100.1")).status).toBe(302);
    expect((await signIn(trusting, "198.51.100.1")).status).toBe(429);
    expect((await signIn(trusting, "203.0.113.9, 198.51.100.2")).status).toBe(
      302,
    );
    expect((await signIn(trusting, "2001:db8:1:2::1")).status).toBe(302);
    expect((await signIn(trusting, "2001:db8:1:2:ffff::9")).status).toBe(429);
    expect((await signIn(trusting, "2001:db8:1:3::1")).status).toBe(302);

    // Without trust, the header is ignored: every request is the socket's.
    const strict = await mcp({ oidc: per(1) });
    expect((await signIn(strict, "198.51.100.1")).status).toBe(302);
    expect((await signIn(strict, "198.51.100.2")).status).toBe(429);
  });

  it("lets apps limit their own routes with the same store", async () => {
    const s = await startStack({
      mount: (app, { auth }) => {
        app.get(
          "/app/limited",
          auth.middleware.rateLimit("app.custom", "ip", { fallback: per(2) }),
          (c) => c.json({ ok: true }),
        );
        app.get(
          "/app/skipped",
          auth.middleware.rateLimit("app.custom", () => null, {
            fallback: per(1),
          }),
          (c) => c.json({ ok: true }),
        );
      },
    });
    stacks.push(s);
    expect((await fetch(`${s.api}/app/limited`)).status).toBe(200);
    expect((await fetch(`${s.api}/app/limited`)).status).toBe(200);
    await limited(await fetch(`${s.api}/app/limited`), "json");
    for (let i = 0; i < 3; i++)
      expect((await fetch(`${s.api}/app/skipped`)).status).toBe(200);
  });

  it("fails closed with a generic 503 when the limiter's store fails", async () => {
    const TOKEN = "scim-token-".repeat(4);
    const s = await mcp({}, { env: { POSTED_SCIM_TOKENS: TOKEN } });
    const ada = await s.person("ada");
    await rows(s, "DROP TABLE {schema}.rate_limit_buckets");
    const unavailable = async (response: Response) => {
      expect(response.status).toBe(503);
      expect(response.headers.get("retry-after")).toBeNull();
      const text = await response.text();
      expect(text).not.toMatch(/rate_limit_buckets|relation|does not exist/);
      return text;
    };
    expect(
      await unavailable(
        await fetch(`${s.api}/auth/sign-in`, { redirect: "manual" }),
      ),
    ).toMatch(/temporarily unavailable/);
    expect(
      JSON.parse(
        await unavailable(
          await fetch(`${s.api}/oauth/token`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: "grant_type=password",
          }),
        ),
      ),
    ).toEqual({
      error: "temporarily_unavailable",
      error_description: expect.any(String),
    });
    expect(
      JSON.parse(
        await unavailable(
          await ada.call("/auth/api-keys", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ name: "k", ceiling: "viewer" }),
          }),
        ),
      ),
    ).toEqual({ error: { code: "unavailable", message: expect.any(String) } });
    const scim = createScim({
      config: s.config,
      sql: s.sql,
      rateLimiter: s.auth.rateLimiter,
    });
    expect(
      JSON.parse(
        await unavailable(
          await scim.request("/ServiceProviderConfig", {
            headers: { authorization: `Bearer ${TOKEN}` },
          }),
        ),
      ),
    ).toMatchObject({ status: "503" });
  });
});
