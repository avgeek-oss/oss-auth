import { describe, expect, it } from "vitest";
import {
  AUTH_ERROR_CODES,
  AuthClientError,
  createAuthClient,
  isAuthClientError,
  roleAtLeast,
} from "../src/index.js";
import { apiError, fakeFetch, json, SESSION } from "./support.js";

const API = "https://api.example.com";

function setup(routes: Parameters<typeof fakeFetch>[0] = {}) {
  const fake = fakeFetch(routes);
  return {
    ...fake,
    client: createAuthClient({ apiOrigin: `${API}/`, fetch: fake.fetch }),
  };
}

const failure = async (promise: Promise<unknown>) => {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(AuthClientError);
  return error as AuthClientError;
};

describe("requests", () => {
  it("sends cookies on every request, the CSRF header on all but GET, and JSON bodies", async () => {
    const { client, seen } = setup({
      "GET /auth/api-keys": json({ apiKeys: [] }),
      "POST /auth/api-keys": json({ key: "k", apiKey: {} }, 201),
      "DELETE /auth/api-keys/a%2Fb": new Response(null, { status: 204 }),
    });
    await client.apiKeys.list();
    await client.apiKeys.create({ name: "CI", ceiling: "member" });
    expect(await client.apiKeys.revoke("a/b")).toBeUndefined();
    expect(seen.map((r) => [r.method, r.url])).toEqual([
      ["GET", `${API}/auth/api-keys`],
      ["POST", `${API}/auth/api-keys`],
      ["DELETE", `${API}/auth/api-keys/a%2Fb`],
    ]);
    for (const request of seen) expect(request.credentials).toBe("include");
    expect(seen[0]?.headers).toEqual({ accept: "application/json" });
    expect(seen[1]?.headers).toEqual({
      accept: "application/json",
      "x-requested-with": "fetch",
      "content-type": "application/json",
    });
    expect(seen[1]?.body).toEqual({ name: "CI", ceiling: "member" });
    expect(seen[2]?.headers).toEqual({
      accept: "application/json",
      "x-requested-with": "fetch",
    });
  });

  it("uses the configured paths and CSRF header, and same-origin URLs for an empty origin", async () => {
    const fake = fakeFetch({
      "POST /api/auth/sign-out": json({ endSessionUrl: null }),
      "GET /api/oauth/consent/r1": json({ client: {} }),
    });
    const client = createAuthClient({
      apiOrigin: "",
      basePath: "/api/auth/",
      oauthBasePath: "/api/oauth",
      csrfHeader: "x-csrf",
      fetch: fake.fetch,
    });
    expect(client.options).toEqual({
      apiOrigin: "",
      basePath: "/api/auth",
      oauthBasePath: "/api/oauth",
      csrfHeader: "x-csrf",
    });
    expect(await client.signOut()).toBeNull();
    await client.consent.get("r1");
    expect(fake.seen.map((r) => r.url)).toEqual([
      "/api/auth/sign-out",
      "/api/oauth/consent/r1",
    ]);
    expect(fake.seen[0]?.headers["x-csrf"]).toBe("fetch");
    expect(client.signInUrl("/x")).toBe("/api/auth/sign-in?returnTo=%2Fx");
  });

  it("builds every method's request", async () => {
    const { client, seen } = setup({
      "GET /auth/session": json(SESSION),
      "POST /auth/sign-out": json({ endSessionUrl: "https://idp/logout" }),
      "POST /auth/api-keys/k1/rotate": json({ key: "s", apiKey: {} }, 201),
      "GET /auth/connected-apps": json({ connectedApps: [{ id: "g1" }] }),
      "DELETE /auth/connected-apps/g1": new Response(null, { status: 204 }),
      "GET /oauth/consent/r1": json({ scope: null }),
      "POST /oauth/consent/r1": json({
        redirectUri: "http://127.0.0.1/cb?code=c",
      }),
      "GET /auth/api-keys?user=u%201": json({ apiKeys: [{ id: "k2" }] }),
      "GET /auth/connected-apps?user=u%201": json({ connectedApps: [] }),
      "DELETE /auth/api-keys/k2": new Response(null, { status: 204 }),
    });
    expect(await client.getSession()).toEqual(SESSION);
    expect(await client.signOut()).toBe("https://idp/logout");
    await client.apiKeys.rotate("k1", { graceSeconds: 3600 });
    await client.apiKeys.rotate("k1");
    expect(await client.connectedApps.list()).toEqual([{ id: "g1" }]);
    await client.connectedApps.revoke("g1");
    expect(await client.consent.get("r1")).toEqual({ scope: null });
    expect(
      await client.consent.decide("r1", { approve: true, ceiling: "member" }),
    ).toEqual({ redirectUri: "http://127.0.0.1/cb?code=c" });
    await client.consent.decide("r1", { approve: false });
    await client.consent.decide("r1", {
      approve: true,
      ceiling: "viewer",
      restrictions: { boards: ["b1"] },
    });
    expect(await client.admin.apiKeys.list("u 1")).toEqual([{ id: "k2" }]);
    expect(await client.admin.connectedApps.list("u 1")).toEqual([]);
    await client.admin.apiKeys.revoke("k2");
    expect(seen.filter((r) => r.body !== undefined).map((r) => r.body)).toEqual(
      [
        { graceSeconds: 3600 },
        { graceSeconds: 0 },
        { decision: "approve", ceiling: "member" },
        { decision: "deny" },
        {
          decision: "approve",
          ceiling: "viewer",
          restrictions: { boards: ["b1"] },
        },
      ],
    );
  });

  it("answers a signed-out session with null, and throws other session failures", async () => {
    const { client, answer } = setup({
      "GET /auth/session": apiError("unauthenticated", 401),
    });
    expect(await client.getSession()).toBeNull();
    answer("GET /auth/session", apiError("unavailable", 503));
    expect((await failure(client.getSession())).code).toBe("unavailable");
  });
});

describe("errors", () => {
  it("maps every auth-core code, with its status and message", async () => {
    const { client, answer } = setup();
    for (const code of AUTH_ERROR_CODES) {
      answer("GET /auth/api-keys", apiError(code, 418));
      const error = await failure(client.apiKeys.list());
      expect(error).toMatchObject({
        code,
        status: 418,
        message: `${code} message`,
      });
      expect(isAuthClientError(error, code)).toBe(true);
    }
  });

  it("passes unknown codes and extra fields through untouched", async () => {
    const { client, answer } = setup();
    answer("GET /auth/api-keys", apiError("brand_new_code", 409, { hint: 3 }));
    const error = await failure(client.apiKeys.list());
    expect(error.code).toBe("brand_new_code");
    expect(error.details).toEqual({ hint: 3 });
    expect(error.name).toBe("AuthClientError");
  });

  it("reads stepUpUrl and Retry-After", async () => {
    const { client, answer } = setup();
    answer(
      "POST /auth/api-keys",
      apiError("step_up_required", 401, { stepUpUrl: `${API}/auth/step-up` }),
    );
    const stepUp = await failure(
      client.apiKeys.create({ name: "x", ceiling: "admin" }),
    );
    expect(stepUp).toMatchObject({
      code: "step_up_required",
      stepUpUrl: `${API}/auth/step-up`,
      retryAfterSeconds: null,
      details: { stepUpUrl: `${API}/auth/step-up` },
    });
    answer(
      "POST /auth/api-keys",
      apiError(
        "rate_limited",
        429,
        {},
        { "retry-after": "17", "cache-control": "no-store" },
      ),
    );
    expect(
      await failure(client.apiKeys.create({ name: "x", ceiling: "viewer" })),
    ).toMatchObject({
      code: "rate_limited",
      status: 429,
      retryAfterSeconds: 17,
      stepUpUrl: null,
    });
  });

  it("names answers that are not auth-core's JSON", async () => {
    const { client, answer } = setup();
    answer(
      "GET /auth/api-keys",
      new Response("Too many requests.", {
        status: 429,
        headers: { "retry-after": "5" },
      }),
    );
    expect(await failure(client.apiKeys.list())).toMatchObject({
      code: "rate_limited",
      retryAfterSeconds: 5,
    });
    answer(
      "GET /auth/api-keys",
      new Response("<html>Bad gateway</html>", { status: 503 }),
    );
    expect((await failure(client.apiKeys.list())).code).toBe("unavailable");
    answer("GET /auth/api-keys", new Response("<html>", { status: 502 }));
    expect(await failure(client.apiKeys.list())).toMatchObject({
      code: "invalid_response",
      status: 502,
    });
    answer(
      "GET /auth/api-keys",
      json({ error: "temporarily_unavailable" }, 400),
    );
    expect((await failure(client.apiKeys.list())).code).toBe(
      "invalid_response",
    );
    answer("GET /auth/api-keys", new Response("not json", { status: 200 }));
    expect(await failure(client.apiKeys.list())).toMatchObject({
      code: "invalid_response",
      status: 200,
    });
    answer(
      "GET /auth/api-keys",
      new Response("x", {
        status: 429,
        headers: { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" },
      }),
    );
    expect((await failure(client.apiKeys.list())).retryAfterSeconds).toBeNull();
  });

  it("turns a failed fetch into network_error, keeping the cause", async () => {
    const cause = new TypeError("Failed to fetch");
    const client = createAuthClient({
      apiOrigin: API,
      fetch: () => Promise.reject(cause),
    });
    const error = await failure(client.signOut());
    expect(error).toMatchObject({ code: "network_error", status: 0 });
    expect(error.cause).toBe(cause);
  });

  it("recognises errors by name across copies, not by instanceof", () => {
    const copy = Object.assign(new Error("x"), {
      name: "AuthClientError",
      code: "forbidden",
    });
    expect(isAuthClientError(copy)).toBe(true);
    expect(isAuthClientError(copy, "forbidden")).toBe(true);
    expect(isAuthClientError(copy, "not_found")).toBe(false);
    expect(isAuthClientError(new Error("x"))).toBe(false);
    expect(isAuthClientError({ name: "AuthClientError", code: "x" })).toBe(
      false,
    );
  });
});

describe("roles", () => {
  it("orders viewer < member < admin", () => {
    expect(roleAtLeast("admin", "member")).toBe(true);
    expect(roleAtLeast("member", "member")).toBe(true);
    expect(roleAtLeast("viewer", "member")).toBe(false);
  });
});
