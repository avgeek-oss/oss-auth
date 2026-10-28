import { describe, expect, it } from "vitest";
import { loadAuthConfig } from "../../src/index.js";
import { createAuth, sessionCookieName } from "../../src/hono/index.js";
import { transactionCookieName, type FetchLike } from "../../src/oidc/index.js";
import type { Sql } from "../../src/postgres/index.js";
import type { RateLimiter } from "../../src/rate-limits/index.js";

const ISSUER = "https://auth.example.com/application/o/posted/";

// Serves a discovery document, so no provider or database is needed.
const discovery: FetchLike = async () =>
  Response.json({
    issuer: ISSUER,
    authorization_endpoint: "https://auth.example.com/application/o/authorize/",
    token_endpoint: "https://auth.example.com/application/o/token/",
    jwks_uri: "https://auth.example.com/application/o/posted/jwks/",
    end_session_endpoint:
      "https://auth.example.com/application/o/posted/end-session/",
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  });

const unusedSql: Sql = {
  query: () => Promise.reject(new Error("no query expected")),
  transaction: () => Promise.reject(new Error("no transaction expected")),
};

// These routes are rate limited; with no database, a limiter that allows
// everything stands in.
const allowAll: RateLimiter = {
  policy: () => ({ limit: 1, periodSeconds: 1 }),
  consume: async () => ({ allowed: true, retryAfterSeconds: 0, remaining: 1 }),
  check: async () => ({ allowed: true, retryAfterSeconds: 0, remaining: 1 }),
  enforce: async () => {},
  purgeExpired: async () => 0,
};

function auth(api: string, web = "https://posted.example.com") {
  const config = loadAuthConfig("posted", {
    POSTED_SECRET: "s".repeat(32),
    POSTED_OIDC_ISSUER: ISSUER,
    POSTED_OIDC_CLIENT_ID: "posted",
    POSTED_OIDC_CLIENT_SECRET: "x",
    POSTED_WEB_ORIGIN: web,
    POSTED_API_ORIGIN: api,
  });
  return createAuth({
    config,
    sql: unusedSql,
    oidc: { fetch: discovery },
    rateLimiter: allowAll,
  });
}

const attributes = (cookie: string | undefined) =>
  (cookie ?? "")
    .split(";")
    .slice(1)
    .map((a) => a.trim())
    .sort();

describe("cookies", () => {
  it("names cookies with the __Host- prefix on HTTPS and without it on loopback HTTP", () => {
    expect(sessionCookieName("posted", "https://api.posted.example.com")).toBe(
      "__Host-posted-session",
    );
    expect(
      transactionCookieName("posted", "https://api.posted.example.com"),
    ).toBe("__Host-posted-oidc");
    for (const api of [
      "http://localhost:8787",
      "http://127.0.0.1:8787",
      "http://[::1]:8787",
    ]) {
      expect(sessionCookieName("posted", api)).toBe("posted-session");
      expect(transactionCookieName("posted", api)).toBe("posted-oidc");
    }
  });

  it("sets Secure, HttpOnly, SameSite=Lax and Path=/ on HTTPS", async () => {
    const a = auth("https://api.posted.example.com");
    const start = await a.routes.request("/sign-in?returnTo=/x");
    expect(start.status).toBe(302);
    const [transaction] = start.headers.getSetCookie();
    expect(transaction?.startsWith("__Host-posted-oidc=")).toBe(true);
    expect(attributes(transaction)).toEqual([
      "HttpOnly",
      "Max-Age=600",
      "Path=/",
      "SameSite=Lax",
      "Secure",
    ]);
    const location = new URL(start.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe(
      "https://auth.example.com/application/o/authorize/",
    );
    expect(location.searchParams.get("redirect_uri")).toBe(
      "https://api.posted.example.com/auth/callback",
    );

    const out = await a.routes.request("/sign-out", {
      method: "POST",
      headers: {
        origin: "https://posted.example.com",
        "x-requested-with": "fetch",
      },
    });
    expect(out.status).toBe(200);
    const [cleared] = out.headers.getSetCookie();
    expect(cleared?.startsWith("__Host-posted-session=;")).toBe(true);
    expect(attributes(cleared)).toEqual([
      "HttpOnly",
      "Max-Age=0",
      "Path=/",
      "SameSite=Lax",
      "Secure",
    ]);
    expect(await out.json()).toEqual({
      endSessionUrl:
        "https://auth.example.com/application/o/posted/end-session/?client_id=posted&post_logout_redirect_uri=https%3A%2F%2Fposted.example.com%2F",
    });
  });

  it("drops the prefix and Secure only for a loopback HTTP API", async () => {
    const a = auth("http://localhost:8787", "http://localhost:5173");
    const start = await a.routes.request("/sign-in");
    const [transaction] = start.headers.getSetCookie();
    expect(transaction?.startsWith("posted-oidc=")).toBe(true);
    expect(attributes(transaction)).toEqual([
      "HttpOnly",
      "Max-Age=600",
      "Path=/",
      "SameSite=Lax",
    ]);
  });

  it("answers errors as typed JSON", async () => {
    const a = auth("https://api.posted.example.com");
    const session = await a.routes.request("/session");
    expect(session.status).toBe(401);
    expect(session.headers.get("cache-control")).toBe("no-store");
    expect(await session.json()).toEqual({
      error: { code: "unauthenticated", message: "Sign in to continue." },
    });
    const bad = await a.routes.request("/sign-in?returnTo=//evil.example");
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({
      error: { code: "return_to_invalid" },
    });
  });

  it("reports an unreachable provider as oidc_unavailable", async () => {
    const config = loadAuthConfig("posted", {
      POSTED_SECRET: "s".repeat(32),
      POSTED_OIDC_ISSUER: ISSUER,
      POSTED_OIDC_CLIENT_ID: "posted",
      POSTED_OIDC_CLIENT_SECRET: "x",
      POSTED_WEB_ORIGIN: "https://posted.example.com",
      POSTED_API_ORIGIN: "https://api.posted.example.com",
    });
    let calls = 0;
    const a = createAuth({
      config,
      sql: unusedSql,
      rateLimiter: allowAll,
      oidc: {
        fetch: async (...args) => {
          calls++;
          if (calls === 1) throw new TypeError("fetch failed");
          return discovery(...args);
        },
      },
    });
    const down = await a.routes.request("/sign-in");
    expect(down.status).toBe(503);
    expect(await down.json()).toMatchObject({
      error: { code: "oidc_unavailable" },
    });
    // A failure is not cached: the next request discovers again.
    expect((await a.routes.request("/sign-in")).status).toBe(302);
    expect((await a.routes.request("/sign-in")).status).toBe(302);
    expect(calls).toBe(2);
  });
});
