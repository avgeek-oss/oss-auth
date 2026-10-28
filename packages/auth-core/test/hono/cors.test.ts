import { afterEach, describe, expect, it } from "vitest";
import { createScim } from "../../src/scim/index.js";
import { databaseUrl } from "../postgres/support.js";
import { PUBLIC_CLIENT, startMcp } from "../mcp/support.js";
import { startStack, WEB, type Stack } from "./support.js";

const stacks: Stack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});

const CORS_HEADERS = [
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "access-control-max-age",
  "access-control-expose-headers",
];

/** The CORS headers of a response, by name. */
const cors = (response: Response) =>
  Object.fromEntries(
    CORS_HEADERS.flatMap((name) => {
      const value = response.headers.get(name);
      return value === null ? [] : [[name, value]];
    }),
  );

/** True when `Vary` names `Origin` exactly once. */
const varies = (response: Response) =>
  (response.headers.get("vary") ?? "")
    .split(",")
    .filter((v) => v.trim().toLowerCase() === "origin").length === 1;

const ALLOWED = {
  "access-control-allow-origin": WEB,
  "access-control-allow-credentials": "true",
  "access-control-expose-headers": "Retry-After",
};

const PREFLIGHT = {
  "access-control-allow-origin": WEB,
  "access-control-allow-credentials": "true",
  "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE",
  "access-control-allow-headers":
    "Content-Type, x-requested-with, Idempotency-Key, Authorization",
  "access-control-max-age": "600",
};

const preflight = (url: string, origin: string, method = "POST") =>
  fetch(url, {
    method: "OPTIONS",
    headers: {
      origin,
      "access-control-request-method": method,
      "access-control-request-headers": "content-type,x-requested-with",
    },
  });

const OTHER_ORIGINS = [
  "https://evil.example",
  "http://localhost:5174",
  "http://localhost:5173.evil.example",
  "https://localhost:5173",
  "null",
];

describe.skipIf(!databaseUrl)("CORS", () => {
  it("allows the web origin with credentials on the auth routes, errors included", async () => {
    const s = await startMcp();
    stacks.push(s);
    // Signed out: the 401 is still readable by the page.
    const signedOut = await s.call("/auth/session");
    expect(signedOut.status).toBe(401);
    expect(cors(signedOut)).toEqual(ALLOWED);
    expect(varies(signedOut)).toBe(true);

    await s.signIn();
    for (const path of [
      "/auth/session",
      "/auth/api-keys",
      "/auth/connected-apps",
    ]) {
      const response = await s.call(path);
      expect(response.status, path).toBe(200);
      expect(cors(response), path).toEqual(ALLOWED);
      expect(varies(response), path).toBe(true);
    }
    const created = await s.call("/auth/api-keys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", ceiling: "viewer" }),
    });
    expect(created.status).toBe(201);
    expect(cors(created)).toEqual(ALLOWED);
    const out = await s.call("/auth/sign-out", { method: "POST" });
    expect(cors(out)).toEqual(ALLOWED);
  });

  it("exposes Retry-After on a rate-limited answer", async () => {
    const s = await startMcp({
      env: {
        POSTED_RATE_LIMITS: JSON.stringify({
          "api-keys.write": { limit: 1, periodSeconds: 60 },
        }),
      },
    });
    stacks.push(s);
    await s.signIn();
    const create = () =>
      s.call("/auth/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "x", ceiling: "viewer" }),
      });
    expect((await create()).status).toBe(201);
    const refused = await create();
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(cors(refused)).toEqual(ALLOWED);
  });

  it("gives any other origin, or none, no CORS headers at all", async () => {
    const s = await startMcp();
    stacks.push(s);
    await s.signIn();
    for (const origin of OTHER_ORIGINS) {
      const response = await s.call("/auth/session", { headers: { origin } });
      expect(cors(response), origin).toEqual({});
      expect(varies(response), origin).toBe(true);
      const answer = await preflight(`${s.api}/auth/api-keys`, origin);
      expect(answer.status, origin).toBe(204);
      expect(cors(answer), origin).toEqual({});
      expect(varies(answer), origin).toBe(true);
    }
    const bare = await s.browser.fetch(`${s.api}/auth/session`);
    expect(bare.status).toBe(200);
    expect(cors(bare)).toEqual({});
  });

  it("answers preflights with 204 before authentication, on the auth and consent routes", async () => {
    const s = await startMcp();
    stacks.push(s);
    for (const [path, method] of [
      ["/auth/api-keys", "POST"],
      ["/auth/api-keys/00000000-0000-4000-8000-000000000000", "DELETE"],
      ["/auth/api-keys/k/rotate", "POST"],
      ["/auth/sign-out", "POST"],
      ["/auth/connected-apps/g1", "DELETE"],
      ["/oauth/consent/r1", "POST"],
      ["/oauth/consent/r1", "GET"],
    ] as const) {
      const answer = await preflight(`${s.api}${path}`, WEB, method);
      expect(answer.status, path).toBe(204);
      expect(cors(answer), path).toEqual(PREFLIGHT);
      expect(await answer.text(), path).toBe("");
    }
    // An OPTIONS without Access-Control-Request-Method is not a preflight.
    const plain = await fetch(`${s.api}/auth/api-keys`, {
      method: "OPTIONS",
      headers: { origin: WEB },
    });
    expect(plain.status).not.toBe(204);
  });

  it("names the configured CSRF header in the preflight", async () => {
    const s = await startStack({ auth: { csrfHeader: "X-CSRF" } });
    stacks.push(s);
    const answer = await preflight(`${s.api}/auth/sign-out`, WEB);
    expect(answer.headers.get("access-control-allow-headers")).toBe(
      "Content-Type, x-csrf, Idempotency-Key, Authorization",
    );
  });

  it("adds no CORS to SCIM, the OAuth endpoints, MCP or the app's routes unless asked", async () => {
    const TOKEN = "scim-token-".repeat(4);
    const s = await startMcp({ env: { POSTED_SCIM_TOKENS: TOKEN } });
    stacks.push(s);
    const scim = createScim({ config: s.config, sql: s.sql });
    const fromWeb = { origin: WEB, authorization: `Bearer ${TOKEN}` };
    for (const response of [
      await scim.request("/ServiceProviderConfig", { headers: fromWeb }),
      await scim.request("/Users", {
        method: "OPTIONS",
        headers: { origin: WEB, "access-control-request-method": "POST" },
      }),
      await fetch(`${s.api}/oauth/token`, {
        method: "POST",
        headers: {
          origin: WEB,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: "x",
          client_id: PUBLIC_CLIENT,
        }),
      }),
      await preflight(`${s.api}/oauth/token`, WEB),
      await preflight(`${s.api}/oauth/revoke`, WEB),
      await fetch(`${s.api}/oauth/authorize?client_id=x`, {
        headers: { origin: WEB },
      }),
      await fetch(`${s.api}/.well-known/oauth-authorization-server`, {
        headers: { origin: WEB },
      }),
      await fetch(`${s.api}/mcp`, { method: "POST", headers: { origin: WEB } }),
      await preflight(`${s.api}/mcp`, WEB),
      await s.call("/api/me"),
    ])
      expect(cors(response), response.url).toEqual({});

    // An app opts its own routes in.
    const app = await startStack({
      mount: (hono, { auth }) => {
        hono.use("/app/*", auth.middleware.cors, auth.middleware.actor);
        hono.get("/app/ping", (c) => c.json({ ok: true }));
      },
    });
    stacks.push(app);
    expect(cors(await app.call("/app/ping"))).toEqual(ALLOWED);
    expect(cors(await preflight(`${app.api}/app/ping`, WEB, "GET"))).toEqual(
      PREFLIGHT,
    );
    expect(
      cors(
        await app.call("/app/ping", {
          headers: { origin: "https://evil.example" },
        }),
      ),
    ).toEqual({});
  });
});
