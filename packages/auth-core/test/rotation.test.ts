import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { createBrowser } from "../src/testing/index.js";
import { deriveKey, hashToken, loadAuthConfig } from "../src/index.js";
import { createRateLimiter } from "../src/rate-limits/index.js";
import { createScim } from "../src/scim/index.js";
import { randomUUID } from "node:crypto";
import { createApiKeys } from "../src/api-keys/index.js";
import { migrate, quoteIdent, type Sql } from "../src/postgres/index.js";
import { createSessions } from "../src/sessions/index.js";
import {
  adapters,
  databaseUrl,
  dropSchemas,
  uniqueSchema,
} from "./postgres/support.js";
import { rows, WEB, type Stack } from "./hono/support.js";
import {
  PUBLIC_CLIENT,
  PUBLIC_REDIRECT,
  pkce,
  startMcp,
} from "./mcp/support.js";

const OLD = "test-secret-".repeat(4);
const NEW = "the-next-secret-".repeat(3);
const SCIM_TOKEN = "scim-token-".repeat(4);

const stacks: Stack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});

describe("loadAuthConfig with previous secrets", () => {
  const base = {
    POSTED_SECRET: NEW,
    POSTED_OIDC_ISSUER: "https://auth.example.com/application/o/posted/",
    POSTED_OIDC_CLIENT_ID: "posted",
    POSTED_OIDC_CLIENT_SECRET: "x",
    POSTED_WEB_ORIGIN: "https://posted.example.com",
    POSTED_API_ORIGIN: "https://api.posted.example.com",
  };
  const issues = (env: Record<string, string>) => {
    try {
      loadAuthConfig("posted", { ...base, ...env });
      return [];
    } catch (error) {
      return (error as { issues: { variable: string }[] }).issues.map(
        (i) => i.variable,
      );
    }
  };

  it("reads them in order, and redacts them", () => {
    const config = loadAuthConfig("posted", {
      ...base,
      POSTED_PREVIOUS_SECRETS: ` ${OLD} , ${"older-secret-".repeat(3)} `,
    });
    expect(config.previousSecrets).toEqual([OLD, "older-secret-".repeat(3)]);
    const shown = JSON.stringify(config);
    expect(shown).not.toContain(OLD);
    expect(shown).not.toContain("older-secret");
    expect(loadAuthConfig("posted", base).previousSecrets).toEqual([]);
  });

  it("refuses short, repeated or current secrets", () => {
    for (const value of ["short", `${OLD},${OLD}`, NEW, `${OLD},${NEW}`])
      expect(issues({ POSTED_PREVIOUS_SECRETS: value }), value).toEqual([
        "POSTED_PREVIOUS_SECRETS",
      ]);
  });
});

describe.skipIf(!databaseUrl)("secret rotation", () => {
  it("keeps every credential made under the old secret working, upgrades what lasts, and drops the rest once it is removed", async () => {
    const s = await startMcp({
      env: { POSTED_SECRET: OLD, POSTED_SCIM_TOKENS: SCIM_TOKEN },
    });
    stacks.push(s);
    const sessionHash = (secret: string, token: string) =>
      hashToken(deriveKey(secret, "posted", "session"), token);
    const keyHash = (secret: string, token: string) =>
      hashToken(deriveKey(secret, "posted", "api-key"), token);
    const schema = s.schema;

    // --- Under the old secret --------------------------------------------
    const ada = await s.person("ada");
    const grace = await s.person("grace"); // signs in, then idles through
    const adaToken = ada.browser.cookie(s.api, s.auth.sessionCookie) ?? "";
    const graceToken = grace.browser.cookie(s.api, s.auth.sessionCookie) ?? "";
    const newKey = async (name: string) => {
      const response = await ada.call("/auth/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, ceiling: "member" }),
      });
      return ((await response.json()) as { key: string }).key;
    };
    const usedKey = await newKey("used");
    const idleKey = await newKey("idle");
    const used = await ada.tokens();
    const idle = await ada.tokens();
    // A consent request opened before the rotation, decided after it.
    const { challenge } = pkce();
    const opened = await ada.authorize({
      response_type: "code",
      client_id: PUBLIC_CLIENT,
      redirect_uri: PUBLIC_REDIRECT,
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: s.resource,
      state: "rot",
    });
    const requestId =
      new URL(opened.headers.get("location") ?? "").searchParams.get(
        "request",
      ) ?? "";
    // A sign-in started before the rotation, finished after it.
    const late = createBrowser();
    s.mock.setLogin({ sub: "grace", amr: ["mfa"] });
    const started = await late.fetch(`${s.api}/auth/sign-in`);
    expect(started.status).toBe(302);
    const providerUrl = started.headers.get("location") ?? "";
    // Rate limit state for one key.
    const limits = (secret: string, previous?: string) =>
      createRateLimiter({
        sql: s.sql,
        config: loadAuthConfig("posted", {
          POSTED_SECRET: secret,
          ...(previous ? { POSTED_PREVIOUS_SECRETS: previous } : {}),
          POSTED_OIDC_ISSUER: "https://auth.example.com/",
          POSTED_OIDC_CLIENT_ID: "posted",
          POSTED_OIDC_CLIENT_SECRET: "x",
          POSTED_WEB_ORIGIN: "https://posted.example.com",
          POSTED_API_ORIGIN: "https://api.posted.example.com",
          POSTED_AUTH_SCHEMA: schema,
        }),
      });
    const policy = { limit: 4, periodSeconds: 3600 };
    for (let i = 0; i < 3; i++)
      expect(
        (await limits(OLD).consume("rotation", "203.0.113.9", policy)).allowed,
      ).toBe(true);

    // --- Rotating: NEW is current, OLD is previous ------------------------
    s.rekey({ POSTED_SECRET: NEW, POSTED_PREVIOUS_SECRETS: OLD });

    // The session works and is re-hashed under the new key.
    expect((await ada.call("/api/me")).status).toBe(200);
    expect(
      await rows(s, `SELECT 1 FROM {schema}.sessions WHERE id_hash = $1`, [
        sessionHash(NEW, adaToken),
      ]),
    ).toHaveLength(1);
    expect(
      await rows(s, `SELECT 1 FROM {schema}.sessions WHERE id_hash = $1`, [
        sessionHash(OLD, adaToken),
      ]),
    ).toHaveLength(0);
    // The API key works and is re-hashed.
    const bearer = (key: string) =>
      fetch(`${s.api}/api/me`, { headers: { authorization: `Bearer ${key}` } });
    expect((await bearer(usedKey)).status).toBe(200);
    expect(
      await rows(s, `SELECT 1 FROM {schema}.api_keys WHERE secret_hash = $1`, [
        keyHash(NEW, usedKey),
      ]),
    ).toHaveLength(1);
    // OAuth: the access token works, and the refresh rotates under the new key.
    expect((await s.bearer("/mcp", used.access_token)).status).toBe(200);
    const refreshed = await s.form("/oauth/token", {
      grant_type: "refresh_token",
      client_id: PUBLIC_CLIENT,
      refresh_token: used.refresh_token,
    });
    expect(refreshed.status).toBe(200);
    const fresh = refreshed.body as {
      access_token: string;
      refresh_token: string;
    };
    // The consent request opened before.
    expect((await ada.call(`/oauth/consent/${requestId}`)).status).toBe(200);
    const decided = await ada.call(`/oauth/consent/${requestId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve", ceiling: "viewer" }),
    });
    expect(decided.status).toBe(200);
    // The sign-in started before finishes.
    const finished = await late.follow(providerUrl, {
      stopAt: (url) => url.origin === WEB,
    });
    expect(new URL(finished.url).searchParams.get("auth_error")).toBeNull();
    expect((await late.fetch(`${s.api}/auth/session`)).status).toBe(200);
    // SCIM tokens are compared as hashes made at request time: unaffected.
    const scim = createScim({ config: s.config, sql: s.sql });
    expect(
      (
        await scim.request("/ServiceProviderConfig", {
          headers: { authorization: `Bearer ${SCIM_TOKEN}` },
        })
      ).status,
    ).toBe(200);
    // Rate limits carry over: one request left of the four, not four more.
    const rotating = limits(NEW, OLD);
    expect(
      (await rotating.check("rotation", "203.0.113.9", policy)).remaining,
    ).toBe(1);
    expect(
      (await rotating.consume("rotation", "203.0.113.9", policy)).allowed,
    ).toBe(true);
    expect(
      (await rotating.consume("rotation", "203.0.113.9", policy)).allowed,
    ).toBe(false);
    // New credentials use the new key.
    const created = await newKey("new");
    expect(
      await rows(s, `SELECT 1 FROM {schema}.api_keys WHERE secret_hash = $1`, [
        keyHash(NEW, created),
      ]),
    ).toHaveLength(1);

    // --- Rotated: OLD removed --------------------------------------------
    s.rekey({ POSTED_SECRET: NEW });
    // Upgraded or new: still fine.
    expect((await ada.call("/api/me")).status).toBe(200);
    expect((await bearer(usedKey)).status).toBe(200);
    expect((await bearer(created)).status).toBe(200);
    expect((await s.bearer("/mcp", fresh.access_token)).status).toBe(200);
    expect((await late.fetch(`${s.api}/auth/session`)).status).toBe(200);
    // Made under OLD and never used during the rotation: gone.
    expect((await grace.call("/api/me")).status).toBe(401);
    expect(graceToken).not.toBe("");
    expect((await bearer(idleKey)).status).toBe(401);
    expect((await s.bearer("/mcp", idle.access_token)).status).toBe(401);
    expect(
      (
        await s.form("/oauth/token", {
          grant_type: "refresh_token",
          client_id: PUBLIC_CLIENT,
          refresh_token: idle.refresh_token,
        })
      ).body,
    ).toMatchObject({ error: "invalid_grant" });
  });

  it("revokes the previous session at sign-in whichever secret it was made under", async () => {
    const s = await startMcp({ env: { POSTED_SECRET: OLD } });
    stacks.push(s);
    const ada = await s.person("ada");
    const before = ada.browser.cookie(s.api, s.auth.sessionCookie) ?? "";
    s.rekey({ POSTED_SECRET: NEW, POSTED_PREVIOUS_SECRETS: OLD });
    // Signing in again in the same browser, without using the old session.
    s.mock.setLogin({ sub: "ada", amr: ["mfa"] });
    await ada.browser.follow(`${s.api}/auth/sign-in`, {
      stopAt: (url) => url.origin === WEB,
    });
    expect(ada.browser.cookie(s.api, s.auth.sessionCookie)).not.toBe(before);
    const revoked = await rows<{ revoked: boolean }>(
      s,
      `SELECT revoked_at IS NOT NULL AS "revoked" FROM {schema}.sessions WHERE id_hash = $1`,
      [hashToken(deriveKey(OLD, "posted", "session"), before)],
    );
    expect(revoked).toEqual([{ revoked: true }]);
  });
});

describe.skipIf(!databaseUrl).each(adapters)(
  "re-hashing with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    const schema = uniqueSchema("rotate");
    const configFor = (secret: string, previous?: string) =>
      loadAuthConfig("posted", {
        POSTED_SECRET: secret,
        ...(previous ? { POSTED_PREVIOUS_SECRETS: previous } : {}),
        POSTED_OIDC_ISSUER: "https://auth.example.com/",
        POSTED_OIDC_CLIENT_ID: "posted",
        POSTED_OIDC_CLIENT_SECRET: "x",
        POSTED_WEB_ORIGIN: "https://posted.example.com",
        POSTED_API_ORIGIN: "https://api.posted.example.com",
        POSTED_AUTH_SCHEMA: schema,
      });
    const before = configFor(OLD);
    const during = configFor(NEW, OLD);
    const after = configFor(NEW);
    let userId = "";

    beforeAll(async () => {
      ({ sql, close } = adapter.open());
      await migrate(sql, { schema });
      const [user] = await sql.query<{ id: string }>(
        `INSERT INTO ${quoteIdent(schema)}.users (iss, sub, role) VALUES ('i', $1, 'member') RETURNING id`,
        [randomUUID()],
      );
      userId = user?.id ?? "";
    });
    afterAll(async () => {
      await dropSchemas(sql, [schema]);
      await close();
    });

    it("moves a session to the current key on its next use", async () => {
      const { token } = await createSessions({ sql, config: before }).create({
        userId,
        authenticatedAt: new Date(),
        amr: [],
        providerSid: null,
      });
      const { token: idle } = await createSessions({
        sql,
        config: before,
      }).create({
        userId,
        authenticatedAt: new Date(),
        amr: [],
        providerSid: null,
      });
      expect(
        await createSessions({ sql, config: after }).lookup(token),
      ).toBeNull();
      const found = await createSessions({ sql, config: during }).lookup(token);
      expect(found?.session.idHash).toBe(
        hashToken(deriveKey(NEW, "posted", "session"), token),
      );
      expect(found?.actor.credential.id).toBe(found?.session.idHash);
      // Twice is fine: the second finds it under the current key.
      expect(
        await createSessions({ sql, config: during }).lookup(token),
      ).not.toBeNull();
      expect(
        await createSessions({ sql, config: after }).lookup(token),
      ).not.toBeNull();
      expect(
        await createSessions({ sql, config: after }).lookup(idle),
      ).toBeNull();
      // A stray update still cannot change a session's id.
      await expect(
        sql.query(`UPDATE ${quoteIdent(schema)}.sessions SET id_hash = $1`, [
          "a".repeat(64),
        ]),
      ).rejects.toThrow(/never change/);
    });

    it("moves an API key to the current key on its next use", async () => {
      const issue = () =>
        createApiKeys({ sql, config: before }).create({
          userId,
          name: "k",
          ceiling: "member",
        });
      const { key } = await issue();
      const { key: idle } = await issue();
      expect(
        await createApiKeys({ sql, config: after }).verify(key),
      ).toBeNull();
      expect(
        await createApiKeys({ sql, config: during }).verify(key),
      ).not.toBeNull();
      const [row] = await sql.query<{ secretHash: string }>(
        `SELECT secret_hash AS "secretHash" FROM ${quoteIdent(schema)}.api_keys WHERE secret_hash = $1`,
        [hashToken(deriveKey(NEW, "posted", "api-key"), key)],
      );
      expect(row).toBeDefined();
      expect(
        await createApiKeys({ sql, config: after }).verify(key),
      ).not.toBeNull();
      expect(
        await createApiKeys({ sql, config: after }).verify(idle),
      ).toBeNull();
      await expect(
        sql.query(
          `UPDATE ${quoteIdent(schema)}.api_keys SET secret_hash = $1`,
          ["b".repeat(64)],
        ),
      ).rejects.toThrow(/never change/);
    });
  },
);
