import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  loadAuthConfig,
  RateLimitedError,
  RateLimiterUnavailableError,
  type AuthConfig,
} from "../../src/index.js";
import { migrate, quoteIdent, type Sql } from "../../src/postgres/index.js";
import {
  createRateLimiter,
  DEFAULT_RATE_LIMITS,
  type RateLimiter,
} from "../../src/rate-limits/index.js";
import {
  adapters,
  databaseUrl,
  dropSchemas,
  uniqueSchema,
} from "../postgres/support.js";

describe.skipIf(!databaseUrl).each(adapters)(
  "rate limiter with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    const schema = uniqueSchema("limits");
    const configFor = (env: Record<string, string> = {}): AuthConfig =>
      loadAuthConfig("posted", {
        POSTED_SECRET: "s".repeat(32),
        POSTED_OIDC_ISSUER: "https://auth.example.com/application/o/posted/",
        POSTED_OIDC_CLIENT_ID: "posted",
        POSTED_OIDC_CLIENT_SECRET: "x",
        POSTED_WEB_ORIGIN: "https://posted.example.com",
        POSTED_API_ORIGIN: "https://api.posted.example.com",
        POSTED_AUTH_SCHEMA: schema,
        ...env,
      });
    let now = new Date();
    const advance = (seconds: number) => {
      now = new Date(now.getTime() + seconds * 1000);
    };
    let limiter: RateLimiter;
    let counter = 0;
    const key = () => `key-${++counter}`;

    beforeAll(async () => {
      ({ sql, close } = adapter.open());
      await migrate(sql, { schema });
      limiter = createRateLimiter({
        sql,
        config: configFor({
          POSTED_RATE_LIMITS: JSON.stringify({
            oidc: { limit: 3, periodSeconds: 60 },
            "test.burst": { limit: 60, periodSeconds: 60, burst: 5 },
          }),
        }),
        now: () => now,
      });
    });
    afterAll(async () => {
      await dropSchemas(sql, [schema]);
      await close();
    });

    const policy = (limit: number, periodSeconds: number, burst?: number) => ({
      limit,
      periodSeconds,
      ...(burst === undefined ? {} : { burst }),
    });

    it("allows the limit, then refuses with the seconds until the next request fits", async () => {
      now = new Date();
      const k = key();
      const p = policy(3, 60);
      const results = [];
      for (let i = 0; i < 4; i++)
        results.push(await limiter.consume("t", k, p));
      expect(results).toEqual([
        { allowed: true, retryAfterSeconds: 0, remaining: 2 },
        { allowed: true, retryAfterSeconds: 0, remaining: 1 },
        { allowed: true, retryAfterSeconds: 0, remaining: 0 },
        { allowed: false, retryAfterSeconds: 20, remaining: 0 },
      ]);
      // One request is earned back every 20 seconds.
      advance(19);
      expect((await limiter.consume("t", k, p)).allowed).toBe(false);
      expect((await limiter.consume("t", k, p)).retryAfterSeconds).toBe(1);
      advance(1);
      expect(await limiter.consume("t", k, p)).toMatchObject({
        allowed: true,
        remaining: 0,
      });
      // After a whole period the bucket is full again.
      advance(60);
      expect(await limiter.consume("t", k, p)).toMatchObject({
        allowed: true,
        remaining: 2,
      });
      // Keys and policy names are separate buckets.
      expect((await limiter.consume("t", key(), p)).allowed).toBe(true);
      expect((await limiter.consume("u", k, p)).allowed).toBe(true);
    });

    it("lets a burst through at once and then the sustained rate", async () => {
      now = new Date();
      const k = key();
      const allowed = [];
      for (let i = 0; i < 7; i++)
        allowed.push((await limiter.consume("test.burst", k)).allowed);
      expect(allowed).toEqual([true, true, true, true, true, false, false]);
      advance(1);
      expect((await limiter.consume("test.burst", k)).allowed).toBe(true);
      expect((await limiter.consume("test.burst", k)).allowed).toBe(false);
    });

    it("allows exactly the limit when the period does not divide evenly", async () => {
      now = new Date();
      const k = key();
      let allowed = 0;
      for (let i = 0; i < 10; i++)
        if ((await limiter.consume("t", k, policy(7, 60))).allowed) allowed++;
      expect(allowed).toBe(7);
    });

    it("allows exactly the limit under 50 concurrent requests", async () => {
      now = new Date();
      const k = key();
      const results = await Promise.all(
        Array.from({ length: 50 }, () =>
          limiter.consume("t", k, policy(20, 60)),
        ),
      );
      expect(results.filter((r) => r.allowed)).toHaveLength(20);
      expect(results.filter((r) => !r.allowed)).toHaveLength(30);
    });

    it("checks without counting, and enforce throws RateLimitedError", async () => {
      now = new Date();
      const k = key();
      const p = policy(2, 60);
      for (let i = 0; i < 5; i++)
        expect(await limiter.check("t", k, p)).toEqual({
          allowed: true,
          retryAfterSeconds: 0,
          remaining: 2,
        });
      await limiter.enforce("t", k, p);
      await limiter.enforce("t", k, p);
      expect(await limiter.check("t", k, p)).toEqual({
        allowed: false,
        retryAfterSeconds: 30,
        remaining: 0,
      });
      const error = await limiter.enforce("t", k, p).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(RateLimitedError);
      expect(error).toMatchObject({
        code: "rate_limited",
        status: 429,
        reason: "t",
        retryAfterSeconds: 30,
      });
    });

    it("takes a policy from the config, then the defaults, then the fallback", () => {
      expect(limiter.policy("oidc")).toEqual({ limit: 3, periodSeconds: 60 });
      expect(limiter.policy("scim")).toEqual(DEFAULT_RATE_LIMITS.scim);
      expect(limiter.policy("app.custom", policy(1, 1))).toEqual(policy(1, 1));
      expect(() => limiter.policy("app.unknown")).toThrow(/app.unknown/);
    });

    it("stores only hashes, never the keys it limits", async () => {
      now = new Date();
      const secrets = [
        "203.0.113.77",
        "ada@example.com",
        "posted-cli",
        "2001:0db8:0001:0002::/64",
      ];
      for (const value of secrets)
        await limiter.consume("privacy", value, policy(5, 60));
      const rows = await sql.query(
        `SELECT * FROM ${quoteIdent(schema)}.rate_limit_buckets`,
      );
      const dump = JSON.stringify(rows);
      for (const value of secrets) expect(dump).not.toContain(value);
      expect(dump).not.toContain("privacy");
      for (const row of rows as { key_hash?: string; keyHash?: string }[])
        expect(row.key_hash ?? row.keyHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("purges buckets that have emptied", async () => {
      now = new Date();
      await sql.query(`DELETE FROM ${quoteIdent(schema)}.rate_limit_buckets`);
      await limiter.consume("t", key(), policy(1, 10));
      await limiter.consume("t", key(), policy(1, 1000));
      expect(await limiter.purgeExpired()).toBe(0);
      advance(11);
      expect(await limiter.purgeExpired()).toBe(1);
      advance(1000);
      expect(await limiter.purgeExpired()).toBe(1);
    });

    it("fails closed when the store fails", async () => {
      const broken: Sql = {
        query: () => Promise.reject(new Error("connection refused")),
        transaction: () => Promise.reject(new Error("connection refused")),
      };
      const failing = createRateLimiter({ sql: broken, config: configFor() });
      for (const call of [
        () => failing.consume("oidc", "x"),
        () => failing.check("oidc", "x"),
        () => failing.enforce("oidc", "x"),
      ]) {
        const error = await call().catch((e: unknown) => e);
        expect(error).toBeInstanceOf(RateLimiterUnavailableError);
        expect(error).toMatchObject({ status: 503, code: "unavailable" });
        expect((error as Error).message).not.toContain("connection refused");
      }
    });
  },
);
