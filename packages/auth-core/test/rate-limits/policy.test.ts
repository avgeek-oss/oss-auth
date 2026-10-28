import { describe, expect, it } from "vitest";
import { loadAuthConfig } from "../../src/index.js";
import type { Sql } from "../../src/postgres/index.js";
import { createRateLimiter } from "../../src/rate-limits/index.js";
import {
  DEFAULT_RATE_LIMITS,
  findPolicy,
  gcraShape,
} from "../../src/rate-limits/policy.js";

describe("gcraShape", () => {
  it("rounds the emission interval up, so the sustained rate never exceeds the limit", () => {
    // 1 second / 7 is 142857.14 microseconds: rounding to nearest would
    // allow 7.000007 a second.
    expect(gcraShape({ limit: 7, periodSeconds: 1 })).toEqual({
      interval: 142858,
      window: 142858 * 7,
    });
    // 1 second / 666667 is 1.49999 microseconds: rounding to nearest would
    // allow 1,000,000 a second.
    expect(gcraShape({ limit: 666_667, periodSeconds: 1 }).interval).toBe(2);
    expect(gcraShape({ limit: 3, periodSeconds: 60 }).interval).toBe(20e6);
    expect(gcraShape({ limit: 60, periodSeconds: 60, burst: 5 })).toEqual({
      interval: 1e6,
      window: 5e6,
    });
    for (const periodSeconds of [1, 7, 60, 61, 3600, 86400])
      for (let limit = 1; limit <= 2000; limit += 7) {
        const { interval } = gcraShape({ limit, periodSeconds });
        const period = periodSeconds * 1e6;
        expect(interval * limit).toBeGreaterThanOrEqual(period);
        // The smallest interval that does: no slower than it must be.
        expect((interval - 1) * limit).toBeLessThan(period);
      }
    for (const policy of Object.values(DEFAULT_RATE_LIMITS)) {
      const { interval } = gcraShape(policy);
      expect(interval * policy.limit).toBeGreaterThanOrEqual(
        policy.periodSeconds * 1e6,
      );
    }
  });
});

describe("policy lookup", () => {
  const names = [
    "constructor",
    "toString",
    "hasOwnProperty",
    "valueOf",
    "__proto__",
    "__defineGetter__",
  ];

  it("ignores Object.prototype members in both dictionaries", () => {
    const fallback = { limit: 1, periodSeconds: 1 };
    for (const name of names) {
      expect(findPolicy({}, name)).toBeUndefined();
      expect(findPolicy({}, name, fallback)).toBe(fallback);
    }
    expect(findPolicy({}, "scim")).toBe(DEFAULT_RATE_LIMITS.scim);
  });

  it("makes the limiter throw for a prototype name with no fallback", () => {
    const sql: Sql = {
      query: () => Promise.reject(new Error("unused")),
      transaction: () => Promise.reject(new Error("unused")),
    };
    const limiter = createRateLimiter({
      sql,
      config: loadAuthConfig("posted", {
        POSTED_SECRET: "s".repeat(32),
        POSTED_OIDC_ISSUER: "https://auth.example.com/application/o/posted/",
        POSTED_OIDC_CLIENT_ID: "posted",
        POSTED_OIDC_CLIENT_SECRET: "x",
        POSTED_WEB_ORIGIN: "https://posted.example.com",
        POSTED_API_ORIGIN: "https://api.posted.example.com",
        POSTED_RATE_LIMITS: JSON.stringify({
          constructor: { limit: 2, periodSeconds: 60 },
        }),
      }),
    });
    for (const name of names.filter((n) => n !== "constructor"))
      expect(() => limiter.policy(name)).toThrow(TypeError);
    // An override may use such a name as its own entry.
    expect(limiter.policy("constructor")).toEqual({
      limit: 2,
      periodSeconds: 60,
    });
    expect(limiter.policy("toString", { limit: 1, periodSeconds: 1 })).toEqual({
      limit: 1,
      periodSeconds: 1,
    });
  });
});
