import type { AuthConfig } from "../config.js";
import { RateLimitedError, RateLimiterUnavailableError } from "../errors.js";
import { quoteIdent } from "../identifiers.js";
import { deriveKeys } from "../keys.js";
import { sweepRateLimitBuckets } from "../jobs/sweeps.js";
import type { Sql } from "../postgres/sql.js";
import { hashToken } from "../tokens.js";
import {
  findPolicy,
  gcraShape as shape,
  type RateLimitPolicy,
  type RateLimitResult,
} from "./policy.js";

export {
  ipLimitKey,
  normaliseIp,
  parseTrustedProxies,
  resolveClientIp,
  TRUSTED_PROXY_HEADERS,
  type TrustedProxyHeader,
} from "./ip.js";
export {
  DEFAULT_RATE_LIMITS,
  type RateLimitPolicy,
  type RateLimitPolicyName,
  type RateLimitResult,
} from "./policy.js";
export {
  clientIpResolver,
  isLimitError,
  limitResponse,
  type LimitSurface,
} from "./responses.js";

/** Options for {@link createRateLimiter}. */
export interface RateLimiterOptions {
  readonly sql: Sql;
  /** Uses `app`, `secret`, `rateLimits` and `schema`. */
  readonly config: AuthConfig;
  /** The current time. Defaults to the database's `now()`. For tests. */
  readonly now?: () => Date;
}

/** Rate limits for one app, stored in `rate_limit_buckets`. */
export interface RateLimiter {
  /**
   * The policy in force for `name`: `<APP>_RATE_LIMITS`, then the built-in
   * default, then `fallback`.
   *
   * @throws `TypeError` when none of them names it.
   */
  policy(name: string, fallback?: RateLimitPolicy): RateLimitPolicy;
  /**
   * Counts one request for `key` under the policy `name` and says whether
   * it may go ahead. Atomic: concurrent calls never allow more than the
   * policy does.
   *
   * @throws {@link RateLimiterUnavailableError} when the store fails.
   */
  consume(
    name: string,
    key: string,
    fallback?: RateLimitPolicy,
  ): Promise<RateLimitResult>;
  /**
   * Whether one more request for `key` would be allowed, without counting
   * it. To limit only failures, `consume` or `enforce` after a request
   * fails instead, so that a request that succeeds is never refused.
   *
   * @throws {@link RateLimiterUnavailableError} when the store fails.
   */
  check(
    name: string,
    key: string,
    fallback?: RateLimitPolicy,
  ): Promise<RateLimitResult>;
  /**
   * `consume`, throwing {@link RateLimitedError} when the request is not
   * allowed.
   */
  enforce(name: string, key: string, fallback?: RateLimitPolicy): Promise<void>;
  /** Deletes buckets that have emptied, and returns how many. */
  purgeExpired(): Promise<number>;
}

/** Creates the rate limiter for one app. */
export function createRateLimiter(options: RateLimiterOptions): RateLimiter {
  const { sql, config } = options;
  const table = `${quoteIdent(config.schema)}.rate_limit_buckets`;
  // Buckets are keyed under the current secret's key. During a rotation,
  // a new bucket starts from where the same key's bucket under a previous
  // secret stood, so the change of key never resets anyone's limit.
  const [hmacKey, ...previousKeys] = deriveKeys(config, "rate-limit");
  if (!hmacKey) throw new Error("deriveKeys returned no key.");
  const clock = () => options.now?.() ?? null;
  const T = "coalesce($1::timestamptz, now())";

  const policy: RateLimiter["policy"] = (name, fallback) => {
    const chosen = findPolicy(config.rateLimits.policies, name, fallback);
    if (!chosen)
      throw new TypeError(`No rate limit policy is named "${name}".`);
    return chosen;
  };

  const bucket = (name: string, key: string) =>
    hashToken(hmacKey, `${name}\u0000${key}`);
  const previousBuckets = (name: string, key: string) =>
    previousKeys.map((k) => hashToken(k, `${name}\u0000${key}`));

  const guard = async <R>(work: () => Promise<R>): Promise<R> => {
    try {
      return await work();
    } catch (error) {
      throw new RateLimiterUnavailableError({ cause: error });
    }
  };

  const US = "interval '1 microsecond'";
  const AHEAD = `(extract(epoch FROM tat - ${T}) * 1000000)::double precision`;

  const consume: RateLimiter["consume"] = async (name, key, fallback) => {
    const { interval, window } = shape(policy(name, fallback));
    // GCRA: the bucket's theoretical arrival time (tat) moves one interval
    // later per allowed request, and a request is allowed while that stays
    // within `window` of now. Every SET expression sees the old row, and the
    // row is locked for the statement, so concurrent requests queue.
    const next = `GREATEST(r.tat, ${T}) + $3::bigint * ${US}`;
    const fits = `${next} - ${T} <= $4::bigint * ${US}`;
    // A new bucket starts at now, or where a previous secret's bucket for
    // the same key stands ($5), whichever is later.
    const firstFits = `p.base + $3::bigint * ${US} - ${T} <= $4::bigint * ${US}`;
    const firstTat = `CASE WHEN ${firstFits} THEN p.base + $3::bigint * ${US} ELSE p.base END`;
    const [row] = await guard(() =>
      sql.query<{ allowed: boolean; ahead: number }>(
        `INSERT INTO ${table} AS r (key_hash, tat, allowed, expires_at)
         SELECT $2, ${firstTat}, ${firstFits}, ${firstTat}
         FROM (SELECT GREATEST(${T}, coalesce(
           (SELECT max(o.tat) FROM ${table} o WHERE o.key_hash = ANY($5::text[])),
           ${T})) AS base) p
         ON CONFLICT (key_hash) DO UPDATE SET
           allowed = ${fits},
           tat = CASE WHEN ${fits} THEN ${next} ELSE r.tat END,
           expires_at = CASE WHEN ${fits} THEN ${next} ELSE r.tat END
         RETURNING allowed, ${AHEAD} AS "ahead"`,
        [
          clock(),
          bucket(name, key),
          interval,
          window,
          previousBuckets(name, key),
        ],
      ),
    );
    if (!row) throw new RateLimiterUnavailableError();
    // After an allowed request, `ahead` is how far the bucket now runs
    // ahead; after a refused one, how far it already did.
    return row.allowed
      ? {
          allowed: true,
          retryAfterSeconds: 0,
          remaining: Math.floor((window - Math.round(row.ahead)) / interval),
        }
      : {
          allowed: false,
          retryAfterSeconds: Math.max(
            1,
            Math.ceil((Math.round(row.ahead) + interval - window) / 1e6),
          ),
          remaining: 0,
        };
  };

  return {
    policy,
    consume,

    async check(name, key, fallback) {
      const { interval, window } = shape(policy(name, fallback));
      const [row] = await guard(() =>
        sql.query<{ ahead: number }>(
          `SELECT max(${AHEAD}) AS "ahead" FROM ${table}
           WHERE key_hash = ANY($2::text[]) AND tat > ${T}`,
          [clock(), [bucket(name, key), ...previousBuckets(name, key)]],
        ),
      );
      const ahead = Math.round(row?.ahead ?? 0);
      return ahead + interval <= window
        ? {
            allowed: true,
            retryAfterSeconds: 0,
            remaining: Math.floor((window - ahead) / interval),
          }
        : {
            allowed: false,
            retryAfterSeconds: Math.max(
              1,
              Math.ceil((ahead + interval - window) / 1e6),
            ),
            remaining: 0,
          };
    },

    async enforce(name, key, fallback) {
      const result = await consume(name, key, fallback);
      if (!result.allowed)
        throw new RateLimitedError(name, result.retryAfterSeconds);
    },

    async purgeExpired() {
      const now = options.now;
      return (
        await sweepRateLimitBuckets({ sql, config, ...(now ? { now } : {}) })
      ).deleted;
    },
  };
}
