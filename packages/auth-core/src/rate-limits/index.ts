import type { AuthConfig } from "../config.js";
import { RateLimitedError, RateLimiterUnavailableError } from "../errors.js";
import { quoteIdent } from "../identifiers.js";
import { deriveKey } from "../keys.js";
import type { Sql } from "../postgres/sql.js";
import { hashToken } from "../tokens.js";

export {
  ipLimitKey,
  normaliseIp,
  parseTrustedProxies,
  resolveClientIp,
} from "./ip.js";
export {
  clientIpResolver,
  isLimitError,
  limitResponse,
  type LimitSurface,
} from "./responses.js";

/**
 * A rate: `limit` requests per `periodSeconds` on average, and at most
 * `burst` at once (default `limit`).
 */
export interface RateLimitPolicy {
  readonly limit: number;
  readonly periodSeconds: number;
  readonly burst?: number;
}

/** The outcome of {@link RateLimiter.consume}. */
export interface RateLimitResult {
  readonly allowed: boolean;
  /** Whole seconds until the request would be allowed; 0 when allowed. */
  readonly retryAfterSeconds: number;
  /** Requests that could still be made right now. */
  readonly remaining: number;
}

/**
 * The policies auth-core applies, by name. Each can be changed with
 * `<APP>_RATE_LIMITS`.
 */
export const DEFAULT_RATE_LIMITS = {
  /** `/auth/sign-in`, `/auth/callback` and `/auth/step-up`, per IP. */
  oidc: { limit: 30, periodSeconds: 60 },
  /** `/auth/backchannel-logout`, per IP. */
  "oidc.backchannel-logout": { limit: 60, periodSeconds: 60 },
  /** MCP `/oauth/authorize`, per IP. */
  "oauth.authorize": { limit: 30, periodSeconds: 60 },
  /** Client metadata document fetches (cache misses only), per IP. */
  "oauth.metadata.ip": { limit: 10, periodSeconds: 60 },
  /** Client metadata document fetches, per document host. */
  "oauth.metadata.host": { limit: 20, periodSeconds: 60 },
  /** Client metadata document fetches, across the whole app. */
  "oauth.metadata.global": { limit: 100, periodSeconds: 60 },
  /** `/oauth/token`, per IP. */
  "oauth.token.ip": { limit: 120, periodSeconds: 60 },
  /** `/oauth/token`, per client id. */
  "oauth.token.client": { limit: 60, periodSeconds: 60 },
  /** `/oauth/token` answers of `invalid_grant` or `invalid_client`, per client id and IP. */
  "oauth.token.failures": { limit: 10, periodSeconds: 60 },
  /** `/oauth/revoke`, per IP. */
  "oauth.revoke": { limit: 60, periodSeconds: 60 },
  /** Legacy dynamic client registration, per IP. */
  "oauth.register": { limit: 5, periodSeconds: 3600 },
  /** Consent decisions, per user. */
  "oauth.consent": { limit: 30, periodSeconds: 60 },
  /** API key creation and rotation, per user. */
  "api-keys.write": { limit: 30, periodSeconds: 60 },
  /** Invalid API keys or OAuth bearer tokens presented, per IP. */
  "bearer.invalid": { limit: 60, periodSeconds: 60 },
  /** SCIM requests, per bearer token. */
  scim: { limit: 3000, periodSeconds: 60 },
} as const satisfies Readonly<Record<string, RateLimitPolicy>>;

/** The name of a built-in policy. */
export type RateLimitPolicyName = keyof typeof DEFAULT_RATE_LIMITS;

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
   * it. For limits on failures: check first, then `consume` only when the
   * request fails.
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
  const hmacKey = deriveKey(config.secret, config.app, "rate-limit");
  const clock = () => options.now?.() ?? null;
  const T = "coalesce($1::timestamptz, now())";

  const policy: RateLimiter["policy"] = (name, fallback) => {
    const chosen =
      config.rateLimits.policies[name] ??
      (DEFAULT_RATE_LIMITS as Readonly<Record<string, RateLimitPolicy>>)[
        name
      ] ??
      fallback;
    if (!chosen)
      throw new TypeError(`No rate limit policy is named "${name}".`);
    return chosen;
  };

  /**
   * The GCRA parameters in whole microseconds, the timestamp resolution, so
   * that `burst` intervals add up to exactly the window: the emission
   * interval, and the window a bucket may run ahead of now.
   */
  const shape = (p: RateLimitPolicy) => {
    const interval = Math.max(1, Math.round((p.periodSeconds * 1e6) / p.limit));
    return { interval, window: interval * (p.burst ?? p.limit) };
  };

  const bucket = (name: string, key: string) =>
    hashToken(hmacKey, `${name}\u0000${key}`);

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
    const [row] = await guard(() =>
      sql.query<{ allowed: boolean; ahead: number }>(
        `INSERT INTO ${table} AS r (key_hash, tat, allowed, expires_at)
         VALUES ($2, ${T} + $3::bigint * ${US}, true, ${T} + $3::bigint * ${US})
         ON CONFLICT (key_hash) DO UPDATE SET
           allowed = ${fits},
           tat = CASE WHEN ${fits} THEN ${next} ELSE r.tat END,
           expires_at = CASE WHEN ${fits} THEN ${next} ELSE r.tat END
         RETURNING allowed, ${AHEAD} AS "ahead"`,
        [clock(), bucket(name, key), interval, window],
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
          `SELECT ${AHEAD} AS "ahead" FROM ${table}
           WHERE key_hash = $2 AND tat > ${T}`,
          [clock(), bucket(name, key)],
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
      const rows = await sql.query(
        `DELETE FROM ${table} WHERE expires_at < ${T} RETURNING 1`,
        [clock()],
      );
      return rows.length;
    },
  };
}
