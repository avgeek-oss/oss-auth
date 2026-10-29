// Policy types and arithmetic, with no framework imports, so that the root
// entry point (through config.ts) can use them without loading Hono.

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
  /** Signing out one session or every session, per user. */
  "sessions.write": { limit: 30, periodSeconds: 60 },
  /** Invalid API keys or OAuth bearer tokens presented, per IP. */
  "bearer.invalid": { limit: 60, periodSeconds: 60 },
  /** SCIM requests, per bearer token. */
  scim: { limit: 3000, periodSeconds: 60 },
} as const satisfies Readonly<Record<string, RateLimitPolicy>>;

/** The name of a built-in policy. */
export type RateLimitPolicyName = keyof typeof DEFAULT_RATE_LIMITS;

/**
 * The GCRA parameters of a policy, in whole microseconds (the timestamp
 * resolution): the emission interval, and the window a bucket may run
 * ahead of now (`burst` intervals). The interval is rounded up, so that the
 * sustained rate never exceeds `limit` per `periodSeconds`.
 */
export function gcraShape(policy: RateLimitPolicy): {
  readonly interval: number;
  readonly window: number;
} {
  const period = policy.periodSeconds * 1e6;
  let interval = Math.max(1, Math.ceil(period / policy.limit));
  // Floating-point division can land just above an exact quotient.
  if (interval > 1 && (interval - 1) * policy.limit >= period) interval -= 1;
  return { interval, window: interval * (policy.burst ?? policy.limit) };
}

/**
 * The policy named `name` in `overrides`, then in
 * {@link DEFAULT_RATE_LIMITS}, then `fallback`. Only a dictionary's own
 * entries count, so names such as `constructor` never resolve to
 * `Object.prototype` members.
 */
export function findPolicy(
  overrides: Readonly<Record<string, RateLimitPolicy>>,
  name: string,
  fallback?: RateLimitPolicy,
): RateLimitPolicy | undefined {
  if (Object.hasOwn(overrides, name)) return overrides[name];
  if (Object.hasOwn(DEFAULT_RATE_LIMITS, name))
    return (DEFAULT_RATE_LIMITS as Readonly<Record<string, RateLimitPolicy>>)[
      name
    ];
  return fallback;
}
