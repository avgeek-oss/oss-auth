import type { Context } from "hono";
import { RateLimitedError, RateLimiterUnavailableError } from "../errors.js";
import { parseTrustedProxies, resolveClientIp } from "./ip.js";

/**
 * How a route answers a refusal:
 * - `json`: auth-core's `{ error: { code, message } }`;
 * - `oauth`: RFC 6749 `{ error: "temporarily_unavailable", error_description }`;
 * - `scim`: the RFC 7644 Error schema;
 * - `plain`: text, for browser navigations that must not redirect.
 */
export type LimitSurface = "json" | "oauth" | "scim" | "plain";

/** True for the errors {@link limitResponse} answers. */
export function isLimitError(
  error: unknown,
): error is RateLimitedError | RateLimiterUnavailableError {
  return (
    error instanceof RateLimitedError ||
    error instanceof RateLimiterUnavailableError
  );
}

/**
 * The response to a rate limit refusal (429 with `Retry-After`) or to the
 * limiter's store failing (503, fail closed), in the route's shape. Never a
 * redirect, and never cached.
 */
export function limitResponse(
  c: Context,
  surface: LimitSurface,
  error: RateLimitedError | RateLimiterUnavailableError,
): Response {
  const status = error instanceof RateLimitedError ? 429 : 503;
  c.header("Cache-Control", "no-store");
  if (error instanceof RateLimitedError)
    c.header("Retry-After", String(error.retryAfterSeconds));
  switch (surface) {
    case "oauth":
      return c.json(
        { error: "temporarily_unavailable", error_description: error.message },
        status,
      );
    case "scim":
      return c.body(
        JSON.stringify({
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: String(status),
          detail: error.message,
        }),
        status,
        { "content-type": "application/scim+json; charset=utf-8" },
      );
    case "plain":
      return c.text(error.message, status);
    default:
      return c.json(
        { error: { code: error.code, message: error.message } },
        status,
      );
  }
}

/** The socket peer as `@hono/node-server` exposes it, without importing it. */
function socketPeer(c: Context): string | null {
  const env = c.env as
    { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  return env?.incoming?.socket?.remoteAddress ?? null;
}

/**
 * A function from a request to its client's address: the socket peer (or
 * what `getPeer` returns, for other runtimes), and through
 * `X-Forwarded-For` or `Forwarded` when the peer is one of
 * `<APP>_TRUSTED_PROXIES`. `null` when no peer address is known.
 */
export function clientIpResolver(
  trustedProxies: readonly string[],
  getPeer: (c: Context) => string | null | undefined = socketPeer,
): (c: Context) => string | null {
  const trusted = parseTrustedProxies(trustedProxies);
  return (c) =>
    resolveClientIp({
      peer: getPeer(c),
      trusted,
      forwarded: c.req.header("forwarded"),
      xForwardedFor: c.req.header("x-forwarded-for"),
    });
}
