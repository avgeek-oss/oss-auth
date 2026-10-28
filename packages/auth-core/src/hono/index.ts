import { Hono, type Context, type MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createRemoteJWKSet } from "jose";
import type { Actor, ActorUser } from "../actor.js";
import {
  createApiKeys,
  type ApiKeyRecord,
  type ApiKeys,
} from "../api-keys/index.js";
import type { AuthConfig } from "../config.js";
import { AuthRequestError, type AuthRequestErrorCode } from "../errors.js";
import { quoteIdent } from "../identifiers.js";
import {
  createOidcClient,
  type FetchLike,
  type OidcClient,
} from "../oidc/client.js";
import { postgresJtiStore } from "../oidc/jti-store.js";
import { verifyLogoutToken } from "../oidc/logout.js";
import { signInUser, type SignInOutcome } from "../oidc/users.js";
import type { Sql } from "../postgres/sql.js";
import {
  clientIpResolver,
  createRateLimiter,
  ipLimitKey,
  isLimitError,
  limitResponse,
  type LimitSurface,
  type RateLimiter,
  type RateLimitPolicy,
} from "../rate-limits/index.js";
import { isRole, roleAtLeast, type Role } from "../roles.js";
import { checkAuthSetup, type AuthSetupReport } from "../setup.js";
import {
  createSessions,
  type SessionRecord,
  type Sessions,
} from "../sessions/index.js";

/** The Hono variables auth-core sets on every request it sees. */
export interface AuthVariables<Ext extends object> {
  /** The signed-in caller, or `null`. Set by `middleware.actor`. */
  actor: Actor<Ext> | null;
  /** The caller's session, or `null`. Set by `middleware.actor`. */
  session: SessionRecord | null;
  /** The API key the caller presented, or `null`. Set by `middleware.actor`. */
  apiKey: ApiKeyRecord | null;
}

/** The Hono environment of the auth routes and middleware. */
export interface AuthEnv<Ext extends object> {
  Variables: AuthVariables<Ext>;
}

/** Options for {@link createAuth}. */
export interface CreateAuthOptions<Ext extends object> {
  readonly config: AuthConfig;
  readonly sql: Sql;
  /** Where the app mounts `routes`. Part of the callback URL. Default `/auth`. */
  readonly basePath?: string;
  readonly hooks?: {
    /** Adds app-specific fields to each actor, such as a workspace id. */
    readonly extendActor?: (user: ActorUser) => Ext | Promise<Ext>;
    /**
     * Whether `actor` may create an API key for `workspace`. Without this
     * hook, keys cannot have a workspace. auth-core stores the workspace
     * opaquely; the app must still enforce it on every request.
     */
    readonly authorizeWorkspace?: (
      actor: Actor<Ext>,
      workspace: string,
    ) => boolean | Promise<boolean>;
  };
  readonly stepUp?: {
    /** Require `mfa` in the provider's `amr` after step-up. Default true. */
    readonly requireMfa?: boolean;
    /** The `max_age` sent with step-up, in seconds. Default 300. */
    readonly maxAgeSeconds?: number;
  };
  /**
   * A header every state-changing request must carry, which a cross-site
   * form cannot set. Default `x-requested-with`.
   */
  readonly csrfHeader?: string;
  /**
   * The web path a failed callback redirects to, with `auth_error=<code>`
   * added. Default `/`.
   */
  readonly errorPath?: string;
  /** Relying-party settings, mostly for tests. */
  readonly oidc?: {
    readonly fetch?: FetchLike;
    readonly timeoutSeconds?: number;
    readonly clockToleranceSeconds?: number;
    readonly discoveryCacheSeconds?: number;
  };
  /** The current time, for tests. Defaults to the real clock. */
  readonly now?: () => Date;
  /**
   * The address of the request's peer, for runtimes other than
   * `@hono/node-server` (whose socket address is used by default), or for
   * a platform that hands over the client's address directly.
   * `<APP>_TRUSTED_PROXIES` still applies to what it returns.
   */
  readonly getClientIp?: (c: Context) => string | null | undefined;
  /** A rate limiter to share with other components. Created when left out. */
  readonly rateLimiter?: RateLimiter;
  /**
   * Where the startup self-check writes its summary, one line at a time.
   * Default: standard error. The check runs unless `<APP>_SELF_CHECK` is
   * false; see `checkAuthSetup`.
   */
  readonly log?: (line: string) => void;
}

/** What {@link createAuth} returns. */
export interface Auth<Ext extends object> {
  /**
   * Mount under `basePath`: `GET /sign-in`, `GET /callback`,
   * `POST /sign-out`, `GET /session`, `GET /step-up`,
   * `POST /backchannel-logout`, and the API key routes `GET /api-keys`,
   * `POST /api-keys`, `POST /api-keys/:id/rotate` and
   * `DELETE /api-keys/:id`.
   */
  readonly routes: Hono<AuthEnv<Ext>>;
  readonly middleware: {
    /**
     * Sets `actor`, `session` and `apiKey` (or null). A request with an
     * `Authorization: Bearer` header is authenticated by that API key alone
     * and the session cookie is ignored; otherwise by the session cookie.
     * Keys are never read from a query string or a cookie.
     */
    readonly actor: MiddlewareHandler<AuthEnv<Ext>>;
    /** 401 `unauthenticated` without an actor. */
    readonly requireActor: MiddlewareHandler<AuthEnv<Ext>>;
    /** 401 without an actor, 403 `forbidden` below `minimum`. */
    readonly requireRole: (minimum: Role) => MiddlewareHandler<AuthEnv<Ext>>;
    /**
     * 401 `step_up_required`, with `stepUpUrl`, unless the session
     * authenticated at the provider within `maxAgeSeconds`. 403
     * `step_up_unavailable` for an API key: sensitive actions need a
     * session.
     */
    readonly requireRecentAuth: (
      maxAgeSeconds: number,
    ) => MiddlewareHandler<AuthEnv<Ext>>;
    /**
     * On POST, PUT, PATCH and DELETE: 403 `origin_invalid` unless `Origin`
     * is the web origin, and 403 `csrf_header_missing` without the CSRF
     * header. Requests with an `Authorization: Bearer` header are skipped:
     * a cross-site page cannot send one, and they ignore cookies.
     */
    readonly trustedOrigin: MiddlewareHandler<AuthEnv<Ext>>;
    /**
     * CORS for the app's pages on `<APP>_WEB_ORIGIN`, for an API on another
     * host of the same site. Only that exact origin is allowed, with
     * credentials: other origins get no `Access-Control-Allow-Origin`, and
     * the header is never `*` or a reflected `Origin`. A preflight
     * (`OPTIONS` with `Access-Control-Request-Method`) is answered here with
     * 204, before any other middleware, allowing GET, POST, PUT, PATCH and
     * DELETE with `Content-Type`, the CSRF header, `Idempotency-Key` and
     * `Authorization`, cached for 10 minutes. Responses expose
     * `Retry-After`; step-up details are in the JSON body. Every response
     * varies on `Origin`.
     *
     * `routes` (and so the connected-apps routes under `basePath`) and the
     * MCP consent routes already use it. Add it to the app's own browser
     * routes, such as `/api/*`, before `actor`. Never add it to SCIM or the
     * OAuth token endpoints, which browsers do not call.
     */
    readonly cors: MiddlewareHandler<AuthEnv<Ext>>;
    /**
     * Limits requests under the policy `name` (one of the defaults, one set
     * in `<APP>_RATE_LIMITS`, or `fallback`), keyed by the client's IP (the
     * /64 for IPv6) or by what `key` returns; `null` skips the limit. Over
     * the limit it answers 429 with `Retry-After` in `surface`'s shape
     * (default JSON); if the store fails, 503.
     */
    readonly rateLimit: (
      name: string,
      key?: "ip" | ((c: Context<AuthEnv<Ext>>) => string | null),
      options?: {
        readonly fallback?: RateLimitPolicy;
        readonly surface?: LimitSurface;
      },
    ) => MiddlewareHandler<AuthEnv<Ext>>;
  };
  readonly sessions: Sessions<Ext>;
  /** The API key service, or `null` when no key prefix is configured. */
  readonly apiKeys: ApiKeys<Ext> | null;
  readonly oidc: OidcClient;
  /** The session cookie's name. */
  readonly sessionCookie: string;
  /** Where `routes` is mounted, such as `/auth`. */
  readonly basePath: string;
  /** The app's `hooks.extendActor`, for actors made elsewhere (MCP tokens). */
  readonly extendActor: (user: ActorUser) => Promise<Ext>;
  /** The rate limiter every auth-core route uses. */
  readonly rateLimiter: RateLimiter;
  /** The client's address, after `<APP>_TRUSTED_PROXIES`, or `null`. */
  readonly clientIp: (c: Context) => string | null;
  /** The per-IP limit key: the address, or the /64 for IPv6. */
  readonly ipKey: (c: Context) => string;
  /**
   * The startup self-check's report, once it finishes, or `null` when
   * `<APP>_SELF_CHECK` is false. Never rejects. To refuse to start on an
   * error, await `checkAuthSetup({ config, sql, failOnError: true })`
   * before serving instead.
   */
  readonly selfCheck: Promise<AuthSetupReport> | null;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const CORS_METHODS = "GET, POST, PUT, PATCH, DELETE";

/** The JSON body of every auth error response. */
export interface AuthErrorBody {
  readonly error: {
    readonly code: AuthRequestErrorCode;
    readonly message: string;
    readonly stepUpUrl?: string;
  };
}

function errorResponse(
  c: Context,
  error: AuthRequestError,
  extra: { stepUpUrl?: string } = {},
): Response {
  if (isLimitError(error)) return limitResponse(c, "json", error);
  c.header("Cache-Control", "no-store");
  return c.json(
    {
      error: { code: error.code, message: error.message, ...extra },
    } satisfies AuthErrorBody,
    error.status as 400,
  );
}

const unauthenticated = () =>
  new AuthRequestError("unauthenticated", "Sign in to continue.");

/** The token of an `Authorization: Bearer` header, `""` if malformed, or `null`. */
function bearerToken(c: Context): string | null {
  const header = c.req.header("authorization");
  if (header === undefined || !/^bearer(\s|$)/i.test(header)) return null;
  return /^bearer +([^\s]+) *$/i.exec(header)?.[1] ?? "";
}

/** An API key as the routes show it: never its secret or hash. */
function keyView(key: ApiKeyRecord) {
  return {
    id: key.id,
    name: key.name,
    ceiling: key.ceiling,
    workspace: key.workspace,
    createdAt: key.createdAt.toISOString(),
    expiresAt: key.expiresAt?.toISOString() ?? null,
    lastUsedAt: key.lastUsedAt?.toISOString() ?? null,
    replacedBy: key.replacedBy,
    graceUntil: key.graceUntil?.toISOString() ?? null,
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The session cookie name for an app and API origin. */
export function sessionCookieName(app: string, apiOrigin: string): string {
  return new URL(apiOrigin).protocol === "https:"
    ? `__Host-${app}-session`
    : `${app}-session`;
}

/**
 * Sign-in, sessions and access checks for a Hono API.
 *
 * Cookies are `__Host-<app>-session` and `__Host-<app>-oidc`: Secure,
 * HttpOnly, SameSite=Lax, Path=/. When the API origin is plain-HTTP
 * loopback (development), they drop the prefix and `Secure`.
 */
export function createAuth<Ext extends object = Record<never, never>>(
  options: CreateAuthOptions<Ext>,
): Auth<Ext> {
  const { config, sql } = options;
  const basePath = (options.basePath ?? "/auth").replace(/\/$/, "");
  const api = config.origins.api;
  const web = config.origins.web;
  const redirectUri = `${api}${basePath}/callback`;
  const stepUpUrl = `${api}${basePath}/step-up`;
  const requireMfa = options.stepUp?.requireMfa ?? true;
  const stepUpMaxAge = options.stepUp?.maxAgeSeconds ?? 300;
  const csrfHeader = (options.csrfHeader ?? "x-requested-with").toLowerCase();
  const errorPath = options.errorPath ?? "/";
  const clock = options.now;
  const nowMs = () => clock?.().getTime() ?? Date.now();
  const secure = new URL(api).protocol === "https:";
  const sessionCookie = sessionCookieName(config.app, api);

  const oidc = createOidcClient({
    config,
    redirectUri,
    now: nowMs,
    ...(options.oidc?.fetch ? { fetch: options.oidc.fetch } : {}),
    ...(options.oidc?.timeoutSeconds === undefined
      ? {}
      : { timeoutSeconds: options.oidc.timeoutSeconds }),
    ...(options.oidc?.clockToleranceSeconds === undefined
      ? {}
      : { clockToleranceSeconds: options.oidc.clockToleranceSeconds }),
    ...(options.oidc?.discoveryCacheSeconds === undefined
      ? {}
      : { discoveryCacheSeconds: options.oidc.discoveryCacheSeconds }),
  });
  const sessions = createSessions<Ext>({
    sql,
    config,
    ...(options.hooks?.extendActor
      ? { extendActor: options.hooks.extendActor }
      : {}),
    ...(clock ? { now: clock } : {}),
  });
  const apiKeys =
    config.apiKeys.prefix === null
      ? null
      : createApiKeys<Ext>({
          sql,
          config,
          ...(options.hooks?.extendActor
            ? { extendActor: options.hooks.extendActor }
            : {}),
          ...(clock ? { now: clock } : {}),
        });
  const rateLimiter =
    options.rateLimiter ??
    createRateLimiter({ sql, config, ...(clock ? { now: clock } : {}) });
  const clientIp = clientIpResolver(config.rateLimits, options.getClientIp);
  const ipKey = (c: Context) => ipLimitKey(clientIp(c) ?? "unknown");

  /** Runs `work`, answering a limit refusal or a store failure itself. */
  const limited = async (
    c: Context,
    surface: LimitSurface,
    work: () => Promise<unknown>,
  ): Promise<Response | null> => {
    try {
      await work();
      return null;
    } catch (error) {
      if (isLimitError(error)) return limitResponse(c, surface, error);
      throw error;
    }
  };

  const rateLimit: Auth<Ext>["middleware"]["rateLimit"] =
    (name, key = "ip", limitOptions = {}) =>
    async (c, next) => {
      const value = key === "ip" ? ipKey(c) : key(c);
      if (value !== null) {
        const refusal = await limited(c, limitOptions.surface ?? "json", () =>
          rateLimiter.enforce(name, value, limitOptions.fallback),
        );
        if (refusal) return refusal;
      }
      await next();
    };

  const jtis = postgresJtiStore(config.schema);
  let jwks:
    { uri: string; keys: ReturnType<typeof createRemoteJWKSet> } | undefined;

  const cookieOptions = {
    httpOnly: true,
    secure,
    sameSite: "Lax" as const,
    path: "/",
  };

  const setSessionCookie = (c: Context, token: string) =>
    setCookie(c, sessionCookie, token, {
      ...cookieOptions,
      maxAge: config.session.maxAgeSeconds,
    });

  const actor: MiddlewareHandler<AuthEnv<Ext>> = async (c, next) => {
    const token = bearerToken(c);
    if (token !== null) {
      const found =
        apiKeys && token !== "" ? await apiKeys.verify(token) : null;
      // Only invalid keys count, and a valid key is never refused, so a
      // neighbour's bad keys cannot throttle good ones.
      if (!found) {
        const failed = await limited(c, "json", () =>
          rateLimiter.enforce("bearer.invalid", ipKey(c)),
        );
        if (failed) return failed;
      }
      c.set("actor", found?.actor ?? null);
      c.set("session", null);
      c.set("apiKey", found?.key ?? null);
    } else {
      const found = await sessions.lookup(getCookie(c, sessionCookie));
      c.set("actor", found?.actor ?? null);
      c.set("session", found?.session ?? null);
      c.set("apiKey", null);
    }
    await next();
  };

  const requireActor: MiddlewareHandler<AuthEnv<Ext>> = async (c, next) => {
    if (!c.get("actor")) return errorResponse(c, unauthenticated());
    await next();
  };

  const requireRole =
    (minimum: Role): MiddlewareHandler<AuthEnv<Ext>> =>
    async (c, next) => {
      const current = c.get("actor");
      if (!current) return errorResponse(c, unauthenticated());
      if (!roleAtLeast(current.role, minimum))
        return errorResponse(
          c,
          new AuthRequestError(
            "forbidden",
            `This needs the ${minimum} role or higher.`,
          ),
        );
      await next();
    };

  /** The response that refuses a request without recent authentication. */
  const recentAuthRefusal = (
    c: Context<AuthEnv<Ext>>,
    maxAgeSeconds: number,
  ): Response | null => {
    const current = c.get("actor");
    const session = c.get("session");
    if (current && current.credential.kind !== "session")
      return errorResponse(
        c,
        new AuthRequestError(
          "step_up_unavailable",
          "This needs a signed-in session, not an API key.",
        ),
      );
    if (!current || !session) return errorResponse(c, unauthenticated());
    if (session.authenticatedAt.getTime() < nowMs() - maxAgeSeconds * 1000)
      return errorResponse(
        c,
        new AuthRequestError(
          "step_up_required",
          "Confirm it's you to continue: sign in again at your identity provider.",
        ),
        { stepUpUrl },
      );
    return null;
  };

  const requireRecentAuth =
    (maxAgeSeconds: number): MiddlewareHandler<AuthEnv<Ext>> =>
    async (c, next) => {
      const refusal = recentAuthRefusal(c, maxAgeSeconds);
      if (refusal) return refusal;
      await next();
    };

  const trustedOrigin: MiddlewareHandler<AuthEnv<Ext>> = async (c, next) => {
    if (SAFE_METHODS.has(c.req.method) || bearerToken(c) !== null)
      return next();
    if (c.req.header("origin") !== web)
      return errorResponse(
        c,
        new AuthRequestError(
          "origin_invalid",
          "This request must come from the app's own pages.",
        ),
      );
    if (!c.req.header(csrfHeader))
      return errorResponse(
        c,
        new AuthRequestError(
          "csrf_header_missing",
          `This request must carry the ${csrfHeader} header.`,
        ),
      );
    await next();
  };

  const corsAllowHeaders = [
    "Content-Type",
    csrfHeader,
    "Idempotency-Key",
    "Authorization",
  ].join(", ");
  const cors: MiddlewareHandler<AuthEnv<Ext>> = async (c, next) => {
    const allowed = c.req.header("origin") === web;
    const preflight =
      c.req.method === "OPTIONS" &&
      c.req.header("access-control-request-method") !== undefined;
    if (preflight) {
      c.header("Vary", "Origin", { append: true });
      if (allowed) {
        c.header("Access-Control-Allow-Origin", web);
        c.header("Access-Control-Allow-Credentials", "true");
        c.header("Access-Control-Allow-Methods", CORS_METHODS);
        c.header("Access-Control-Allow-Headers", corsAllowHeaders);
        c.header("Access-Control-Max-Age", "600");
      }
      return c.body(null, 204);
    }
    await next();
    c.header("Vary", "Origin", { append: true });
    if (allowed) {
      c.header("Access-Control-Allow-Origin", web);
      c.header("Access-Control-Allow-Credentials", "true");
      c.header("Access-Control-Expose-Headers", "Retry-After");
    }
  };

  const routes = new Hono<AuthEnv<Ext>>();
  routes.use("*", cors);

  routes.onError((error, c) => {
    if (error instanceof AuthRequestError) return errorResponse(c, error);
    throw error;
  });

  const oidcLimit = rateLimit("oidc", "ip", { surface: "plain" });
  const userKey = (c: Context<AuthEnv<Ext>>) => c.get("actor")?.user.id ?? null;

  routes.get("/sign-in", oidcLimit, async (c) => {
    const start = await oidc.start({
      purpose: "sign-in",
      returnTo: c.req.query("returnTo") ?? null,
    });
    setCookie(c, oidc.transactionCookie, start.transaction, {
      ...cookieOptions,
      maxAge: 600,
    });
    c.header("Cache-Control", "no-store");
    return c.redirect(start.url, 302);
  });

  routes.get("/step-up", oidcLimit, actor, async (c) => {
    const session = c.get("session");
    if (!session) throw unauthenticated();
    const start = await oidc.start({
      purpose: "step-up",
      returnTo: c.req.query("returnTo") ?? null,
      sessionIdHash: session.idHash,
      maxAgeSeconds: stepUpMaxAge,
    });
    setCookie(c, oidc.transactionCookie, start.transaction, {
      ...cookieOptions,
      maxAge: 600,
    });
    c.header("Cache-Control", "no-store");
    return c.redirect(start.url, 302);
  });

  routes.get("/callback", oidcLimit, async (c) => {
    const sealed = getCookie(c, oidc.transactionCookie);
    deleteCookie(c, oidc.transactionCookie, cookieOptions);
    c.header("Cache-Control", "no-store");
    const query = new URL(c.req.url).search;
    try {
      const { claims, transaction } = await oidc.finish(
        new URL(`${redirectUri}${query}`),
        sealed,
      );
      const now = nowMs();
      const authTime =
        typeof claims.auth_time === "number" ? claims.auth_time * 1000 : null;
      const amr = Array.isArray(claims.amr)
        ? claims.amr.filter((v): v is string => typeof v === "string")
        : [];

      if (transaction.purpose === "step-up") {
        const current = await sessions.lookup(getCookie(c, sessionCookie));
        if (!current || current.session.idHash !== transaction.sessionIdHash)
          throw new AuthRequestError(
            "step_up_failed",
            "Your session changed during the check. Sign in again.",
            { reason: "session" },
          );
        const [owner] = await sql.query<{ iss: string; sub: string | null }>(
          `SELECT iss, sub FROM ${quoteIdent(config.schema)}.users WHERE id = $1`,
          [current.session.userId],
        );
        if (owner?.iss !== claims.iss || owner.sub !== claims.sub)
          throw new AuthRequestError(
            "step_up_failed",
            "You confirmed as a different person. Sign in again as yourself.",
            { reason: "user" },
          );
        const floor =
          Math.floor(transaction.requestedAt / 1000) -
          oidc.clockToleranceSeconds;
        if (authTime === null || authTime / 1000 < floor)
          throw new AuthRequestError(
            "step_up_failed",
            "The identity provider did not ask you to sign in again.",
            { reason: "stale" },
          );
        if (requireMfa && !amr.includes("mfa"))
          throw new AuthRequestError(
            "step_up_failed",
            "Confirming needs multi-factor authentication at your identity provider.",
            { reason: "mfa_missing" },
          );
        if (
          !(await sessions.reauthenticate(current.session.idHash, {
            authenticatedAt: new Date(Math.min(authTime, now)),
            amr,
          }))
        )
          throw unauthenticated();
        return c.redirect(`${web}${transaction.returnTo}`, 303);
      }

      const previous = getCookie(c, sessionCookie);
      const outcome: SignInOutcome & { token?: string } = await sql.transaction(
        async (tx) => {
          const result = await signInUser(tx, config, claims);
          if (result.kind === "denied") return result;
          const created = await sessions.create(
            {
              userId: result.user.id,
              authenticatedAt: new Date(Math.min(authTime ?? now, now)),
              amr,
              providerSid: typeof claims.sid === "string" ? claims.sid : null,
            },
            tx,
          );
          return { ...result, token: created.token };
        },
      );
      if (outcome.kind === "denied")
        throw new AuthRequestError(
          "sign_in_denied",
          outcome.reason === "no_role" || outcome.reason === "unassigned"
            ? "You don't have access to this app. Ask an administrator to give you a role."
            : "Your account is not active in this app.",
          { reason: outcome.reason },
        );
      // A new token every sign-in; the browser's previous session ends.
      if (previous !== undefined) await sessions.revokeToken(previous);
      setSessionCookie(c, outcome.token ?? "");
      return c.redirect(`${web}${transaction.returnTo}`, 303);
    } catch (error) {
      if (!(error instanceof AuthRequestError)) throw error;
      const target = new URL(errorPath, web);
      target.searchParams.set("auth_error", error.code);
      if (error.reason)
        target.searchParams.set("auth_error_reason", error.reason);
      return c.redirect(target.href, 303);
    }
  });

  routes.post("/sign-out", trustedOrigin, actor, async (c) => {
    const session = c.get("session");
    if (session) await sessions.revoke(session.idHash);
    deleteCookie(c, sessionCookie, cookieOptions);
    let endSessionUrl: string | null = null;
    try {
      endSessionUrl = await oidc.endSessionUrl(`${web}/`);
    } catch {
      endSessionUrl = null;
    }
    c.header("Cache-Control", "no-store");
    return c.json({ endSessionUrl });
  });

  routes.get("/session", actor, (c) => {
    const current = c.get("actor");
    const session = c.get("session");
    if (!current || !session) throw unauthenticated();
    c.header("Cache-Control", "no-store");
    return c.json({
      user: current.user,
      role: current.role,
      ext: current.ext,
      session: {
        authenticatedAt: session.authenticatedAt.toISOString(),
        expiresAt: session.expiresAt.toISOString(),
        amr: session.amr,
      },
    });
  });

  routes.post(
    "/backchannel-logout",
    rateLimit("oidc.backchannel-logout"),
    async (c) => {
      c.header("Cache-Control", "no-store");
      const form = await c.req
        .parseBody()
        .catch(() => ({}) as Record<string, unknown>);
      const token = (form as Record<string, unknown>).logout_token;
      if (typeof token !== "string")
        throw new AuthRequestError(
          "logout_token_invalid",
          "The request has no logout_token.",
          { reason: "missing" },
        );
      const metadata = (await oidc.configuration()).serverMetadata();
      if (!metadata.jwks_uri)
        throw new AuthRequestError(
          "oidc_unavailable",
          "The provider publishes no keys.",
        );
      if (jwks?.uri !== metadata.jwks_uri)
        jwks = {
          uri: metadata.jwks_uri,
          keys: createRemoteJWKSet(new URL(metadata.jwks_uri)),
        };
      const logout = await verifyLogoutToken(token, {
        issuer: metadata.issuer,
        clientId: config.oidc.clientId,
        keys: jwks.keys,
        clockToleranceSeconds: oidc.clockToleranceSeconds,
        now: nowMs,
      });
      // Recording the jti and revoking commit together: if the revocation
      // fails, the provider's retry of the same token still works.
      await sql.transaction(async (tx) => {
        if (
          !(await jtis.remember(tx, logout.iss, logout.jti, logout.expiresAt))
        )
          throw new AuthRequestError(
            "logout_token_invalid",
            "The logout token was already used.",
            { reason: "replay" },
          );
        await sessions.revokeForProvider(logout, tx);
      });
      return c.body(null, 200);
    },
  );

  // API keys ---------------------------------------------------------------

  /** Seconds since sign-in within which a session may create an admin key. */
  const ADMIN_KEY_RECENT_AUTH = 600;

  const keyService = (): ApiKeys<Ext> => {
    if (!apiKeys)
      throw new AuthRequestError("not_found", "API keys are not enabled.");
    return apiKeys;
  };

  const readJson = async (c: Context): Promise<Record<string, unknown>> => {
    const text = await c.req.text();
    if (text.trim() === "") return {};
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
    if (typeof body !== "object" || body === null || Array.isArray(body))
      throw new AuthRequestError(
        "invalid_request",
        "The body must be a JSON object.",
        { reason: "body" },
      );
    return body as Record<string, unknown>;
  };

  // Key management needs a session: a key cannot mint or manage keys.
  routes.use("/api-keys/*", actor, trustedOrigin, async (c, next) => {
    keyService();
    const current = c.get("actor");
    if (!current) throw unauthenticated();
    if (current.credential.kind !== "session")
      throw new AuthRequestError(
        "forbidden",
        "API keys are managed from a signed-in session.",
        { reason: "session_required" },
      );
    c.header("Cache-Control", "no-store");
    await next();
  });

  /** The signed-in actor; the middleware above guarantees one. */
  const me = (c: Context<AuthEnv<Ext>>): Actor<Ext> => {
    const current = c.get("actor");
    if (!current) throw unauthenticated();
    return current;
  };

  routes.get("/api-keys", async (c) => {
    const current = me(c);
    const other = c.req.query("user");
    let userId = current.user.id;
    if (other !== undefined && other !== current.user.id) {
      if (!roleAtLeast(current.role, "admin"))
        throw new AuthRequestError(
          "forbidden",
          "Only an admin can see other people's keys.",
        );
      if (!UUID.test(other))
        throw new AuthRequestError("invalid_request", "No such user.", {
          reason: "user",
        });
      userId = other;
    }
    return c.json({
      apiKeys: (await keyService().list(userId)).map(keyView),
    });
  });

  routes.post("/api-keys", rateLimit("api-keys.write", userKey), async (c) => {
    const current = me(c);
    const body = await readJson(c);
    const { name, ceiling, workspace } = body;
    if (!isRole(ceiling))
      throw new AuthRequestError(
        "invalid_request",
        "ceiling must be viewer, member or admin.",
        { reason: "ceiling" },
      );
    if (ceiling === "admin") {
      const refusal = recentAuthRefusal(c, ADMIN_KEY_RECENT_AUTH);
      if (refusal) return refusal;
    }
    if (workspace !== undefined && workspace !== null) {
      const authorize = options.hooks?.authorizeWorkspace;
      if (!authorize)
        throw new AuthRequestError(
          "invalid_request",
          "This app does not issue keys for workspaces.",
          { reason: "workspace" },
        );
      if (
        typeof workspace !== "string" ||
        !(await authorize(current, workspace))
      )
        throw new AuthRequestError(
          "forbidden",
          "You cannot create keys for this workspace.",
          { reason: "workspace" },
        );
    }
    const expires = body.expiresInSeconds;
    if (
      expires !== undefined &&
      expires !== null &&
      typeof expires !== "number"
    )
      throw new AuthRequestError(
        "invalid_request",
        "expiresInSeconds must be a number of seconds or null.",
        { reason: "expiry" },
      );
    const issued = await keyService().create({
      userId: current.user.id,
      name: typeof name === "string" ? name : "",
      ceiling,
      workspace: (workspace as string | null | undefined) ?? null,
      ...(expires === undefined ? {} : { expiresInSeconds: expires }),
    });
    return c.json({ key: issued.key, apiKey: keyView(issued.record) }, 201);
  });

  routes.post(
    "/api-keys/:id/rotate",
    rateLimit("api-keys.write", userKey),
    async (c) => {
      const current = me(c);
      const body = await readJson(c);
      const grace = body.graceSeconds ?? 0;
      if (typeof grace !== "number")
        throw new AuthRequestError(
          "invalid_request",
          "graceSeconds must be a number of seconds.",
          { reason: "grace" },
        );
      const service = keyService();
      const existing = await service.get(c.req.param("id"));
      if (!existing || existing.userId !== current.user.id)
        throw new AuthRequestError("not_found", "No such API key.");
      if (existing.ceiling === "admin") {
        const refusal = recentAuthRefusal(c, ADMIN_KEY_RECENT_AUTH);
        if (refusal) return refusal;
      }
      const issued = await service.rotate(existing.id, {
        graceSeconds: grace,
        userId: current.user.id,
      });
      return c.json({ key: issued.key, apiKey: keyView(issued.record) }, 201);
    },
  );

  routes.delete("/api-keys/:id", async (c) => {
    const current = me(c);
    const admin = roleAtLeast(current.role, "admin");
    const revoked = await keyService().revoke(
      c.req.param("id"),
      admin ? {} : { userId: current.user.id },
    );
    if (!revoked) throw new AuthRequestError("not_found", "No such API key.");
    return c.body(null, 204);
  });

  const selfCheck = config.selfCheck
    ? checkAuthSetup({
        config,
        sql,
        basePath,
        ...(options.oidc?.fetch ? { fetch: options.oidc.fetch } : {}),
        log: options.log ?? ((line) => process.stderr.write(`${line}\n`)),
      }).catch((error: unknown): AuthSetupReport => ({
        ok: false,
        problems: [
          {
            level: "error",
            code: "self_check_failed",
            message: `The self-check itself failed: ${error instanceof Error ? error.message : String(error)}`,
            hint: "Run checkAuthSetup directly to see why.",
          },
        ],
      }))
    : null;

  return {
    selfCheck,
    routes,
    middleware: {
      actor,
      requireActor,
      requireRole,
      requireRecentAuth,
      trustedOrigin,
      cors,
      rateLimit,
    },
    sessions,
    apiKeys,
    oidc,
    sessionCookie,
    basePath,
    extendActor: async (user) =>
      options.hooks?.extendActor
        ? await options.hooks.extendActor(user)
        : ({} as Ext),
    rateLimiter,
    clientIp,
    ipKey,
  };
}
