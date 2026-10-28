import { Hono, type Context, type MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createRemoteJWKSet } from "jose";
import { auditActor } from "../audit.js";
import type { Actor, ActorUser } from "../actor.js";
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
import { roleAtLeast, type Role } from "../roles.js";
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
}

/** What {@link createAuth} returns. */
export interface Auth<Ext extends object> {
  /**
   * Mount under `basePath`: `GET /sign-in`, `GET /callback`,
   * `POST /sign-out`, `GET /session`, `GET /step-up` and
   * `POST /backchannel-logout`.
   */
  readonly routes: Hono<AuthEnv<Ext>>;
  readonly middleware: {
    /** Reads the session cookie and sets `actor` and `session` (or null). */
    readonly actor: MiddlewareHandler<AuthEnv<Ext>>;
    /** 401 `unauthenticated` without an actor. */
    readonly requireActor: MiddlewareHandler<AuthEnv<Ext>>;
    /** 401 without an actor, 403 `forbidden` below `minimum`. */
    readonly requireRole: (minimum: Role) => MiddlewareHandler<AuthEnv<Ext>>;
    /**
     * 401 `step_up_required`, with `stepUpUrl`, unless the session
     * authenticated at the provider within `maxAgeSeconds`.
     */
    readonly requireRecentAuth: (
      maxAgeSeconds: number,
    ) => MiddlewareHandler<AuthEnv<Ext>>;
    /**
     * On POST, PUT, PATCH and DELETE: 403 `origin_invalid` unless `Origin`
     * is the web origin, and 403 `csrf_header_missing` without the CSRF
     * header.
     */
    readonly trustedOrigin: MiddlewareHandler<AuthEnv<Ext>>;
  };
  readonly sessions: Sessions<Ext>;
  readonly oidc: OidcClient;
  /** The session cookie's name. */
  readonly sessionCookie: string;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

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
    const found = await sessions.lookup(getCookie(c, sessionCookie));
    c.set("actor", found?.actor ?? null);
    c.set("session", found?.session ?? null);
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

  const requireRecentAuth =
    (maxAgeSeconds: number): MiddlewareHandler<AuthEnv<Ext>> =>
    async (c, next) => {
      const session = c.get("session");
      if (!c.get("actor") || !session)
        return errorResponse(c, unauthenticated());
      if (session.authenticatedAt.getTime() < nowMs() - maxAgeSeconds * 1000)
        return errorResponse(
          c,
          new AuthRequestError(
            "step_up_required",
            "Confirm it's you to continue: sign in again at your identity provider.",
          ),
          { stepUpUrl },
        );
      await next();
    };

  const trustedOrigin: MiddlewareHandler<AuthEnv<Ext>> = async (c, next) => {
    if (SAFE_METHODS.has(c.req.method)) return next();
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

  const routes = new Hono<AuthEnv<Ext>>();

  routes.onError((error, c) => {
    if (error instanceof AuthRequestError) return errorResponse(c, error);
    throw error;
  });

  routes.get("/sign-in", async (c) => {
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

  routes.get("/step-up", actor, async (c) => {
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

  routes.get("/callback", async (c) => {
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

      const previous = sessions.hash(getCookie(c, sessionCookie));
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
          outcome.reason === "no_role"
            ? "You don't have access to this app. Ask an administrator to give you a role."
            : "Your account is not active in this app.",
          { reason: outcome.reason },
        );
      // A new token every sign-in; the browser's previous session ends.
      if (previous !== null)
        await sessions.revoke(previous, "replaced", {
          type: "user",
          userId: outcome.user.id,
          credential: { kind: "session", id: previous },
        });
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
    const current = c.get("actor");
    const session = c.get("session");
    if (current && session)
      await sessions.revoke(session.idHash, "sign_out", auditActor(current));
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

  routes.post("/backchannel-logout", async (c) => {
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
      if (!(await jtis.remember(tx, logout.iss, logout.jti, logout.expiresAt)))
        throw new AuthRequestError(
          "logout_token_invalid",
          "The logout token was already used.",
          { reason: "replay" },
        );
      await sessions.revokeForProvider(logout, tx);
    });
    return c.body(null, 200);
  });

  return {
    routes,
    middleware: {
      actor,
      requireActor,
      requireRole,
      requireRecentAuth,
      trustedOrigin,
    },
    sessions,
    oidc,
    sessionCookie,
  };
}
