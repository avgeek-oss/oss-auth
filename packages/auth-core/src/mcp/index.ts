import { createHash, randomUUID } from "node:crypto";
import { Hono, type Context, type MiddlewareHandler } from "hono";
import { createActor, type Actor } from "../actor.js";
import type { AuthConfig } from "../config.js";
import { AuthRequestError } from "../errors.js";
import type { Auth, AuthEnv, AuthErrorBody } from "../hono/index.js";
import { quoteIdent } from "../identifiers.js";
import { deriveKeys } from "../keys.js";
import {
  sweepOAuthCodes,
  sweepOAuthRequests,
  sweepOAuthTokens,
} from "../jobs/sweeps.js";
import type { Sql, SqlQueryable } from "../postgres/sql.js";
import { isLimitError, limitResponse } from "../rate-limits/index.js";
import { isLoopbackRedirect, redirectMatches } from "../redirect-uris.js";
import {
  isRole,
  maxRole,
  minRole,
  roleAtLeast,
  ROLES,
  type Role,
} from "../roles.js";
import {
  constantTimeEqual,
  generateToken,
  hashToken,
  hashTokens,
} from "../tokens.js";
import {
  ClientError,
  createClientStore,
  readClientMetadata,
  type ClientKind,
  type OAuthClient,
} from "./clients.js";
import type { MetadataFetchOptions } from "./fetch.js";

export {
  cacheSeconds,
  fetchMetadataDocument,
  isPublicAddress,
  MetadataFetchError,
  type MetadataFetchOptions,
  type ResolvedAddress,
  type TransportResponse,
} from "./fetch.js";
export {
  ClientError,
  isMetadataDocumentId,
  MAX_METADATA_CACHE_SECONDS,
  readClientMetadata,
  type ClientKind,
  type OAuthClient,
} from "./clients.js";

/** Seconds an authorization code is valid. */
export const CODE_TTL_SECONDS = 60;
/** Seconds an access token is valid. */
export const ACCESS_TOKEN_TTL_SECONDS = 900;
/** Seconds a refresh token family survives without use. */
export const REFRESH_IDLE_SECONDS = 30 * 86400;
/** Seconds a refresh token family survives in all. */
export const REFRESH_ABSOLUTE_SECONDS = 90 * 86400;
/** Seconds a consent request waits for a decision. */
export const CONSENT_TTL_SECONDS = 600;
/** Seconds since sign-in within which a session may approve an `admin` grant. */
export const ADMIN_GRANT_RECENT_AUTH_SECONDS = 600;

/** A protected resource, such as the app's MCP endpoint. */
export interface McpResource {
  /**
   * The path on the API origin, such as `/mcp` or `/v1`. The resource
   * identifier (RFC 8707) is the API origin followed by this path, and its
   * metadata (RFC 9728) is at `/.well-known/oauth-protected-resource` plus
   * this path.
   */
  readonly path: string;
  /** A human-readable name, for the consent page and the metadata. */
  readonly name?: string;
  /** The least role a token needs here. Default `viewer`. */
  readonly scope?: Role;
}

/** A configured resource with its identifiers. */
export interface McpResourceInfo {
  readonly path: string;
  readonly name: string;
  readonly scope: Role;
  /** The RFC 8707 resource identifier, such as `https://api.example.com/mcp`. */
  readonly uri: string;
  /** Its RFC 9728 metadata URL. */
  readonly metadataUrl: string;
}

/** Callbacks for app-specific grant shaping. */
export interface McpHooks<Ext extends object> {
  /**
   * Checks the `restrictions` a person chose on the consent page, such as
   * the boards a grant may touch, and returns what to store. Throw
   * {@link AuthRequestError} to refuse. Without this hook, consent with
   * restrictions is refused. auth-core stores them opaquely; the app must
   * enforce them on every request.
   */
  readonly validateRestrictions?: (
    actor: Actor<Ext>,
    restrictions: unknown,
    context: { readonly clientId: string; readonly resource: string },
  ) =>
    | Readonly<Record<string, unknown>>
    | Promise<Readonly<Record<string, unknown>>>;
}

/** Options for {@link createMcpAuth}. */
export interface CreateMcpAuthOptions<Ext extends object> {
  readonly config: AuthConfig;
  readonly sql: Sql;
  /** The app's `createAuth` result: sessions, sign-in and middleware. */
  readonly auth: Auth<Ext>;
  /** The protected resources. At least one. */
  readonly resources: readonly McpResource[];
  readonly hooks?: McpHooks<Ext>;
  /** The web origin's consent page. Default `/oauth/consent`. */
  readonly consentPath?: string;
  /** How client metadata documents are fetched. For tests. */
  readonly metadataFetch?: MetadataFetchOptions;
  /** The current time. Defaults to the database's `now()`. For tests. */
  readonly now?: () => Date;
}

/** A grant as the connected-apps routes show it. */
export interface GrantRecord {
  readonly id: string;
  readonly userId: string;
  readonly clientId: string;
  readonly clientName: string;
  readonly logoUri: string | null;
  readonly ceiling: Role;
  readonly resources: readonly string[];
  readonly restrictions: Readonly<Record<string, unknown>> | null;
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
}

/** What {@link createMcpAuth} returns. */
export interface McpAuth<Ext extends object> {
  /**
   * Mount at the root of the API (`app.route("/", mcp.routes)`): the
   * metadata documents, `/oauth/authorize`, `/oauth/token`,
   * `/oauth/revoke`, `/oauth/register` (legacy DCR only), the consent API
   * under `/oauth/consent/:id`, and `<auth basePath>/connected-apps`.
   */
  readonly routes: Hono<AuthEnv<Ext>>;
  /**
   * Requires a bearer access token issued for `resource` (a configured
   * path), and sets an `oauth` actor with the grant's effective role and
   * restrictions. 401 with a `WWW-Authenticate` challenge without a valid
   * token; 403 `insufficient_scope` below `role` (default the resource's
   * `scope`).
   */
  readonly requireMcpToken: (options: {
    readonly resource: string;
    readonly role?: Role;
  }) => MiddlewareHandler<AuthEnv<Ext>>;
  /** The authorization server's issuer: the API origin. */
  readonly issuer: string;
  readonly resources: readonly McpResourceInfo[];
  /** A user's live grants, newest first. */
  listGrants(userId: string): Promise<GrantRecord[]>;
  /** Revokes a grant, optionally only one of `userId`'s. */
  revokeGrant(
    id: string,
    options?: { readonly userId?: string },
  ): Promise<boolean>;
  /**
   * Deletes consent requests, codes and tokens past their lifetime (the
   * sweeps of `@avgeek-oss/auth-core/jobs`), and returns how many of each.
   * `runAuthJobs` runs these and every other sweep; prefer it.
   */
  purgeExpired(): Promise<{
    readonly requests: number;
    readonly codes: number;
    readonly tokens: number;
  }>;
}

/** An OAuth error response (RFC 6749 §5.2). */
class OAuthError extends Error {
  constructor(
    readonly error: string,
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CHALLENGE = /^[A-Za-z0-9_-]{43,128}$/;
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const MAX_FORM_BYTES = 16384;

function authError(
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

function oauthJson(c: Context, error: OAuthError): Response {
  c.header("Cache-Control", "no-store");
  if (error.status === 401) c.header("WWW-Authenticate", 'Basic realm="oauth"');
  return c.json(
    { error: error.error, error_description: error.message },
    error.status as 400,
  );
}

/** The role a scope parameter asks for: the highest role named, or null. */
function requestedRole(scope: string | null): Role | null | undefined {
  if (scope === null || scope.trim() === "") return null;
  let best: Role | null = null;
  for (const entry of scope.trim().split(/ +/)) {
    if (!isRole(entry)) return undefined;
    best = best === null ? entry : maxRole(best, entry);
  }
  return best;
}

/** The value of a `WWW-Authenticate: Bearer` challenge (RFC 6750, RFC 9728). */
export function bearerChallenge(params: {
  readonly error?: "invalid_token" | "insufficient_scope";
  readonly description?: string;
  readonly resourceMetadata: string;
  readonly scope: string;
}): string {
  const quote = (value: string) => `"${value.replace(/["\\]/g, "\\$&")}"`;
  const parts: string[] = [];
  if (params.error) parts.push(`error=${quote(params.error)}`);
  if (params.description)
    parts.push(`error_description=${quote(params.description)}`);
  parts.push(`resource_metadata=${quote(params.resourceMetadata)}`);
  parts.push(`scope=${quote(params.scope)}`);
  return `Bearer ${parts.join(", ")}`;
}

/**
 * The OAuth 2.1 authorization server for MCP clients, and the middleware
 * that protects the app's resources with its tokens. It follows the MCP
 * authorization specification (2026-07-28): RFC 8414 metadata, RFC 9728
 * protected resource metadata, PKCE with S256 only, RFC 8707 resource
 * indicators with audience-bound tokens, RFC 9207 `iss` on every
 * authorization response, client metadata documents, and rotating refresh
 * tokens. The scopes are the role names.
 *
 * People sign in through the app's OpenID provider as usual; consent is a
 * page on the web origin that calls the consent API with the session.
 */
export function createMcpAuth<Ext extends object = Record<never, never>>(
  options: CreateMcpAuthOptions<Ext>,
): McpAuth<Ext> {
  const { config, sql, auth } = options;
  const issuer = config.origins.api;
  const web = config.origins.web;
  const consentPath = options.consentPath ?? "/oauth/consent";
  const schema = quoteIdent(config.schema);
  const t = {
    users: `${schema}.users`,
    clients: `${schema}.oauth_clients`,
    requests: `${schema}.oauth_requests`,
    grants: `${schema}.oauth_grants`,
    codes: `${schema}.oauth_codes`,
    tokens: `${schema}.oauth_tokens`,
  };
  // New values are hashed under the current secret's key (`keys`); lookups
  // also try the keys of <APP>_PREVIOUS_SECRETS (`rings`). None of these
  // live long enough to need re-hashing: refresh tokens rotate on use.
  const rings = {
    request: deriveKeys(config, "oauth-request"),
    code: deriveKeys(config, "oauth-code"),
    access: deriveKeys(config, "oauth-access-token"),
    refresh: deriveKeys(config, "oauth-refresh-token"),
  };
  const first = (ring: readonly Buffer[]) => {
    const key = ring[0];
    if (!key) throw new Error("deriveKeys returned no key.");
    return key;
  };
  const keys = {
    request: first(rings.request),
    code: first(rings.code),
    access: first(rings.access),
    refresh: first(rings.refresh),
  };
  const scimRoles = config.roleSource === "scim";
  const clock = () => options.now?.() ?? null;
  // $1 is always the clock; null means the database's now().
  const T = "coalesce($1::timestamptz, now())";
  const limiter = auth.rateLimiter;
  const clients = createClientStore({
    config,
    table: t.clients,
    clock,
    ...(options.metadataFetch ? { fetch: options.metadataFetch } : {}),
  });

  if (options.resources.length === 0)
    throw new TypeError("createMcpAuth needs at least one resource.");
  const resources: McpResourceInfo[] = options.resources.map((r) => {
    if (
      !/^\/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-]$/.test(r.path) ||
      r.path.includes("//")
    )
      throw new TypeError(
        `Resource path "${r.path}" must start with / and not end with one.`,
      );
    return {
      path: r.path,
      name: r.name ?? r.path.slice(1),
      scope: r.scope ?? "viewer",
      uri: `${issuer}${r.path}`,
      metadataUrl: `${issuer}/.well-known/oauth-protected-resource${r.path}`,
    };
  });
  if (new Set(resources.map((r) => r.path)).size !== resources.length)
    throw new TypeError("Resource paths must be unique.");
  const byUri = new Map(resources.map((r) => [r.uri, r]));

  /** SQL for an owner who may use a grant: active, undeleted, with a role. */
  const usableOwner = (scimParam: string) => `u.active AND u.deleted_at IS NULL
    AND u.role IS NOT NULL
    AND (${scimParam}::boolean IS NOT TRUE OR u.role_source = 'scim')`;

  async function usableGrant(db: SqlQueryable, grantId: string) {
    const [row] = await db.query<{
      id: string;
      ceiling: Role;
      role: Role;
      clientId: string;
    }>(
      `SELECT g.id, g.ceiling, u.role, g.client_id AS "clientId"
       FROM ${t.grants} g JOIN ${t.users} u ON u.id = g.user_id
       WHERE g.id = $2 AND g.revoked_at IS NULL AND ${usableOwner("$1")}
       FOR SHARE OF g`,
      [scimRoles, grantId],
    );
    return row ?? null;
  }

  async function revokeGrantTx(db: SqlQueryable, grantId: string) {
    await db.query(
      `UPDATE ${t.grants} SET revoked_at = GREATEST(${T}, created_at)
       WHERE id = $2 AND revoked_at IS NULL`,
      [clock(), grantId],
    );
    await db.query(
      `UPDATE ${t.tokens} SET revoked_at = ${T}
       WHERE grant_id = $2 AND revoked_at IS NULL`,
      [clock(), grantId],
    );
  }

  async function issueTokens(
    db: SqlQueryable,
    input: {
      grantId: string;
      resource: string;
      familyId: string;
      familyExpiresAt: Date | null;
      role: Role;
    },
  ) {
    const access = generateToken();
    const refresh = generateToken();
    await db.query(
      `INSERT INTO ${t.tokens}
         (token_hash, kind, grant_id, family_id, resource, created_at, expires_at)
       VALUES ($2, 'access', $3, $4, $5, ${T}, ${T} + make_interval(secs => $6))`,
      [
        clock(),
        hashToken(keys.access, access),
        input.grantId,
        input.familyId,
        input.resource,
        ACCESS_TOKEN_TTL_SECONDS,
      ],
    );
    await db.query(
      `INSERT INTO ${t.tokens}
         (token_hash, kind, grant_id, family_id, resource, created_at,
          expires_at, family_expires_at)
       SELECT $2, 'refresh', $3, $4, $5, ${T},
              LEAST(${T} + make_interval(secs => $6), f.limit_at), f.limit_at
       FROM (SELECT coalesce($8::timestamptz, ${T} + make_interval(secs => $7)) AS limit_at) f`,
      [
        clock(),
        hashToken(keys.refresh, refresh),
        input.grantId,
        input.familyId,
        input.resource,
        REFRESH_IDLE_SECONDS,
        REFRESH_ABSOLUTE_SECONDS,
        input.familyExpiresAt,
      ],
    );
    return {
      access_token: access,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refresh,
      scope: input.role,
    };
  }

  /** Reads a form body, refusing duplicates and other content types. */
  async function readForm(c: Context): Promise<URLSearchParams> {
    if (
      !/^application\/x-www-form-urlencoded\s*(;|$)/i.test(
        c.req.header("content-type") ?? "",
      )
    )
      throw new OAuthError(
        "invalid_request",
        "Send application/x-www-form-urlencoded.",
      );
    const text = await c.req.text();
    if (Buffer.byteLength(text) > MAX_FORM_BYTES)
      throw new OAuthError("invalid_request", "The request is too large.");
    const form = new URLSearchParams(text);
    for (const key of new Set(form.keys()))
      if (form.getAll(key).length > 1)
        throw new OAuthError("invalid_request", `${key} is repeated.`);
    return form;
  }

  /** The client id a token request presents, from Basic or the form. */
  function presentedClientId(c: Context, form: URLSearchParams): string | null {
    const header = c.req.header("authorization");
    const match = header
      ? /^basic +([A-Za-z0-9+/=]+)$/i.exec(header.trim())
      : null;
    if (match?.[1]) {
      const decoded = Buffer.from(match[1], "base64").toString("utf8");
      const colon = decoded.indexOf(":");
      try {
        if (colon >= 0) return decodeURIComponent(decoded.slice(0, colon));
      } catch {
        return null;
      }
    }
    return form.get("client_id");
  }

  /** Authenticates the client at the token and revocation endpoints. */
  async function authenticateClient(
    c: Context,
    form: URLSearchParams,
  ): Promise<OAuthClient> {
    const header = c.req.header("authorization");
    let clientId = form.get("client_id");
    let secret: string | null = null;
    if (header !== undefined) {
      const match = /^basic +([A-Za-z0-9+/=]+)$/i.exec(header.trim());
      const decoded = match?.[1]
        ? Buffer.from(match[1], "base64").toString("utf8")
        : "";
      const colon = decoded.indexOf(":");
      if (colon < 0)
        throw new OAuthError(
          "invalid_client",
          "Use HTTP Basic client authentication.",
          401,
        );
      let basicId: string;
      try {
        basicId = decodeURIComponent(decoded.slice(0, colon));
        secret = decodeURIComponent(decoded.slice(colon + 1));
      } catch {
        throw new OAuthError("invalid_client", "Malformed credentials.", 401);
      }
      if (clientId !== null && clientId !== basicId)
        throw new OAuthError("invalid_request", "Two different client ids.");
      clientId = basicId;
    }
    if (!clientId)
      throw new OAuthError("invalid_client", "client_id is required.", 401);
    const client = await clients.resolve(sql, clientId, { fetch: false });
    if (!client) throw new OAuthError("invalid_client", "Unknown client.", 401);
    if (
      client.clientSecret !== null &&
      (secret === null || !constantTimeEqual(secret, client.clientSecret))
    )
      throw new OAuthError(
        "invalid_client",
        "This client must authenticate with its secret.",
        401,
      );
    return client;
  }

  const sessionOnly: MiddlewareHandler<AuthEnv<Ext>> = async (c, next) => {
    const current = c.get("actor");
    if (!current)
      return authError(
        c,
        new AuthRequestError("unauthenticated", "Sign in to continue."),
      );
    if (current.credential.kind !== "session")
      return authError(
        c,
        new AuthRequestError("forbidden", "This needs a signed-in session.", {
          reason: "session_required",
        }),
      );
    c.header("Cache-Control", "no-store");
    await next();
  };

  const readJson = async (c: Context): Promise<Record<string, unknown>> => {
    const text = await c.req.text();
    let body: unknown = null;
    if (Buffer.byteLength(text) <= MAX_FORM_BYTES)
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

  const me = (c: Context<AuthEnv<Ext>>): Actor<Ext> => {
    const current = c.get("actor");
    if (!current)
      throw new AuthRequestError("unauthenticated", "Sign in to continue.");
    return current;
  };

  const routes = new Hono<AuthEnv<Ext>>();

  routes.onError((error, c) => {
    if (isLimitError(error))
      return limitResponse(
        c,
        /^\/oauth\/(token|revoke|register)$/.test(c.req.path)
          ? "oauth"
          : c.req.path === "/oauth/authorize"
            ? "plain"
            : "json",
        error,
      );
    if (error instanceof OAuthError) return oauthJson(c, error);
    if (error instanceof AuthRequestError) return authError(c, error);
    throw error;
  });

  // Metadata -----------------------------------------------------------------

  const serverMetadata = () => ({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    ...(config.oauth.legacyDcr
      ? { registration_endpoint: `${issuer}/oauth/register` }
      : {}),
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
    revocation_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
    scopes_supported: [...ROLES],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: true,
  });

  routes.get("/.well-known/oauth-authorization-server", (c) => {
    c.header("Cache-Control", "max-age=300");
    return c.json(serverMetadata());
  });

  for (const resource of resources)
    routes.get(`/.well-known/oauth-protected-resource${resource.path}`, (c) => {
      c.header("Cache-Control", "max-age=300");
      return c.json({
        resource: resource.uri,
        authorization_servers: [issuer],
        scopes_supported: [...ROLES],
        bearer_methods_supported: ["header"],
        resource_name: resource.name,
      });
    });

  // Authorization ------------------------------------------------------------

  routes.get(
    "/oauth/authorize",
    auth.middleware.rateLimit("oauth.authorize", "ip", { surface: "plain" }),
    auth.middleware.actor,
    async (c) => {
      c.header("Cache-Control", "no-store");
      const params = new URL(c.req.url).searchParams;
      // Until the client and redirect URI are known, errors cannot be
      // redirected: they are shown to the person instead.
      const refuse = (error: string, description: string) =>
        c.json({ error, error_description: description, iss: issuer }, 400);
      for (const key of new Set(params.keys()))
        if (params.getAll(key).length > 1)
          return refuse("invalid_request", `${key} is repeated.`);
      const clientId = params.get("client_id");
      if (!clientId) return refuse("invalid_request", "client_id is required.");
      let client: OAuthClient | null;
      try {
        const ip = auth.ipKey(c);
        client = await clients.resolve(sql, clientId, {
          fetch: true,
          // Only cache misses reach the network, and only they count.
          beforeFetch: async (url) => {
            await limiter.enforce("oauth.metadata.ip", ip);
            await limiter.enforce("oauth.metadata.host", url.hostname);
            await limiter.enforce("oauth.metadata.global", "all");
          },
        });
      } catch (error) {
        if (error instanceof ClientError)
          return refuse("invalid_client", error.message);
        throw error;
      }
      if (!client) return refuse("invalid_client", "Unknown client.");
      const redirectUri = params.get("redirect_uri");
      if (!redirectUri)
        return refuse("invalid_request", "redirect_uri is required.");
      if (!client.redirectUris.some((r) => redirectMatches(r, redirectUri)))
        return refuse(
          "invalid_request",
          "redirect_uri is not registered for this client.",
        );

      const stateParam = params.get("state");
      const state =
        stateParam !== null && stateParam.length <= 1024 ? stateParam : null;
      const back = (values: Record<string, string>) => {
        const target = new URL(redirectUri);
        for (const [k, v] of Object.entries(values))
          target.searchParams.set(k, v);
        if (state !== null) target.searchParams.set("state", state);
        target.searchParams.set("iss", issuer);
        return c.redirect(target.href, 302);
      };
      const fail = (error: string, description: string) =>
        back({ error, error_description: description });

      if (stateParam !== null && state === null)
        return fail("invalid_request", "state is longer than 1024 characters.");
      const responseType = params.get("response_type");
      if (responseType === null)
        return fail("invalid_request", "response_type is required.");
      if (responseType !== "code")
        return fail(
          "unsupported_response_type",
          "Only the authorization code flow is supported.",
        );
      if (params.get("code_challenge_method") !== "S256")
        return fail(
          "invalid_request",
          "PKCE with code_challenge_method S256 is required.",
        );
      const challenge = params.get("code_challenge") ?? "";
      if (!CHALLENGE.test(challenge))
        return fail(
          "invalid_request",
          "code_challenge is missing or malformed.",
        );
      const resource = byUri.get(params.get("resource") ?? "");
      if (!resource)
        return fail(
          "invalid_target",
          `resource must be one of: ${resources.map((r) => r.uri).join(", ")}.`,
        );
      const scope = requestedRole(params.get("scope"));
      if (scope === undefined)
        return fail(
          "invalid_scope",
          `Scopes are role names: ${ROLES.join(", ")}.`,
        );

      const requestId = generateToken();
      await sql.query(
        `INSERT INTO ${t.requests}
         (id_hash, client_id, redirect_uri, resource, scope, state, code_challenge,
          created_at, expires_at)
       VALUES ($2, $3, $4, $5, $6, $7, $8, ${T}, ${T} + make_interval(secs => $9))`,
        [
          clock(),
          hashToken(keys.request, requestId),
          client.clientId,
          redirectUri,
          resource.uri,
          scope,
          state,
          challenge,
          CONSENT_TTL_SECONDS,
        ],
      );
      const consent = `${consentPath}?request=${encodeURIComponent(requestId)}`;
      if (c.get("actor")?.credential.kind === "session")
        return c.redirect(`${web}${consent}`, 302);
      return c.redirect(
        `${issuer}${auth.basePath}/sign-in?returnTo=${encodeURIComponent(consent)}`,
        302,
      );
    },
  );

  // Consent ------------------------------------------------------------------

  interface PendingRequest {
    clientId: string;
    clientName: string;
    logoUri: string | null;
    kind: ClientKind;
    redirectUri: string;
    resource: string;
    scope: Role | null;
    state: string | null;
    codeChallenge: string;
    userId: string | null;
    expiresAt: Date;
  }

  /** The pending request named by `id`, locked, bound to the caller. */
  async function pending(
    db: SqlQueryable,
    id: string,
    userId: string,
  ): Promise<PendingRequest & { idHash: string }> {
    const [row] = await db.query<PendingRequest & { idHash: string }>(
      `SELECT r.id_hash AS "idHash", r.client_id AS "clientId", c.client_name AS "clientName",
         c.logo_uri AS "logoUri", c.kind, r.redirect_uri AS "redirectUri",
         r.resource, r.scope, r.state, r.code_challenge AS "codeChallenge",
         r.user_id AS "userId", r.expires_at AS "expiresAt"
       FROM ${t.requests} r JOIN ${t.clients} c ON c.client_id = r.client_id
       WHERE r.id_hash = ANY($2::text[]) AND r.decided_at IS NULL
         AND r.expires_at > ${T}
       FOR UPDATE OF r`,
      [clock(), hashTokens(rings.request, id)],
    );
    if (!row || (row.userId !== null && row.userId !== userId))
      throw new AuthRequestError(
        "not_found",
        "This authorization request has expired or was already answered.",
      );
    if (row.userId === null)
      await db.query(
        `UPDATE ${t.requests} SET user_id = $2 WHERE id_hash = $1`,
        [row.idHash, userId],
      );
    return { ...row, userId };
  }

  const roleUpTo = (role: Role) => ROLES.filter((r) => roleAtLeast(role, r));

  // The consent screen is a page on the web origin, which may be another
  // host: CORS for it, and for nothing else on these routes.
  routes.use("/oauth/consent/*", auth.middleware.cors);
  routes.use(
    "/oauth/consent/*",
    auth.middleware.actor,
    auth.middleware.trustedOrigin,
    sessionOnly,
  );

  routes.get("/oauth/consent/:id", async (c) => {
    const current = me(c);
    const request = await sql.transaction((tx) =>
      pending(tx, c.req.param("id"), current.user.id),
    );
    const redirect = new URL(request.redirectUri);
    const resource = byUri.get(request.resource);
    const allowed = roleUpTo(current.user.role);
    return c.json({
      client: {
        id: request.clientId,
        name: request.clientName,
        logoUri: request.logoUri,
        kind: request.kind,
        redirectUri: request.redirectUri,
        redirectHost: redirect.host,
        localhost: isLoopbackRedirect(request.redirectUri),
      },
      resource: { uri: request.resource, name: resource?.name ?? null },
      scope: request.scope,
      ceilings: allowed,
      defaultCeiling: request.scope
        ? minRole(request.scope, current.user.role)
        : (allowed[0] ?? "viewer"),
      expiresAt: request.expiresAt.toISOString(),
    });
  });

  routes.post(
    "/oauth/consent/:id",
    auth.middleware.rateLimit(
      "oauth.consent",
      (c) => c.get("actor")?.user.id ?? null,
    ),
    async (c) => {
      const current = me(c);
      const body = await readJson(c);
      const decision = body.decision;
      if (decision !== "approve" && decision !== "deny")
        throw new AuthRequestError(
          "invalid_request",
          "decision must be approve or deny.",
          { reason: "decision" },
        );
      const ceiling = body.ceiling;
      if (decision === "approve") {
        if (!isRole(ceiling))
          throw new AuthRequestError(
            "invalid_request",
            "ceiling must be viewer, member or admin.",
            { reason: "ceiling" },
          );
        if (ceiling === "admin") {
          const refusal = await auth.middleware.requireRecentAuth(
            ADMIN_GRANT_RECENT_AUTH_SECONDS,
          )(c, async () => {});
          if (refusal) return refusal;
        }
      }
      let restrictions: Readonly<Record<string, unknown>> | null = null;
      if (decision === "approve" && body.restrictions !== undefined) {
        const validate = options.hooks?.validateRestrictions;
        if (!validate)
          throw new AuthRequestError(
            "invalid_request",
            "This app does not accept restrictions.",
            { reason: "restrictions" },
          );
        const peek = await sql.transaction((tx) =>
          pending(tx, c.req.param("id"), current.user.id),
        );
        const checked = await validate(current, body.restrictions, {
          clientId: peek.clientId,
          resource: peek.resource,
        });
        if (
          typeof checked !== "object" ||
          checked === null ||
          Array.isArray(checked)
        )
          throw new Error("validateRestrictions must return an object.");
        restrictions = checked;
      }

      const redirectUri = await sql.transaction(async (tx) => {
        const request = await pending(tx, c.req.param("id"), current.user.id);
        const target = new URL(request.redirectUri);
        const finish = async (values: Record<string, string>) => {
          await tx.query(
            `UPDATE ${t.requests} SET decided_at = ${T} WHERE id_hash = $2`,
            [clock(), request.idHash],
          );
          for (const [k, v] of Object.entries(values))
            target.searchParams.set(k, v);
          if (request.state !== null)
            target.searchParams.set("state", request.state);
          target.searchParams.set("iss", issuer);
          return target.href;
        };
        if (decision === "deny")
          return finish({
            error: "access_denied",
            error_description: "The person declined the request.",
          });
        const [owner] = await tx.query<{ role: Role | null; usable: boolean }>(
          `SELECT role, active AND deleted_at IS NULL AS "usable"
         FROM ${t.users} WHERE id = $1 FOR SHARE`,
          [current.user.id],
        );
        if (!owner?.usable || owner.role === null)
          throw new AuthRequestError(
            "forbidden",
            "Your account has no access.",
          );
        if (!roleAtLeast(owner.role, ceiling as Role))
          throw new AuthRequestError(
            "forbidden",
            `A connection cannot have a higher role than yours (${owner.role}).`,
            { reason: "ceiling" },
          );
        const [grant] = await tx.query<{ id: string }>(
          `INSERT INTO ${t.grants}
           (user_id, client_id, client_name, logo_uri, ceiling, resources,
            restrictions, created_at)
         VALUES ($2, $3, $4, $5, $6, ARRAY[$7::text], $8::text::jsonb, ${T})
         RETURNING id`,
          [
            clock(),
            current.user.id,
            request.clientId,
            request.clientName,
            request.logoUri,
            ceiling,
            request.resource,
            restrictions === null ? null : JSON.stringify(restrictions),
          ],
        );
        if (!grant) throw new Error("INSERT … RETURNING returned no row.");
        const code = generateToken();
        await tx.query(
          `INSERT INTO ${t.codes}
           (code_hash, grant_id, client_id, redirect_uri, resource, code_challenge,
            created_at, expires_at)
         VALUES ($2, $3, $4, $5, $6, $7, ${T}, ${T} + make_interval(secs => $8))`,
          [
            clock(),
            hashToken(keys.code, code),
            grant.id,
            request.clientId,
            request.redirectUri,
            request.resource,
            request.codeChallenge,
            CODE_TTL_SECONDS,
          ],
        );
        return finish({ code });
      });
      return c.json({ redirectUri });
    },
  );

  // Tokens -------------------------------------------------------------------

  routes.post(
    "/oauth/token",
    auth.middleware.rateLimit("oauth.token.ip", "ip", { surface: "oauth" }),
    async (c) => {
      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      const form = await readForm(c);
      const presented = presentedClientId(c, form) ?? "";
      await limiter.enforce("oauth.token.client", presented);
      try {
        return await exchange(c, form);
      } catch (error) {
        // Failed grants and client authentications are counted per client
        // and IP after the fact, like invalid bearer credentials: a request
        // that succeeds is never refused and never counted, and a failure
        // over the limit is answered with a 429 instead of its error.
        if (
          error instanceof OAuthError &&
          (error.error === "invalid_grant" || error.error === "invalid_client")
        )
          await limiter.enforce(
            "oauth.token.failures",
            `${presented}\u0000${auth.ipKey(c)}`,
          );
        throw error;
      }
    },
  );

  async function exchange(
    c: Context,
    form: URLSearchParams,
  ): Promise<Response> {
    const client = await authenticateClient(c, form);
    const grantType = form.get("grant_type");
    const resourceParam = form.get("resource");
    if (grantType === "authorization_code") {
      const result = await sql.transaction(async (tx) => {
        const code = form.get("code") ?? "";
        const [row] = await tx.query<{
          grantId: string;
          clientId: string;
          redirectUri: string;
          resource: string;
          codeChallenge: string;
          consumed: boolean;
          live: boolean;
          codeHash: string;
        }>(
          `SELECT code_hash AS "codeHash", grant_id AS "grantId", client_id AS "clientId",
             redirect_uri AS "redirectUri", resource, code_challenge AS "codeChallenge",
             consumed_at IS NOT NULL AS "consumed", expires_at > ${T} AS "live"
           FROM ${t.codes} WHERE code_hash = ANY($2::text[]) FOR UPDATE`,
          [clock(), hashTokens(rings.code, code)],
        );
        const invalid = new OAuthError(
          "invalid_grant",
          "The code is invalid, expired or already used.",
        );
        if (!row || !row.live) return invalid;
        // The client and PKCE come first: only someone holding the
        // verifier can revoke a grant by replaying its code.
        const verifier = form.get("code_verifier") ?? "";
        const pkce =
          VERIFIER.test(verifier) &&
          constantTimeEqual(
            createHash("sha256").update(verifier).digest("base64url"),
            row.codeChallenge,
          );
        if (
          row.clientId !== client.clientId ||
          row.redirectUri !== form.get("redirect_uri") ||
          !pkce
        )
          return invalid;
        if (row.consumed) {
          await revokeGrantTx(tx, row.grantId);
          return invalid;
        }
        await tx.query(
          `UPDATE ${t.codes} SET consumed_at = ${T} WHERE code_hash = $2`,
          [clock(), row.codeHash],
        );
        if (resourceParam !== null && resourceParam !== row.resource)
          return new OAuthError(
            "invalid_target",
            "resource must be the one the code was issued for.",
          );
        const grant = await usableGrant(tx, row.grantId);
        if (!grant) return invalid;
        return issueTokens(tx, {
          grantId: grant.id,
          resource: row.resource,
          familyId: randomUUID(),
          familyExpiresAt: null,
          role: minRole(grant.ceiling, grant.role),
        });
      });
      if (result instanceof OAuthError) throw result;
      return c.json(result);
    }
    if (grantType === "refresh_token") {
      const result = await sql.transaction(async (tx) => {
        const presented = form.get("refresh_token") ?? "";
        const [row] = await tx.query<{
          tokenHash: string;
          grantId: string;
          familyId: string;
          resource: string;
          familyExpiresAt: Date;
          clientId: string;
          rotated: boolean;
          revoked: boolean;
          live: boolean;
        }>(
          `SELECT t.token_hash AS "tokenHash", t.grant_id AS "grantId",
             t.family_id AS "familyId", t.resource,
             t.family_expires_at AS "familyExpiresAt", g.client_id AS "clientId",
             t.rotated_at IS NOT NULL AS "rotated", t.revoked_at IS NOT NULL AS "revoked",
             t.expires_at > ${T} AND t.family_expires_at > ${T} AS "live"
           FROM ${t.tokens} t JOIN ${t.grants} g ON g.id = t.grant_id
           WHERE t.token_hash = ANY($2::text[]) AND t.kind = 'refresh'
           FOR UPDATE OF t`,
          [clock(), hashTokens(rings.refresh, presented)],
        );
        const invalid = new OAuthError(
          "invalid_grant",
          "The refresh token is invalid, expired or revoked.",
        );
        if (!row || row.clientId !== client.clientId) return invalid;
        if (row.rotated) {
          // A rotated token came back: someone has a copy. End the family
          // and the grant.
          await revokeGrantTx(tx, row.grantId);
          return invalid;
        }
        if (row.revoked || !row.live) return invalid;
        if (resourceParam !== null && resourceParam !== row.resource)
          return new OAuthError(
            "invalid_target",
            "resource must be the one the token was issued for.",
          );
        const grant = await usableGrant(tx, row.grantId);
        if (!grant) return invalid;
        await tx.query(
          `UPDATE ${t.tokens} SET rotated_at = ${T} WHERE token_hash = $2`,
          [clock(), row.tokenHash],
        );
        return issueTokens(tx, {
          grantId: grant.id,
          resource: row.resource,
          familyId: row.familyId,
          familyExpiresAt: row.familyExpiresAt,
          role: minRole(grant.ceiling, grant.role),
        });
      });
      if (result instanceof OAuthError) throw result;
      return c.json(result);
    }
    throw new OAuthError(
      "unsupported_grant_type",
      "grant_type must be authorization_code or refresh_token.",
    );
  }

  routes.post(
    "/oauth/revoke",
    auth.middleware.rateLimit("oauth.revoke", "ip", { surface: "oauth" }),
    async (c) => {
      c.header("Cache-Control", "no-store");
      const form = await readForm(c);
      const client = await authenticateClient(c, form);
      const token = form.get("token") ?? "";
      await sql.query(
        `UPDATE ${t.tokens} SET revoked_at = ${T}
       WHERE revoked_at IS NULL AND family_id IN (
         SELECT t.family_id FROM ${t.tokens} t JOIN ${t.grants} g ON g.id = t.grant_id
         WHERE t.token_hash = ANY($2::text[]) AND g.client_id = $3)`,
        [
          clock(),
          [
            ...hashTokens(rings.access, token),
            ...hashTokens(rings.refresh, token),
          ],
          client.clientId,
        ],
      );
      return c.body(null, 200);
    },
  );

  if (config.oauth.legacyDcr)
    routes.post(
      "/oauth/register",
      auth.middleware.rateLimit("oauth.register", "ip", { surface: "oauth" }),
      async (c) => {
        c.header("Cache-Control", "no-store");
        let body: unknown = null;
        const text = await c.req.text();
        if (Buffer.byteLength(text) <= MAX_FORM_BYTES)
          try {
            body = JSON.parse(text);
          } catch {
            body = null;
          }
        let metadata: ReturnType<typeof readClientMetadata>;
        try {
          metadata = readClientMetadata(body);
        } catch (error) {
          if (error instanceof ClientError)
            throw new OAuthError("invalid_client_metadata", error.message);
          throw error;
        }
        const registered = await clients.register(
          sql,
          `dcr_${randomUUID()}`,
          metadata,
        );
        return c.json(
          {
            client_id: registered.clientId,
            client_id_issued_at: Math.floor(Date.now() / 1000),
            client_name: registered.clientName,
            redirect_uris: registered.redirectUris,
            ...(registered.logoUri ? { logo_uri: registered.logoUri } : {}),
            token_endpoint_auth_method: "none",
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
          },
          201,
        );
      },
    );

  // Connected apps -----------------------------------------------------------

  const GRANT_COLUMNS = `g.id, g.user_id AS "userId", g.client_id AS "clientId",
    g.client_name AS "clientName", g.logo_uri AS "logoUri", g.ceiling, g.resources,
    g.restrictions, g.created_at AS "createdAt", g.last_used_at AS "lastUsedAt"`;

  const listGrants = (userId: string) =>
    sql.query<GrantRecord>(
      `SELECT ${GRANT_COLUMNS} FROM ${t.grants} g
       WHERE g.user_id = $1 AND g.revoked_at IS NULL
       ORDER BY g.created_at DESC, g.id`,
      [userId],
    );

  const revokeGrant = (id: string, revokeOptions: { userId?: string } = {}) =>
    UUID.test(id)
      ? sql.transaction(async (tx) => {
          const [row] = await tx.query<{ id: string }>(
            `SELECT id FROM ${t.grants}
             WHERE id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR user_id = $2)
             FOR UPDATE`,
            [id, revokeOptions.userId ?? null],
          );
          if (!row) return false;
          await revokeGrantTx(tx, row.id);
          return true;
        })
      : Promise.resolve(false);

  const grantView = (g: GrantRecord) => ({
    id: g.id,
    clientId: g.clientId,
    clientName: g.clientName,
    logoUri: g.logoUri,
    ceiling: g.ceiling,
    resources: g.resources,
    restrictions: g.restrictions,
    createdAt: g.createdAt.toISOString(),
    lastUsedAt: g.lastUsedAt?.toISOString() ?? null,
  });

  const appsPath = `${auth.basePath}/connected-apps`;
  // CORS for these comes from auth.routes, mounted at the same basePath.
  routes.use(
    `${appsPath}/*`,
    auth.middleware.actor,
    auth.middleware.trustedOrigin,
    sessionOnly,
  );

  routes.get(appsPath, async (c) => {
    const current = me(c);
    const other = c.req.query("user");
    let userId = current.user.id;
    if (other !== undefined && other !== current.user.id) {
      if (!roleAtLeast(current.role, "admin"))
        throw new AuthRequestError(
          "forbidden",
          "Only an admin can see other people's connected apps.",
        );
      if (!UUID.test(other))
        throw new AuthRequestError("invalid_request", "No such user.", {
          reason: "user",
        });
      userId = other;
    }
    return c.json({ connectedApps: (await listGrants(userId)).map(grantView) });
  });

  routes.delete(`${appsPath}/:id`, async (c) => {
    const current = me(c);
    const admin = roleAtLeast(current.role, "admin");
    const revoked = await revokeGrant(
      c.req.param("id"),
      admin ? {} : { userId: current.user.id },
    );
    if (!revoked)
      throw new AuthRequestError("not_found", "No such connected app.");
    return c.body(null, 204);
  });

  // Resource server ----------------------------------------------------------

  const requireMcpToken: McpAuth<Ext>["requireMcpToken"] = (mcpOptions) => {
    const resource = resources.find((r) => r.path === mcpOptions.resource);
    if (!resource)
      throw new TypeError(
        `"${mcpOptions.resource}" is not a configured resource.`,
      );
    const required = mcpOptions.role ?? resource.scope;
    return async (c, next) => {
      const refuse = (
        status: 401 | 403,
        error: "invalid_token" | "insufficient_scope" | null,
        message: string,
      ) => {
        c.header("Cache-Control", "no-store");
        c.header(
          "WWW-Authenticate",
          bearerChallenge({
            ...(error ? { error, description: message } : {}),
            resourceMetadata: resource.metadataUrl,
            scope: required,
          }),
        );
        return c.json(
          {
            error: {
              code: status === 401 ? "unauthenticated" : "forbidden",
              message,
            },
          } satisfies AuthErrorBody,
          status,
        );
      };
      const header = c.req.header("authorization");
      if (header === undefined)
        return refuse(401, null, "A bearer token is required.");
      // Only invalid tokens count, and a valid token is never refused, so a
      // neighbour's bad tokens cannot throttle good ones.
      const invalid = async (message: string) => {
        try {
          await limiter.enforce("bearer.invalid", auth.ipKey(c));
        } catch (error) {
          if (isLimitError(error)) return limitResponse(c, "json", error);
          throw error;
        }
        return refuse(401, "invalid_token", message);
      };
      const match = /^bearer +([^\s]+) *$/i.exec(header);
      if (!match?.[1]) return invalid("A bearer token is required.");
      const tokenHashes = hashTokens(rings.access, match[1]);
      const [row] = await sql.query<{
        grantId: string;
        ceiling: Role;
        restrictions: Readonly<Record<string, unknown>> | null;
        userId: string;
        role: Role;
        email: string | null;
        displayName: string | null;
        lastUsedAt: Date | null;
      }>(
        `SELECT g.id AS "grantId", g.ceiling, g.restrictions, u.id AS "userId",
           u.role, u.email, u.display_name AS "displayName",
           g.last_used_at AS "lastUsedAt"
         FROM ${t.tokens} t
         JOIN ${t.grants} g ON g.id = t.grant_id
         JOIN ${t.users} u ON u.id = g.user_id
         WHERE t.token_hash = ANY($3::text[]) AND t.kind = 'access' AND t.resource = $4
           AND t.revoked_at IS NULL AND t.expires_at > ${T}
           AND g.revoked_at IS NULL AND ${usableOwner("$2")}`,
        [clock(), scimRoles, tokenHashes, resource.uri],
      );
      if (!row)
        return invalid(
          "The access token is invalid, expired or not for this resource.",
        );
      const user = {
        id: row.userId,
        role: row.role,
        email: row.email,
        displayName: row.displayName,
      };
      const current = createActor<Ext>({
        user,
        credential: {
          kind: "oauth",
          id: row.grantId,
          ceiling: row.ceiling,
          workspace: null,
          restrictions: row.restrictions,
        },
        ext: await auth.extendActor(user),
      });
      if (!roleAtLeast(current.role, required))
        return refuse(
          403,
          "insufficient_scope",
          `This needs the ${required} scope.`,
        );
      await sql.query(
        `UPDATE ${t.grants} SET last_used_at = GREATEST(${T}, created_at)
         WHERE id = $2 AND (last_used_at IS NULL OR last_used_at < ${T} - interval '60 seconds')`,
        [clock(), row.grantId],
      );
      c.set("actor", current);
      c.set("session", null);
      c.set("apiKey", null);
      await next();
    };
  };

  async function purgeExpired() {
    const sweep = {
      sql,
      config,
      ...(options.now ? { now: options.now } : {}),
    };
    return {
      requests: (await sweepOAuthRequests(sweep)).deleted,
      codes: (await sweepOAuthCodes(sweep)).deleted,
      tokens: (await sweepOAuthTokens(sweep)).deleted,
    };
  }

  return {
    routes,
    requireMcpToken,
    issuer,
    resources,
    listGrants,
    revokeGrant,
    purgeExpired,
  };
}
