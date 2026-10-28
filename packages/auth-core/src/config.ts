import { z } from "zod";
import { assertAppId } from "./app-id.js";
import { AuthConfigError, type ConfigIssue } from "./errors.js";
import { isValidSchemaName } from "./identifiers.js";
import {
  parseTrustedProxies,
  TRUSTED_PROXY_HEADERS,
  type TrustedProxyHeader,
} from "./rate-limits/ip.js";
import type { RateLimitPolicy } from "./rate-limits/policy.js";
import { isHttpsUrl, isValidRedirectUri } from "./redirect-uris.js";
import { isRole, ROLES, type Role, type RoleMap } from "./roles.js";

/** The fewest bytes an app secret may have. */
export const MIN_SECRET_BYTES = 32;

/** The fewest characters a SCIM bearer token may have. */
export const MIN_SCIM_TOKEN_LENGTH = 32;

/** The fewest characters a pre-registered OAuth client secret may have. */
export const MIN_OAUTH_CLIENT_SECRET_LENGTH = 32;

/** An OAuth client registered in `<APP>_OAUTH_CLIENTS`. */
export interface OAuthClientConfig {
  /** `client_id`. Not a URL, which would be read as a metadata document. */
  readonly clientId: string;
  /** `client_name`, shown on the consent page. */
  readonly clientName: string;
  /** `redirect_uris`: `https`, or `http` on a loopback host. */
  readonly redirectUris: readonly string[];
  /** `logo_uri`, an `https` URL, or `null`. */
  readonly logoUri: string | null;
  /**
   * `client_secret` for a confidential client, which then authenticates at
   * the token endpoint with HTTP Basic. `null` for a public PKCE client.
   */
  readonly clientSecret: string | null;
}

/** The longest `<APP>_API_KEY_MAX_TTL_DAYS` accepts: ten years. */
export const MAX_API_KEY_TTL_DAYS = 3650;

const API_KEY_PREFIX_PATTERN = /^[a-z][a-z0-9]{1,15}$/;

/** The role map used when `<APP>_OIDC_ROLE_MAP` is unset: role names map to themselves. */
export const DEFAULT_ROLE_MAP_VALUES: Readonly<Record<string, Role>> =
  Object.freeze(Object.fromEntries(ROLES.map((role) => [role, role])));

/** Everything auth-core needs from the environment, validated. */
export interface AuthConfig {
  /** The app id, such as `posted`. Part of every derived key. */
  readonly app: string;
  /** `<APP>_SECRET`: the root of every derived key. At least 32 bytes. */
  readonly secret: string;
  /**
   * `<APP>_PREVIOUS_SECRETS`: secrets being rotated out, newest first.
   * Values made under them (sessions, API keys, OAuth tokens, sign-in
   * transactions, consent requests, rate limit buckets) are still accepted,
   * and long-lived ones are re-hashed under `secret` when next used. New
   * values always use `secret`. Empty outside a rotation.
   */
  readonly previousSecrets: readonly string[];
  /**
   * `<APP>_SELF_CHECK`: whether `createAuth` runs `checkAuthSetup` in the
   * background at startup and logs the result. Default true.
   */
  readonly selfCheck: boolean;
  readonly oidc: {
    /** `<APP>_OIDC_ISSUER`, exactly as configured. Compared byte for byte. */
    readonly issuer: string;
    /** `<APP>_OIDC_CLIENT_ID`. */
    readonly clientId: string;
    /** `<APP>_OIDC_CLIENT_SECRET`. */
    readonly clientSecret: string;
    /** `<APP>_OIDC_ROLE_CLAIMS` and `<APP>_OIDC_ROLE_MAP`. */
    readonly roleMap: RoleMap;
    /**
     * `<APP>_OIDC_SCOPES`: scopes requested at sign-in. Always includes
     * `openid`. authentik needs `entitlements` for its `roles` claim.
     */
    readonly scopes: readonly string[];
  };
  readonly scim: {
    /**
     * `<APP>_SCIM_TOKENS`: accepted bearer tokens. Several allow rotation.
     * Empty when SCIM is not configured.
     */
    readonly tokens: readonly string[];
    /**
     * `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT`: link a SCIM-provisioned user to
     * their first sign-in when their `externalId` equals the OIDC `sub`, as
     * in authentik's hashed-user-id subject mode. Default `false`.
     */
    readonly externalIdIsSubject: boolean;
  };
  readonly oauth: {
    /** `<APP>_OAUTH_CLIENTS`: pre-registered OAuth clients. */
    readonly clients: readonly OAuthClientConfig[];
    /**
     * `<APP>_OAUTH_LEGACY_DCR`: accept RFC 7591 dynamic client registration.
     * Default `false`; MCP has deprecated it in favour of client metadata
     * documents.
     */
    readonly legacyDcr: boolean;
  };
  readonly rateLimits: {
    /**
     * `<APP>_TRUSTED_PROXIES`: CIDRs of the proxies in front of the API,
     * whose forwarding header is believed. Empty by default: the socket
     * peer is the client.
     */
    readonly trustedProxies: readonly string[];
    /**
     * `<APP>_TRUSTED_PROXY_HEADER`: the one forwarding header the trusted
     * proxies set, `x-forwarded-for` (default) or `forwarded` (RFC 7239).
     * The other is ignored.
     */
    readonly proxyHeader: TrustedProxyHeader;
    /** `<APP>_RATE_LIMITS`: policies that replace the defaults, by name. */
    readonly policies: Readonly<Record<string, RateLimitPolicy>>;
  };
  readonly apiKeys: {
    /**
     * `<APP>_API_KEY_PREFIX`: the first part of every key, such as
     * `posted`. Defaults to the app id when that is 2 to 16 characters;
     * `null` when neither gives one, and then API keys are off.
     */
    readonly prefix: string | null;
    /** `<APP>_API_KEY_MAX_TTL_DAYS` (default 365), in seconds. */
    readonly maxTtlSeconds: number;
    /** `<APP>_API_KEY_ALLOW_NO_EXPIRY`: allow keys that never expire. Default `false`. */
    readonly allowNoExpiry: boolean;
  };
  /**
   * `<APP>_ROLE_SOURCE`: where roles come from. `claims` (default) reads the
   * role claim at sign-in; `scim` derives the role from SCIM group
   * membership, mapped through `<APP>_OIDC_ROLE_MAP`.
   */
  readonly roleSource: "claims" | "scim";
  readonly origins: {
    /** `<APP>_WEB_ORIGIN`, normalised, such as `https://posted.example.com`. */
    readonly web: string;
    /** `<APP>_API_ORIGIN`, normalised. The OIDC callback and cookies live here. */
    readonly api: string;
  };
  readonly session: {
    /** `<APP>_SESSION_MAX_AGE`: absolute session lifetime, in seconds. */
    readonly maxAgeSeconds: number;
    /** `<APP>_SESSION_IDLE_TIMEOUT`: inactivity limit, in seconds. */
    readonly idleTimeoutSeconds: number;
  };
  /** `<APP>_AUTH_SCHEMA`: the Postgres schema holding auth tables. */
  readonly schema: string;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Reads `<APP>_RATE_LIMITS`: a JSON object from policy name to
 * `{ "limit": n, "periodSeconds": n, "burst"?: n }`. Returns the policies,
 * or the problem as a message.
 */
function parseRateLimits(
  source: string,
): Readonly<Record<string, RateLimitPolicy>> | string {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    value = undefined;
  }
  const example = '{"oauth.token.ip":{"limit":300,"periodSeconds":60}}';
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return `must be a JSON object from policy name to a policy, such as ${example}`;
  // A null prototype, so that no name resolves to an Object.prototype member.
  const out = Object.create(null) as Record<string, RateLimitPolicy>;
  const whole = (n: unknown, max: number): n is number =>
    typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= max;
  for (const [name, entry] of Object.entries(value)) {
    if (!/^[a-z][a-z0-9._-]{0,63}$/.test(name))
      return `has an invalid policy name, ${JSON.stringify(name).slice(0, 70)}`;
    const p = entry as Record<string, unknown> | null;
    if (
      typeof p !== "object" ||
      p === null ||
      Object.keys(p).some(
        (k) => !["limit", "periodSeconds", "burst"].includes(k),
      ) ||
      !whole(p.limit, 1_000_000) ||
      !whole(p.periodSeconds, 86400) ||
      (p.burst !== undefined && !whole(p.burst, 1_000_000))
    )
      return `${name} must be { "limit": 1 to 1000000, "periodSeconds": 1 to 86400, "burst"?: 1 to 1000000 }`;
    out[name] = Object.freeze({
      limit: p.limit,
      periodSeconds: p.periodSeconds,
      ...(p.burst === undefined ? {} : { burst: p.burst as number }),
    });
  }
  return Object.freeze(out);
}

const OAUTH_CLIENTS_EXAMPLE =
  '[{"client_id":"posted-cli","client_name":"Posted CLI","redirect_uris":["http://127.0.0.1/callback"]}]';

/**
 * Reads `<APP>_OAUTH_CLIENTS`, a JSON array of RFC 7591-style objects:
 * `client_id`, `client_name`, `redirect_uris`, and optionally `logo_uri`
 * and `client_secret`. Returns the clients, or the problem as a message.
 */
function parseOAuthClients(source: string): OAuthClientConfig[] | string {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    value = undefined;
  }
  if (!Array.isArray(value) || value.length > 100)
    return `must be a JSON array of up to 100 clients, such as ${OAUTH_CLIENTS_EXAMPLE}`;
  const clients: OAuthClientConfig[] = [];
  for (const [index, entry] of value.entries()) {
    const at = `client ${index + 1}`;
    if (typeof entry !== "object" || entry === null || Array.isArray(entry))
      return `${at} must be an object`;
    const c = entry as Record<string, unknown>;
    const known = [
      "client_id",
      "client_name",
      "redirect_uris",
      "logo_uri",
      "client_secret",
    ];
    const unknown = Object.keys(c).find((key) => !known.includes(key));
    if (unknown !== undefined) return `${at} has an unknown field, ${unknown}`;
    if (
      typeof c.client_id !== "string" ||
      !/^[A-Za-z0-9._~-]{1,255}$/.test(c.client_id) ||
      c.client_id.startsWith("dcr_")
    )
      return `${at} needs a client_id of 1 to 255 letters, digits, dots, dashes, underscores or tildes, not starting with dcr_`;
    if (
      typeof c.client_name !== "string" ||
      c.client_name.trim() === "" ||
      c.client_name.length > 200
    )
      return `${at} needs a client_name of 1 to 200 characters`;
    if (
      !Array.isArray(c.redirect_uris) ||
      c.redirect_uris.length === 0 ||
      c.redirect_uris.length > 20 ||
      !c.redirect_uris.every(isValidRedirectUri)
    )
      return `${at} needs 1 to 20 redirect_uris, each https or http on a loopback host, with no fragment`;
    if (c.logo_uri !== undefined && !isHttpsUrl(c.logo_uri))
      return `${at} has a logo_uri that is not an https URL`;
    if (
      c.client_secret !== undefined &&
      (typeof c.client_secret !== "string" ||
        c.client_secret.length < MIN_OAUTH_CLIENT_SECRET_LENGTH ||
        /\s/.test(c.client_secret))
    )
      return `${at} has a client_secret shorter than ${MIN_OAUTH_CLIENT_SECRET_LENGTH} characters or with spaces; generate one with \`openssl rand -base64 48\``;
    clients.push(
      Object.freeze({
        clientId: c.client_id,
        clientName: c.client_name.trim(),
        redirectUris: Object.freeze([...(c.redirect_uris as string[])]),
        logoUri: (c.logo_uri as string | undefined) ?? null,
        clientSecret: (c.client_secret as string | undefined) ?? null,
      }),
    );
  }
  if (new Set(clients.map((c) => c.clientId)).size !== clients.length)
    return "lists the same client_id twice";
  return clients;
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function secureOrLoopback(url: URL): boolean {
  return (
    url.protocol === "https:" ||
    (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))
  );
}

/** Parses `90`, `90s`, `15m`, `12h` or `30d` into seconds. */
export function parseDuration(value: string): number | null {
  const match = /^(\d{1,9})([smhd]?)$/.exec(value.trim());
  if (!match) return null;
  const amount = Number(match[1]);
  const unit = match[2] || "s";
  const factor = { s: 1, m: 60, h: 3600, d: 86400 }[unit] ?? 1;
  return amount * factor;
}

const required = (what: string) => ({
  error: (issue: { input?: unknown }) =>
    issue.input === undefined ? `is required: ${what}` : `must be ${what}`,
});

const list = (value: string) =>
  value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");

function duration(min: number, max: number, fallback: string) {
  return z
    .string(required("a duration"))
    .default(fallback)
    .transform((value, ctx) => {
      const seconds = parseDuration(value);
      if (seconds === null) {
        ctx.addIssue({
          code: "custom",
          message:
            "must be a duration such as 900, 15m, 12h or 7d (s, m, h or d)",
        });
        return z.NEVER;
      }
      if (seconds < min || seconds > max) {
        ctx.addIssue({
          code: "custom",
          message: `must be between ${min} and ${max} seconds`,
        });
        return z.NEVER;
      }
      return seconds;
    });
}

const origin = z
  .string(required("an origin such as https://app.example.com"))
  .transform((value, ctx) => {
    const url = parseUrl(value.trim());
    if (
      url === null ||
      url.username !== "" ||
      url.password !== "" ||
      url.search !== "" ||
      url.hash !== "" ||
      url.pathname !== "/" ||
      !secureOrLoopback(url)
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "must be an HTTPS origin such as https://app.example.com, with no path, or an http://localhost origin for development",
      });
      return z.NEVER;
    }
    return url.origin;
  });

const fields = z
  .object({
    SECRET: z
      .string(required(`at least ${MIN_SECRET_BYTES} bytes of random data`))
      .refine((value) => Buffer.byteLength(value) >= MIN_SECRET_BYTES, {
        error: `must be at least ${MIN_SECRET_BYTES} bytes; generate one with \`openssl rand -base64 48\``,
      }),
    PREVIOUS_SECRETS: z
      .string(required("a comma-separated list of secrets"))
      .default("")
      .transform((value, ctx) => {
        const secrets = list(value);
        if (
          secrets.some((secret) => Buffer.byteLength(secret) < MIN_SECRET_BYTES)
        ) {
          ctx.addIssue({
            code: "custom",
            message: `must be comma-separated secrets of at least ${MIN_SECRET_BYTES} bytes each: the earlier values of the SECRET variable`,
          });
          return z.NEVER;
        }
        if (new Set(secrets).size !== secrets.length) {
          ctx.addIssue({ code: "custom", message: "lists a secret twice" });
          return z.NEVER;
        }
        return secrets;
      }),
    SELF_CHECK: z
      .string(required("true or false"))
      .default("true")
      .transform((value, ctx) => {
        const normalised = value.trim().toLowerCase();
        if (normalised !== "true" && normalised !== "false") {
          ctx.addIssue({ code: "custom", message: "must be true or false" });
          return z.NEVER;
        }
        return normalised === "true";
      }),
    OIDC_ISSUER: z
      .string(required("the identity provider's issuer URL"))
      .refine(
        (value) => {
          const url = parseUrl(value);
          return (
            url !== null &&
            url.href.replace(/\/$/, "") === value.replace(/\/$/, "") &&
            url.username === "" &&
            url.password === "" &&
            url.search === "" &&
            url.hash === "" &&
            secureOrLoopback(url)
          );
        },
        {
          error:
            "must be the provider's HTTPS issuer URL, exactly as its discovery document states it, with no query or fragment",
        },
      ),
    OIDC_CLIENT_ID: z.string(required("the OIDC client id")).trim().min(1, {
      error: "must not be blank",
    }),
    OIDC_CLIENT_SECRET: z
      .string(required("the OIDC client secret"))
      .min(1, { error: "must not be blank" }),
    OIDC_ROLE_CLAIMS: z
      .string(required("a comma-separated list of claim names"))
      .default("roles")
      .transform((value, ctx) => {
        const claims = list(value);
        if (claims.length === 0) {
          ctx.addIssue({
            code: "custom",
            message:
              "must name at least one claim, such as roles or groups (comma-separated)",
          });
          return z.NEVER;
        }
        return claims;
      }),
    OIDC_ROLE_MAP: z
      .string(required("a JSON object"))
      .optional()
      .transform((value, ctx) => {
        if (value === undefined) return DEFAULT_ROLE_MAP_VALUES;
        let parsed: unknown;
        try {
          parsed = JSON.parse(value);
        } catch {
          parsed = undefined;
        }
        if (
          typeof parsed !== "object" ||
          parsed === null ||
          Array.isArray(parsed)
        ) {
          ctx.addIssue({
            code: "custom",
            message:
              'must be a JSON object from claim value to role, such as {"posted-admins":"admin","posted-members":"member"}',
          });
          return z.NEVER;
        }
        const entries = Object.entries(parsed);
        const bad = entries.filter(
          ([key, role]) => key.trim() === "" || !isRole(role),
        );
        if (entries.length === 0 || bad.length > 0) {
          ctx.addIssue({
            code: "custom",
            message: `must map at least one claim value, and every value must be one of ${ROLES.join(", ")}`,
          });
          return z.NEVER;
        }
        return Object.freeze(Object.fromEntries(entries)) as Readonly<
          Record<string, Role>
        >;
      }),
    OIDC_SCOPES: z
      .string(required("a space-separated list of scopes"))
      .default("openid email profile")
      .transform((value, ctx) => {
        const scopes = [
          ...new Set(value.split(/[\s,]+/).filter((s) => s !== "")),
        ];
        if (
          !scopes.includes("openid") ||
          scopes.some((s) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(s))
        ) {
          ctx.addIssue({
            code: "custom",
            message:
              'must be space-separated scopes including openid, such as "openid email profile entitlements"',
          });
          return z.NEVER;
        }
        return scopes;
      }),
    SCIM_TOKENS: z
      .string(required("a comma-separated list of bearer tokens"))
      .default("")
      .transform((value, ctx) => {
        const tokens = list(value);
        if (
          tokens.some(
            (token) => token.length < MIN_SCIM_TOKEN_LENGTH || /\s/.test(token),
          )
        ) {
          ctx.addIssue({
            code: "custom",
            message: `every token must be at least ${MIN_SCIM_TOKEN_LENGTH} characters with no spaces; generate one with \`openssl rand -base64 48\``,
          });
          return z.NEVER;
        }
        if (new Set(tokens).size !== tokens.length) {
          ctx.addIssue({
            code: "custom",
            message: "lists the same token twice",
          });
          return z.NEVER;
        }
        return tokens;
      }),
    SCIM_EXTERNAL_ID_IS_SUBJECT: z
      .string(required("true or false"))
      .default("false")
      .transform((value, ctx) => {
        const normalised = value.trim().toLowerCase();
        if (normalised !== "true" && normalised !== "false") {
          ctx.addIssue({ code: "custom", message: "must be true or false" });
          return z.NEVER;
        }
        return normalised === "true";
      }),
    ROLE_SOURCE: z
      .string(required("claims or scim"))
      .default("claims")
      .transform((value, ctx) => {
        const normalised = value.trim().toLowerCase();
        if (normalised !== "claims" && normalised !== "scim") {
          ctx.addIssue({
            code: "custom",
            message:
              "must be claims (roles from the sign-in role claim) or scim (roles from SCIM groups)",
          });
          return z.NEVER;
        }
        return normalised as "claims" | "scim";
      }),
    OAUTH_CLIENTS: z
      .string(required("a JSON array of clients"))
      .default("[]")
      .transform((value, ctx) => {
        const clients = parseOAuthClients(value);
        if (typeof clients === "string") {
          ctx.addIssue({ code: "custom", message: clients });
          return z.NEVER;
        }
        return clients;
      }),
    OAUTH_LEGACY_DCR: z
      .string(required("true or false"))
      .default("false")
      .transform((value, ctx) => {
        const normalised = value.trim().toLowerCase();
        if (normalised !== "true" && normalised !== "false") {
          ctx.addIssue({ code: "custom", message: "must be true or false" });
          return z.NEVER;
        }
        return normalised === "true";
      }),
    TRUSTED_PROXIES: z
      .string(required("a comma-separated list of CIDRs"))
      .default("")
      .transform((value, ctx) => {
        const entries = list(value);
        try {
          parseTrustedProxies(entries);
        } catch (error) {
          ctx.addIssue({
            code: "custom",
            message: `must be comma-separated addresses or CIDRs, such as 10.0.0.0/8,fd00::/8: ${(error as Error).message}`,
          });
          return z.NEVER;
        }
        return entries;
      }),
    TRUSTED_PROXY_HEADER: z
      .string(required("x-forwarded-for or forwarded"))
      .default("x-forwarded-for")
      .transform((value, ctx) => {
        const normalised = value.trim().toLowerCase();
        const header = TRUSTED_PROXY_HEADERS.find((h) => h === normalised);
        if (!header) {
          ctx.addIssue({
            code: "custom",
            message:
              "must be x-forwarded-for (the default) or forwarded, the header your trusted proxies set",
          });
          return z.NEVER;
        }
        return header;
      }),
    RATE_LIMITS: z
      .string(required("a JSON object"))
      .default("{}")
      .transform((value, ctx) => {
        const policies = parseRateLimits(value);
        if (typeof policies === "string") {
          ctx.addIssue({ code: "custom", message: policies });
          return z.NEVER;
        }
        return policies;
      }),
    API_KEY_PREFIX: z
      .string(required("2 to 16 lowercase letters or digits"))
      .optional()
      .refine(
        (value) => value === undefined || API_KEY_PREFIX_PATTERN.test(value),
        {
          error:
            "must be 2 to 16 lowercase letters or digits, starting with a letter, such as posted",
        },
      ),
    API_KEY_MAX_TTL_DAYS: z
      .string(required("a number of days"))
      .default("365")
      .transform((value, ctx) => {
        const days = /^\d{1,4}$/.test(value.trim()) ? Number(value) : NaN;
        if (!(days >= 1 && days <= MAX_API_KEY_TTL_DAYS)) {
          ctx.addIssue({
            code: "custom",
            message: `must be a whole number of days from 1 to ${MAX_API_KEY_TTL_DAYS}`,
          });
          return z.NEVER;
        }
        return days;
      }),
    API_KEY_ALLOW_NO_EXPIRY: z
      .string(required("true or false"))
      .default("false")
      .transform((value, ctx) => {
        const normalised = value.trim().toLowerCase();
        if (normalised !== "true" && normalised !== "false") {
          ctx.addIssue({ code: "custom", message: "must be true or false" });
          return z.NEVER;
        }
        return normalised === "true";
      }),
    WEB_ORIGIN: origin,
    API_ORIGIN: origin,
    SESSION_MAX_AGE: duration(300, 30 * 86400, "12h"),
    SESSION_IDLE_TIMEOUT: duration(60, 30 * 86400, "2h"),
    AUTH_SCHEMA: z
      .string(required("a Postgres schema name"))
      .default("auth")
      .refine(isValidSchemaName, {
        error:
          "must be a Postgres schema name of 1 to 63 bytes with no control characters or surrounding spaces, not starting with pg_",
      }),
  })
  .superRefine((value, ctx) => {
    if (value.SESSION_IDLE_TIMEOUT > value.SESSION_MAX_AGE)
      ctx.addIssue({
        code: "custom",
        path: ["SESSION_IDLE_TIMEOUT"],
        message: "must not be longer than the session max age",
      });
    if (value.PREVIOUS_SECRETS.includes(value.SECRET))
      ctx.addIssue({
        code: "custom",
        path: ["PREVIOUS_SECRETS"],
        message:
          "must not contain the current secret: list only the secrets it replaced",
      });
  });

type FieldName = keyof z.input<typeof fields>;

const FIELD_ORDER: readonly FieldName[] = Object.keys(
  fields.shape,
) as FieldName[];

/** The environment variable names an app reads, keyed by field. */
export function authEnvNames(app: string): Readonly<Record<FieldName, string>> {
  const prefix = envPrefix(app);
  return Object.fromEntries(
    FIELD_ORDER.map((field) => [field, `${prefix}_${field}`]),
  ) as Record<FieldName, string>;
}

function envPrefix(app: string): string {
  assertAppId(app);
  return app.toUpperCase();
}

const REDACTED = "[redacted]";

function redacted(config: AuthConfig) {
  return {
    ...config,
    secret: REDACTED,
    previousSecrets: config.previousSecrets.map(() => REDACTED),
    oidc: { ...config.oidc, clientSecret: REDACTED },
    scim: {
      ...config.scim,
      tokens: config.scim.tokens.map(() => REDACTED),
    },
    oauth: {
      ...config.oauth,
      clients: config.oauth.clients.map((client) => ({
        ...client,
        clientSecret: client.clientSecret === null ? null : REDACTED,
      })),
    },
  };
}

/**
 * Reads and validates the auth configuration for `app` from `env`.
 *
 * Variables are named `<APP>_<FIELD>`, such as `POSTED_SECRET`. Empty values
 * count as unset. On failure it throws {@link AuthConfigError} listing every
 * problem by variable name, without echoing values.
 *
 * The returned object is frozen. Logging it or serialising it to JSON shows
 * `[redacted]` in place of the secrets.
 *
 * @param app - Lowercase app id, such as `posted`. Also used in key derivation.
 * @param env - Usually `process.env`.
 */
export function loadAuthConfig(
  app: string,
  env: Readonly<Record<string, string | undefined>>,
): AuthConfig {
  const names = authEnvNames(app);
  const input: Partial<Record<FieldName, string>> = {};
  for (const field of FIELD_ORDER) {
    const value = env[names[field]];
    if (value !== undefined && value !== "") input[field] = value;
  }
  const result = fields.safeParse(input);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => ({ field: issue.path[0] as FieldName, issue }))
      .sort(
        (a, b) => FIELD_ORDER.indexOf(a.field) - FIELD_ORDER.indexOf(b.field),
      )
      .map(({ field, issue }): ConfigIssue => ({
        variable: names[field],
        message: issue.message,
      }));
    throw new AuthConfigError(issues);
  }
  const v = result.data;
  const config: AuthConfig = {
    app,
    secret: v.SECRET,
    previousSecrets: Object.freeze(v.PREVIOUS_SECRETS),
    selfCheck: v.SELF_CHECK,
    oidc: {
      issuer: v.OIDC_ISSUER,
      clientId: v.OIDC_CLIENT_ID,
      clientSecret: v.OIDC_CLIENT_SECRET,
      roleMap: Object.freeze({
        claims: Object.freeze(v.OIDC_ROLE_CLAIMS),
        values: v.OIDC_ROLE_MAP,
      }),
      scopes: Object.freeze(v.OIDC_SCOPES),
    },
    scim: Object.freeze({
      tokens: Object.freeze(v.SCIM_TOKENS),
      externalIdIsSubject: v.SCIM_EXTERNAL_ID_IS_SUBJECT,
    }),
    oauth: Object.freeze({
      clients: Object.freeze(v.OAUTH_CLIENTS),
      legacyDcr: v.OAUTH_LEGACY_DCR,
    }),
    rateLimits: Object.freeze({
      trustedProxies: Object.freeze(v.TRUSTED_PROXIES),
      proxyHeader: v.TRUSTED_PROXY_HEADER,
      policies: v.RATE_LIMITS,
    }),
    apiKeys: Object.freeze({
      prefix:
        v.API_KEY_PREFIX ?? (API_KEY_PREFIX_PATTERN.test(app) ? app : null),
      maxTtlSeconds: v.API_KEY_MAX_TTL_DAYS * 86400,
      allowNoExpiry: v.API_KEY_ALLOW_NO_EXPIRY,
    }),
    roleSource: v.ROLE_SOURCE,
    origins: Object.freeze({ web: v.WEB_ORIGIN, api: v.API_ORIGIN }),
    session: Object.freeze({
      maxAgeSeconds: v.SESSION_MAX_AGE,
      idleTimeoutSeconds: v.SESSION_IDLE_TIMEOUT,
    }),
    schema: v.AUTH_SCHEMA,
  };
  Object.freeze(config.oidc);
  Object.defineProperties(config, {
    toJSON: { value: () => redacted(config), enumerable: false },
    [Symbol.for("nodejs.util.inspect.custom")]: {
      value: () => redacted(config),
      enumerable: false,
    },
  });
  return Object.freeze(config);
}
