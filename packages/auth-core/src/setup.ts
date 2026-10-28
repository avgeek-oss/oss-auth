import { randomBytes } from "node:crypto";
import type { AuthConfig } from "./config.js";
import { AuthSetupError } from "./errors.js";
import { quoteIdent } from "./identifiers.js";
import type { FetchLike } from "./oidc/client.js";
import {
  loadMigrations,
  migrationChecksum,
  MIGRATIONS_TABLE,
} from "./postgres/migrate.js";
import type { Sql } from "./postgres/sql.js";
import { parseTrustedProxies } from "./rate-limits/ip.js";
import { isRole } from "./roles.js";

/** One finding of {@link checkAuthSetup}. */
export interface AuthSetupProblem {
  /** `error`: sign-in or provisioning will not work. `warning`: it may not. */
  readonly level: "error" | "warning";
  /** Stable, such as `oidc_issuer_mismatch`. */
  readonly code: string;
  /** What is wrong. */
  readonly message: string;
  /** How to fix it. */
  readonly hint: string;
}

/** What {@link checkAuthSetup} found. */
export interface AuthSetupReport {
  /** True when there are no errors. Warnings do not count. */
  readonly ok: boolean;
  readonly problems: readonly AuthSetupProblem[];
}

/** Options for {@link checkAuthSetup}. */
export interface CheckAuthSetupOptions {
  readonly config: AuthConfig;
  readonly sql: Sql;
  /** Where the app mounts the auth routes, for the callback URL. Default `/auth`. */
  readonly basePath?: string;
  /** For requests to the identity provider, as in `createAuth`. */
  readonly fetch?: FetchLike;
  /** Seconds each request to the provider may take. Default 5. */
  readonly timeoutSeconds?: number;
  /**
   * Throw {@link AuthSetupError} when there is an error, so the app refuses
   * to start. Default false: the report is returned either way.
   */
  readonly failOnError?: boolean;
  /** Receives the summary, one line at a time. Default: nothing is logged. */
  readonly log?: (line: string) => void;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Which scopes make authentik (and most providers) send a role claim. */
const CLAIM_SCOPES: Readonly<Record<string, readonly string[]>> = {
  roles: ["roles", "entitlements"],
  groups: ["groups", "profile"],
};

function withoutTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") end--;
  return value.slice(0, end);
}

/**
 * The site of an origin for SameSite purposes: scheme and the last two
 * labels of the host. Without the public suffix list this treats
 * `a.co.uk` and `b.co.uk` as one site; the check says so.
 */
function site(origin: URL): string {
  const labels = origin.hostname.split(".");
  const host =
    labels.length > 2 && !/^\d+$/.test(labels.at(-1) ?? "")
      ? labels.slice(-2).join(".")
      : origin.hostname;
  return `${origin.protocol}//${host}`;
}

/** Second-level labels that usually form a public suffix under a ccTLD. */
const MULTIPART = new Set([
  "ac",
  "co",
  "com",
  "edu",
  "gov",
  "ne",
  "net",
  "or",
  "org",
]);

/** True for hosts like `a.example.co.uk`, where two labels are not a site. */
function underMultipartSuffix(origin: URL): boolean {
  const labels = origin.hostname.split(".");
  return (
    labels.length > 2 &&
    (labels.at(-1) ?? "").length === 2 &&
    MULTIPART.has(labels.at(-2) ?? "")
  );
}

/**
 * Checks what can be checked of the auth setup without a person signing
 * in, and reports every problem at once. It never throws for a problem
 * unless `failOnError` is set; `createAuth` runs it in the background at
 * startup (unless `<APP>_SELF_CHECK=false`) and logs the summary.
 *
 * It checks the provider's discovery document (reachable, the exact
 * issuer, the code flow with S256 PKCE), the client credentials (with one
 * token request for a made-up code: a provider that answers
 * `invalid_grant` accepted them), the role map and scopes, SCIM tokens for
 * `ROLE_SOURCE=scim`, the origins and cookies, the migrations and the
 * trusted proxies.
 */
export async function checkAuthSetup(
  options: CheckAuthSetupOptions,
): Promise<AuthSetupReport> {
  const { config } = options;
  const problems: AuthSetupProblem[] = [];
  const add = (
    level: AuthSetupProblem["level"],
    code: string,
    message: string,
    hint: string,
  ) => problems.push({ level, code, message, hint });
  const env = (field: string) => `${config.app.toUpperCase()}_${field}`;

  await checkProvider(options, add, env);

  // Roles.
  const values = Object.entries(config.oidc.roleMap.values);
  if (values.length === 0)
    add(
      "error",
      "role_map_empty",
      "The role map is empty, so nobody gets a role and every sign-in is refused.",
      `Set ${env("OIDC_ROLE_MAP")} to a JSON object from group or role names to viewer, member or admin.`,
    );
  for (const [name, role] of values)
    if (!isRole(role))
      add(
        "error",
        "role_map_invalid",
        `The role map gives "${name}" the role "${String(role)}", which is not viewer, member or admin.`,
        `Fix ${env("OIDC_ROLE_MAP")}.`,
      );
  if (config.roleSource === "claims") {
    const known = config.oidc.roleMap.claims.filter(
      (claim) => CLAIM_SCOPES[claim],
    );
    const covered = known.some((claim) =>
      (CLAIM_SCOPES[claim] ?? []).some((scope) =>
        config.oidc.scopes.includes(scope),
      ),
    );
    if (known.length > 0 && !covered)
      add(
        "warning",
        "scopes_role_claim",
        `Roles come from the ${known.join(" or ")} claim, but the requested scopes (${config.oidc.scopes.join(" ")}) may not include it.`,
        `Add the scope that carries it to ${env("OIDC_SCOPES")}: with authentik, entitlements for roles, or profile for groups.`,
      );
  }
  if (config.roleSource === "scim" && config.scim.tokens.length === 0)
    add(
      "error",
      "scim_tokens_missing",
      "Roles come from SCIM, but no SCIM token is set, so the provider cannot push groups and nobody gets a role.",
      `Set ${env("SCIM_TOKENS")} to the token the provider's SCIM provider sends.`,
    );

  // Origins and cookies.
  const web = new URL(config.origins.web);
  const api = new URL(config.origins.api);
  for (const [field, url] of [
    ["WEB_ORIGIN", web],
    ["API_ORIGIN", api],
  ] as const)
    if (url.protocol !== "https:")
      add(
        LOOPBACK.has(url.hostname) ? "warning" : "error",
        "origin_insecure",
        `${env(field)} is ${url.origin}, plain HTTP.${LOOPBACK.has(url.hostname) ? " Fine for development on this computer; cookies drop the __Host- prefix and Secure." : ""}`,
        "Serve the app over HTTPS.",
      );
  if (site(web) !== site(api))
    add(
      "error",
      "origins_cross_site",
      `The web origin ${web.origin} and the API origin ${api.origin} are different sites, so the browser will not send the session cookie (SameSite=Lax) with the page's requests.`,
      "Put the API on a host of the same site, such as api.example.com for example.com, or serve it under the web origin through a proxy.",
    );
  else if (web.hostname !== api.hostname && underMultipartSuffix(web))
    add(
      "warning",
      "origins_site_unverified",
      `${web.hostname} and ${api.hostname} share ${site(web).split("//")[1] ?? ""}, which looks like a multi-part public suffix (such as co.uk); if it is one, they are different sites.`,
      "Check that the two hosts share a registrable domain, such as example.co.uk.",
    );

  // Proxies.
  try {
    parseTrustedProxies(config.rateLimits.trustedProxies);
    const everyone = config.rateLimits.trustedProxies.filter((entry) =>
      ["0.0.0.0/0", "::/0"].includes(entry.trim()),
    );
    if (everyone.length > 0)
      add(
        "warning",
        "trusted_proxies_everyone",
        `${env("TRUSTED_PROXIES")} includes ${everyone.join(" and ")}, so any client can choose the address per-IP limits use.`,
        "List only the proxies in front of the API.",
      );
  } catch (error) {
    add(
      "error",
      "trusted_proxies_invalid",
      `${env("TRUSTED_PROXIES")} does not parse: ${(error as Error).message}.`,
      "Use comma-separated addresses or CIDRs.",
    );
  }

  if (config.previousSecrets.length > 0)
    add(
      "warning",
      "secret_rotation_in_progress",
      `${env("PREVIOUS_SECRETS")} lists ${config.previousSecrets.length} previous secret${config.previousSecrets.length === 1 ? "" : "s"}: values made under them are still accepted.`,
      `Remove it once the longest-lived credential made before the rotation has expired or been re-issued.`,
    );

  await checkMigrations(options, add);

  const report: AuthSetupReport = {
    ok: !problems.some((p) => p.level === "error"),
    problems,
  };
  if (options.log)
    for (const line of formatAuthSetupReport(config.app, report))
      options.log(line);
  if (options.failOnError && !report.ok) throw new AuthSetupError(report);
  return report;
}

type Add = (
  level: AuthSetupProblem["level"],
  code: string,
  message: string,
  hint: string,
) => void;

async function checkProvider(
  options: CheckAuthSetupOptions,
  add: Add,
  env: (field: string) => string,
): Promise<void> {
  const { config } = options;
  const send = options.fetch ?? (fetch as unknown as FetchLike);
  const timeout = (options.timeoutSeconds ?? 5) * 1000;
  const discoveryUrl = `${withoutTrailingSlashes(config.oidc.issuer)}/.well-known/openid-configuration`;
  let metadata: Record<string, unknown>;
  try {
    const response = await send(discoveryUrl, {
      method: "GET",
      headers: { accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(timeout),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    metadata = (await response.json()) as Record<string, unknown>;
  } catch (error) {
    add(
      "error",
      "oidc_discovery_unreachable",
      `The identity provider's discovery document at ${discoveryUrl} could not be read (${error instanceof Error ? error.message : String(error)}). Nobody can sign in while it is down.`,
      `Check ${env("OIDC_ISSUER")} and that the API can reach the provider.`,
    );
    return;
  }
  if (metadata.issuer !== config.oidc.issuer)
    add(
      "error",
      "oidc_issuer_mismatch",
      `The provider says its issuer is ${JSON.stringify(metadata.issuer)}, not ${JSON.stringify(config.oidc.issuer)}. ID tokens will be refused.`,
      `Set ${env("OIDC_ISSUER")} to exactly the provider's issuer, trailing slash included.`,
    );
  const list = (name: string) =>
    Array.isArray(metadata[name]) ? (metadata[name] as unknown[]) : null;
  if (!(list("response_types_supported") ?? []).includes("code"))
    add(
      "error",
      "oidc_code_flow_unsupported",
      "The provider does not offer the authorization code flow (response_types_supported has no code).",
      "Use an OAuth2/OpenID provider configured for the authorization code flow.",
    );
  const pkce = list("code_challenge_methods_supported");
  if (pkce === null)
    add(
      "warning",
      "oidc_pkce_unadvertised",
      "The provider does not say whether it supports PKCE (code_challenge_methods_supported is missing). Sign-in always sends S256.",
      "Check that the provider enforces PKCE with S256.",
    );
  else if (!pkce.includes("S256"))
    add(
      "error",
      "oidc_pkce_unsupported",
      "The provider does not support PKCE with S256, which every sign-in uses.",
      "Enable S256 PKCE at the provider.",
    );

  const tokenEndpoint = metadata.token_endpoint;
  if (typeof tokenEndpoint !== "string") {
    add(
      "error",
      "oidc_token_endpoint_missing",
      "The discovery document has no token_endpoint.",
      "Check the provider's configuration.",
    );
    return;
  }
  // A made-up code: a provider that checks the client first answers
  // invalid_grant for good credentials and invalid_client for bad ones.
  const basePath = withoutTrailingSlashes(options.basePath ?? "/auth");
  const id = encodeURIComponent(config.oidc.clientId);
  const secret = encodeURIComponent(config.oidc.clientSecret);
  let outcome: { status: number; error: unknown } | null = null;
  try {
    const response = await send(tokenEndpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: randomBytes(24).toString("base64url"),
        redirect_uri: `${config.origins.api}${basePath}/callback`,
      }).toString(),
      redirect: "manual",
      signal: AbortSignal.timeout(timeout),
    });
    const body = (await response.json().catch(() => ({}))) as {
      error?: unknown;
    };
    outcome = { status: response.status, error: body.error };
  } catch {
    outcome = null;
  }
  if (outcome?.error === "invalid_client" || outcome?.status === 401)
    add(
      "error",
      "oidc_client_rejected",
      "The provider refused the client id or secret.",
      `Check ${env("OIDC_CLIENT_ID")} and ${env("OIDC_CLIENT_SECRET")} against the provider's application.`,
    );
  else if (outcome?.error !== "invalid_grant")
    add(
      "warning",
      "oidc_client_unverified",
      `The client credentials could not be checked without a sign-in: the provider answered ${outcome ? `${outcome.status} ${JSON.stringify(outcome.error ?? null)}` : "nothing"} to a test request.`,
      "Sign in once to confirm them.",
    );
}

async function checkMigrations(
  options: CheckAuthSetupOptions,
  add: Add,
): Promise<void> {
  const { config, sql } = options;
  let applied: Map<string, string>;
  try {
    const rows = await sql.query<{ name: string; checksum: string }>(
      `SELECT name, checksum FROM ${quoteIdent(config.schema)}.${MIGRATIONS_TABLE}`,
    );
    applied = new Map(rows.map((row) => [row.name, row.checksum]));
  } catch (error) {
    const missing = (error as { code?: unknown }).code === "42P01";
    add(
      "error",
      missing ? "migrations_pending" : "database_unreachable",
      missing
        ? `Schema ${config.schema} has no migrations applied.`
        : `The database could not be queried (${error instanceof Error ? error.message : String(error)}).`,
      missing
        ? "Run migrate() from the app's migrate step."
        : "Check the database connection.",
    );
    return;
  }
  const shipped = await loadMigrations();
  const pending = shipped.filter((m) => !applied.has(m.name));
  const changed = shipped.filter(
    (m) =>
      applied.has(m.name) && applied.get(m.name) !== migrationChecksum(m.sql),
  );
  const names = new Set(shipped.map((m) => m.name));
  const unknown = [...applied.keys()].filter((name) => !names.has(name));
  if (pending.length > 0)
    add(
      "error",
      "migrations_pending",
      `Schema ${config.schema} is missing ${pending.map((m) => m.name).join(", ")}.`,
      "Run migrate() from the app's migrate step.",
    );
  if (changed.length > 0)
    add(
      "error",
      "migrations_modified",
      `Applied migrations changed since: ${changed.map((m) => m.name).join(", ")}.`,
      "Restore the original files; migrate() refuses to run until then.",
    );
  if (unknown.length > 0)
    add(
      "error",
      "migrations_unknown",
      `Schema ${config.schema} has migrations this version does not ship: ${unknown.join(", ")}.`,
      "A newer @avgeek-oss/auth-core migrated it; upgrade the package.",
    );
}

/** The report as log lines: a summary, then one line per problem. */
export function formatAuthSetupReport(
  app: string,
  report: AuthSetupReport,
): string[] {
  const count = (level: AuthSetupProblem["level"]) =>
    report.problems.filter((p) => p.level === level).length;
  const errors = count("error");
  const warnings = count("warning");
  const plural = (n: number, word: string) =>
    `${n} ${word}${n === 1 ? "" : "s"}`;
  return [
    `auth setup for ${app}: ${report.ok ? "ok" : "FAILED"}, ${plural(errors, "error")}, ${plural(warnings, "warning")}`,
    ...report.problems.map(
      (p) => `  ${p.level} ${p.code}: ${p.message} ${p.hint}`,
    ),
  ];
}
