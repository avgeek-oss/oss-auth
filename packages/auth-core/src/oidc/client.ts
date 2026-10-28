import * as oidc from "openid-client";
import type { AuthConfig } from "../config.js";
import { AuthRequestError } from "../errors.js";
import { deriveKeys } from "../keys.js";
import { constantTimeEqual } from "../tokens.js";
import { safeReturnTo } from "./return-to.js";
import {
  openTransaction,
  sealTransaction,
  type OidcTransaction,
  type TransactionPurpose,
} from "./transaction.js";

/** A `fetch` implementation, for tests and outbound proxies. */
export type FetchLike = (
  url: string,
  init: {
    body?: oidc.FetchBody;
    headers: Record<string, string>;
    method: string;
    redirect: "manual";
    signal?: AbortSignal;
  },
) => Promise<Response>;

/** Options for {@link createOidcClient}. */
export interface OidcClientOptions {
  readonly config: AuthConfig;
  /** The callback URL registered with the provider, on the API origin. */
  readonly redirectUri: string;
  /** Seconds to wait for each request to the provider. Default 5. */
  readonly timeoutSeconds?: number;
  /** Seconds to reuse discovered metadata before fetching it again. Default 3600. */
  readonly discoveryCacheSeconds?: number;
  /**
   * Seconds of clock difference tolerated between this server and the
   * provider, for token timestamps and the step-up `auth_time` check.
   * Default 5.
   */
  readonly clockToleranceSeconds?: number;
  /** Replaces `fetch` for every request to the provider. */
  readonly fetch?: FetchLike;
  /** The current time in milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/** What {@link OidcClient.start} returns. */
export interface OidcStart {
  /** Send the browser here. */
  readonly url: string;
  /** Store this in the transaction cookie. */
  readonly transaction: string;
}

/** The validated outcome of a callback. */
export interface OidcCallbackResult {
  readonly transaction: OidcTransaction;
  /** The ID token's claims, validated by openid-client. */
  readonly claims: Readonly<Record<string, unknown>> & {
    readonly iss: string;
    readonly sub: string;
  };
}

/** The OpenID Connect relying party for one app. */
export interface OidcClient {
  /** The discovered configuration, cached. */
  configuration(): Promise<oidc.Configuration>;
  /**
   * Starts a sign-in or step-up: returns the provider URL and the sealed
   * transaction for the cookie. Step-up adds `prompt=login` and `max_age`.
   *
   * @throws {@link AuthRequestError} `return_to_invalid` for an unsafe
   *   `returnTo`, `oidc_unavailable` when discovery fails.
   */
  start(input: {
    readonly purpose: TransactionPurpose;
    readonly returnTo?: string | null;
    readonly sessionIdHash?: string;
    readonly maxAgeSeconds?: number;
  }): Promise<OidcStart>;
  /**
   * Validates a callback: the transaction cookie, `state`, the RFC 9207
   * `iss` parameter (required when the provider advertises it, checked when
   * present), then redeems the code and validates the ID token (signature,
   * `iss`, `aud`, `exp`, `nonce`).
   *
   * @throws {@link AuthRequestError} `oidc_transaction_invalid` or
   *   `oidc_callback_invalid`, with `reason` `state`, `iss`, `nonce`,
   *   `id_token`, `code` or `provider_error`.
   */
  finish(
    callbackUrl: URL,
    transaction: string | undefined,
  ): Promise<OidcCallbackResult>;
  /**
   * The provider's RP-initiated logout URL, or `null` when it has no
   * `end_session_endpoint`.
   */
  endSessionUrl(postLogoutRedirectUri: string): Promise<string | null>;
  /** The transaction cookie's name, also bound into the seal. */
  readonly transactionCookie: string;
  /** Tolerated clock difference, in seconds. */
  readonly clockToleranceSeconds: number;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** The transaction cookie name for an app and API origin. */
export function transactionCookieName(app: string, apiOrigin: string): string {
  return new URL(apiOrigin).protocol === "https:"
    ? `__Host-${app}-oidc`
    : `${app}-oidc`;
}

function reasonOf(error: unknown): string {
  if (error instanceof oidc.AuthorizationResponseError) return "provider_error";
  if (error instanceof oidc.ResponseBodyError) return "code";
  // openid-client wraps oauth4webapi's error, whose cause names the claim.
  for (let e: unknown = error, depth = 0; e && depth < 5; depth++) {
    const cause = (e as { cause?: unknown }).cause;
    const claim = (cause as { claim?: unknown } | undefined)?.claim;
    if (claim === "nonce") return "nonce";
    if (claim === "iss") return "id_token_iss";
    if (claim === "aud") return "id_token_aud";
    if (e instanceof oidc.ResponseBodyError) return "code";
    e = cause;
  }
  return "id_token";
}

/**
 * Creates the relying party. Discovery is lazy: the first call fetches the
 * provider's metadata, with a timeout, and later calls reuse it for
 * `discoveryCacheSeconds`. If a refresh fails, the previous metadata stays in
 * use.
 */
export function createOidcClient(options: OidcClientOptions): OidcClient {
  const { config, redirectUri } = options;
  const now = options.now ?? Date.now;
  const timeout = options.timeoutSeconds ?? 5;
  const ttl = (options.discoveryCacheSeconds ?? 3600) * 1000;
  const tolerance = options.clockToleranceSeconds ?? 5;
  // Seal with the current secret's key; open with any, so a sign-in that
  // started just before a rotation still finishes.
  const transactionKeys = deriveKeys(config, "oidc-transaction");
  const key = transactionKeys[0] ?? raise();
  const cookieName = transactionCookieName(config.app, config.origins.api);
  const issuer = new URL(config.oidc.issuer);
  const insecure = issuer.protocol === "http:" && LOOPBACK.has(issuer.hostname);

  let cached: { config: oidc.Configuration; at: number } | undefined;
  let pending: Promise<oidc.Configuration> | undefined;

  async function discover(): Promise<oidc.Configuration> {
    const discovered = await oidc.discovery(
      issuer,
      config.oidc.clientId,
      {
        client_secret: config.oidc.clientSecret,
        [oidc.clockTolerance]: tolerance,
      },
      oidc.ClientSecretBasic(config.oidc.clientSecret),
      {
        timeout,
        execute: insecure ? [oidc.allowInsecureRequests] : [],
        ...(options.fetch ? { [oidc.customFetch]: options.fetch } : {}),
      },
    );
    discovered.timeout = timeout;
    return discovered;
  }

  async function configuration(): Promise<oidc.Configuration> {
    if (cached && now() - cached.at < ttl) return cached.config;
    pending ??= discover()
      .then((discovered) => {
        cached = { config: discovered, at: now() };
        return discovered;
      })
      .catch((error: unknown) => {
        if (cached) return cached.config;
        throw new AuthRequestError(
          "oidc_unavailable",
          "The identity provider could not be reached. Try again shortly.",
          { cause: error },
        );
      })
      .finally(() => {
        pending = undefined;
      });
    return pending;
  }

  return {
    transactionCookie: cookieName,
    clockToleranceSeconds: tolerance,
    configuration,

    async start(input) {
      const returnTo = safeReturnTo(input.returnTo, config.origins.web);
      if (returnTo === null)
        throw new AuthRequestError(
          "return_to_invalid",
          "returnTo must be a path on this app, such as /settings.",
        );
      const configuration_ = await configuration();
      const transaction: OidcTransaction = {
        state: oidc.randomState(),
        nonce: oidc.randomNonce(),
        verifier: oidc.randomPKCECodeVerifier(),
        returnTo,
        purpose: input.purpose,
        requestedAt: now(),
        ...(input.sessionIdHash === undefined
          ? {}
          : { sessionIdHash: input.sessionIdHash }),
      };
      const parameters: Record<string, string> = {
        redirect_uri: redirectUri,
        scope: config.oidc.scopes.join(" "),
        response_type: "code",
        code_challenge: await oidc.calculatePKCECodeChallenge(
          transaction.verifier,
        ),
        code_challenge_method: "S256",
        state: transaction.state,
        nonce: transaction.nonce,
      };
      if (input.purpose === "step-up") {
        parameters.prompt = "login";
        // authentik ignores max_age=0, so never send less than 1.
        parameters.max_age = String(Math.max(1, input.maxAgeSeconds ?? 300));
      }
      return {
        url: oidc.buildAuthorizationUrl(configuration_, parameters).href,
        transaction: sealTransaction(key, transaction, cookieName),
      };
    },

    async finish(callbackUrl, sealed) {
      const transaction =
        sealed === undefined
          ? null
          : transactionKeys.reduce<ReturnType<typeof openTransaction>>(
              (found, k) =>
                found ?? openTransaction(k, sealed, cookieName, now()),
              null,
            );
      if (transaction === null)
        throw new AuthRequestError(
          "oidc_transaction_invalid",
          "The sign-in attempt expired or was not started in this browser. Sign in again.",
        );
      const params = callbackUrl.searchParams;
      const state = params.get("state");
      if (state === null || !constantTimeEqual(state, transaction.state))
        throw new AuthRequestError(
          "oidc_callback_invalid",
          "The sign-in response does not match this attempt. Sign in again.",
          { reason: "state" },
        );
      const configuration_ = await configuration();
      const metadata = configuration_.serverMetadata();
      const iss = params.get("iss");
      if (
        (iss !== null && iss !== metadata.issuer) ||
        (iss === null &&
          metadata.authorization_response_iss_parameter_supported === true)
      )
        throw new AuthRequestError(
          "oidc_callback_invalid",
          "The sign-in response came from an unexpected identity provider.",
          { reason: "iss" },
        );
      let tokens: Awaited<ReturnType<typeof oidc.authorizationCodeGrant>>;
      try {
        tokens = await oidc.authorizationCodeGrant(
          configuration_,
          callbackUrl,
          {
            pkceCodeVerifier: transaction.verifier,
            expectedState: transaction.state,
            expectedNonce: transaction.nonce,
            idTokenExpected: true,
          },
        );
      } catch (error) {
        throw new AuthRequestError(
          "oidc_callback_invalid",
          "The identity provider's response could not be verified. Sign in again.",
          { cause: error, reason: reasonOf(error) },
        );
      }
      const claims = tokens.claims();
      if (claims === undefined)
        throw new AuthRequestError(
          "oidc_callback_invalid",
          "The identity provider returned no ID token.",
          { reason: "id_token" },
        );
      return {
        transaction,
        claims: claims as OidcCallbackResult["claims"],
      };
    },

    async endSessionUrl(postLogoutRedirectUri) {
      const configuration_ = await configuration();
      if (!configuration_.serverMetadata().end_session_endpoint) return null;
      return oidc.buildEndSessionUrl(configuration_, {
        client_id: config.oidc.clientId,
        post_logout_redirect_uri: postLogoutRedirectUri,
      }).href;
    },
  };
}

function raise(): never {
  throw new Error("deriveKeys returned no key.");
}
