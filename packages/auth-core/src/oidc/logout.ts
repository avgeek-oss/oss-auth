import { errors, jwtVerify, type JWTVerifyGetKey } from "jose";
import { AuthRequestError } from "../errors.js";
import type { SqlQueryable } from "../postgres/sql.js";

/** The `events` member that marks a back-channel logout token. */
export const BACKCHANNEL_LOGOUT_EVENT =
  "http://schemas.openid.net/event/backchannel-logout";

/** Remembers logout token ids so a token cannot be replayed. */
export interface JtiStore {
  /**
   * Records `jti` from `issuer` until `expiresAt`, on `db`. Pass the
   * transaction that also revokes the sessions, so the id is recorded only
   * if the logout takes effect. Returns `false` when it was already
   * recorded, which means the token is a replay.
   */
  remember(
    db: SqlQueryable,
    issuer: string,
    jti: string,
    expiresAt: Date,
  ): Promise<boolean>;
}

/** A validated back-channel logout token. */
export interface LogoutToken {
  readonly iss: string;
  readonly jti: string;
  /** The provider's subject, when the token names one. */
  readonly sub: string | null;
  /** The provider's session id, when the token names one. */
  readonly sid: string | null;
  /**
   * When the token stops being acceptable (`iat` + max age + tolerance).
   * Keep its `jti` until then.
   */
  readonly expiresAt: Date;
}

/** Options for {@link verifyLogoutToken}. */
export interface VerifyLogoutTokenOptions {
  /** The expected `iss`, exactly. */
  readonly issuer: string;
  /** This app's client id, which `aud` must contain. */
  readonly clientId: string;
  /** The provider's signing keys, usually `createRemoteJWKSet(jwks_uri)`. */
  readonly keys: JWTVerifyGetKey;
  /** Oldest `iat` accepted, in seconds. Default 300. */
  readonly maxAgeSeconds?: number;
  /** Tolerated clock difference, in seconds. Default 5. */
  readonly clockToleranceSeconds?: number;
  /** The current time. Defaults to now. */
  readonly now?: () => number;
}

const ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
];

function invalid(reason: string, cause?: unknown): AuthRequestError {
  return new AuthRequestError(
    "logout_token_invalid",
    "The logout token is invalid.",
    { reason, ...(cause === undefined ? {} : { cause }) },
  );
}

/**
 * Validates a back-channel logout token as OpenID Connect Back-Channel
 * Logout 1.0 §2.6 requires:
 *
 * - an asymmetric JWS signature from the provider's keys (`alg: none` and
 *   shared-secret algorithms are refused);
 * - `iss`, `aud` containing this client, `iat` no older than
 *   `maxAgeSeconds`, and `exp` when present;
 * - `typ`, when present, of `logout+jwt`;
 * - an `events` claim with the back-channel logout member as an object;
 * - `sub`, `sid` or both, and no `nonce`;
 * - a `jti`.
 *
 * It does not check for replay: the caller records `jti` in a
 * {@link JtiStore} in the same transaction that revokes the sessions, so a
 * failed revocation leaves the token usable for the provider's retry.
 *
 * @throws {@link AuthRequestError} `logout_token_invalid`, with `reason`
 *   `signature`, `claims`, `events`, `subject`, `nonce` or `jti`.
 */
export async function verifyLogoutToken(
  token: string,
  options: VerifyLogoutTokenOptions,
): Promise<LogoutToken> {
  const maxAge = options.maxAgeSeconds ?? 300;
  const tolerance = options.clockToleranceSeconds ?? 5;
  const now = options.now ?? Date.now;
  let payload: Record<string, unknown>;
  let typ: string | undefined;
  try {
    const result = await jwtVerify(token, options.keys, {
      issuer: options.issuer,
      audience: options.clientId,
      algorithms: ALGORITHMS,
      maxTokenAge: maxAge,
      clockTolerance: tolerance,
      currentDate: new Date(now()),
      requiredClaims: ["iat"],
    });
    payload = result.payload;
    typ = result.protectedHeader.typ;
  } catch (error) {
    throw invalid(
      error instanceof errors.JWTClaimValidationFailed ||
        error instanceof errors.JWTExpired
        ? "claims"
        : "signature",
      error,
    );
  }
  if (typ !== undefined && typ.toLowerCase() !== "logout+jwt")
    throw invalid("claims");
  const events = payload.events;
  const event =
    typeof events === "object" && events !== null
      ? (events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT]
      : undefined;
  if (typeof event !== "object" || event === null || Array.isArray(event))
    throw invalid("events");
  if (Object.hasOwn(payload, "nonce")) throw invalid("nonce");
  const sub =
    typeof payload.sub === "string" && payload.sub !== "" ? payload.sub : null;
  const sid =
    typeof payload.sid === "string" && payload.sid !== "" ? payload.sid : null;
  if (sub === null && sid === null) throw invalid("subject");
  const jti = payload.jti;
  if (typeof jti !== "string" || jti === "" || jti.length > 255)
    throw invalid("jti");
  const iat = payload.iat as number;
  // Keep the id until iat + maxAge + tolerance: after that, the token is
  // refused as too old anyway.
  const expiresAt = new Date((iat + maxAge + tolerance) * 1000);
  return { iss: options.issuer, jti, sub, sid, expiresAt };
}
