import { hkdfSync } from "node:crypto";
import { SecretTooShortError, UnknownKeyLabelError } from "./errors.js";
import { assertAppId } from "./app-id.js";
import { MIN_SECRET_BYTES } from "./config.js";

/**
 * Every purpose a key is derived for. Each label yields an independent key,
 * so a value made for one purpose is useless for another.
 *
 * Labels are part of the stored data's format: renaming one, or changing
 * {@link KEY_DERIVATION_SALT}, invalidates every hash and signature made with
 * it. Add labels; never change or reuse one.
 */
export const KEY_LABELS = [
  /** Hashes session tokens at rest. */
  "session",
  /** Protects the short-lived OIDC sign-in transaction (state, nonce, PKCE). */
  "oidc-transaction",
  /** Hashes SCIM bearer tokens for comparison. */
  "scim-token",
  /** Hashes API key secrets at rest. */
  "api-key",
  /** Hashes OAuth authorization codes at rest. */
  "oauth-code",
  /** Hashes OAuth access tokens at rest. */
  "oauth-access-token",
  /** Hashes OAuth refresh tokens at rest. */
  "oauth-refresh-token",
  /** Encrypts stored idempotent responses. */
  "idempotency",
  /** Hashes one-time break-glass sign-in tokens. */
  "break-glass",
  /** Hashes the ids of pending OAuth consent requests at rest. */
  "oauth-request",
  /** Hashes rate limit keys, so buckets never hold raw IPs or ids. */
  "rate-limit",
] as const;

/** One of {@link KEY_LABELS}. */
export type KeyLabel = (typeof KEY_LABELS)[number];

/** The HKDF salt for every auth-core key. Fixed; see {@link KEY_LABELS}. */
export const KEY_DERIVATION_SALT = "avgeek-oss/auth-core";

/** Length in bytes of every derived key. */
export const DERIVED_KEY_BYTES = 32;

/**
 * Derives the 32-byte key for `label` from the app secret with HKDF-SHA256
 * (RFC 5869):
 *
 * ```text
 * HKDF-SHA256(IKM = UTF-8(secret), salt = "avgeek-oss/auth-core",
 *             info = "<app>:<label>:v1", L = 32)
 * ```
 *
 * The app id in `info` keeps two apps that share a secret apart.
 *
 * @throws {@link SecretTooShortError} when the secret is under 32 bytes.
 * @throws {@link UnknownKeyLabelError} when `label` is not registered.
 * @throws `TypeError` when `app` is not a valid app id.
 */
export function deriveKey(
  secret: string,
  app: string,
  label: KeyLabel,
): Buffer {
  const bytes = Buffer.byteLength(secret);
  if (bytes < MIN_SECRET_BYTES) throw new SecretTooShortError(bytes);
  if (!(KEY_LABELS as readonly string[]).includes(label))
    throw new UnknownKeyLabelError(label);
  assertAppId(app);
  return Buffer.from(
    hkdfSync(
      "sha256",
      Buffer.from(secret, "utf8"),
      Buffer.from(KEY_DERIVATION_SALT, "utf8"),
      Buffer.from(`${app}:${label}:v1`, "utf8"),
      DERIVED_KEY_BYTES,
    ),
  );
}

/** Derived keys for one app, computed on first use and cached. */
export interface Keyring {
  /** The key for `label`. Returns a copy, so callers cannot alter the cache. */
  key(label: KeyLabel): Buffer;
}

/**
 * A {@link Keyring} over `secret` and `app`, usually `config.secret` and
 * `config.app`. Validates the secret immediately.
 */
export function createKeyring(secret: string, app: string): Keyring {
  const bytes = Buffer.byteLength(secret);
  if (bytes < MIN_SECRET_BYTES) throw new SecretTooShortError(bytes);
  assertAppId(app);
  const cache = new Map<KeyLabel, Buffer>();
  return {
    key(label) {
      let key = cache.get(label);
      if (key === undefined) {
        key = deriveKey(secret, app, label);
        cache.set(label, key);
      }
      return Buffer.from(key);
    },
  };
}
