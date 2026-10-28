import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/** Random bytes in every generated token: 256 bits. */
export const TOKEN_BYTES = 32;

/** Characters in a generated token: 32 bytes as unpadded base64url. */
export const TOKEN_LENGTH = 43;

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/**
 * A new 256-bit random token, as 43 unpadded base64url characters. Use it for
 * session ids, authorization codes and any other bearer secret.
 */
export function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

/**
 * True when `value` has the exact shape {@link generateToken} produces: 43
 * base64url characters encoding 32 bytes. Check this before hashing input,
 * so malformed values are rejected without a database read.
 */
export function isWellFormedToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

/**
 * The value to store for `token`: HMAC-SHA256 under `key` (a derived key for
 * the token's purpose), as 64 lowercase hex characters.
 *
 * An HMAC, rather than a plain hash, means a leaked table cannot be checked
 * against guessed tokens without the app secret.
 *
 * This is deliberately not a password hash such as Argon2 or scrypt, which
 * code scanners may suggest. Those slow down guessing of low-entropy,
 * human-chosen secrets. Every value hashed here is machine-generated with at
 * least 256 bits of entropy (sessions, API key secrets, OAuth codes and
 * tokens), so guessing is already infeasible, and a fast keyed hash keeps
 * each request's lookup cheap.
 */
export function hashToken(key: Uint8Array, token: string): string {
  if (key.byteLength < 32)
    throw new RangeError("Token hashing keys must be at least 32 bytes.");
  return createHmac("sha256", key).update(token, "utf8").digest("hex");
}

/**
 * Compares two values without leaking where they differ. Both sides are
 * hashed with SHA-256 and the digests compared with `timingSafeEqual`, so the
 * comparison time reveals neither the position of a mismatch nor the length
 * of the expected value.
 */
export function constantTimeEqual(
  a: string | Uint8Array,
  b: string | Uint8Array,
): boolean {
  const digest = (value: string | Uint8Array) =>
    createHash("sha256").update(value).digest();
  const da = digest(a);
  const db = digest(b);
  // Equal digests mean equal inputs in practice. The exact comparison runs
  // only then, so it leaks nothing about unequal inputs.
  if (!timingSafeEqual(da, db)) return false;
  return Buffer.from(a).equals(Buffer.from(b));
}

/**
 * True when `token` hashes to `storedHash` under `key`, compared in
 * constant time.
 */
export function verifyTokenHash(
  key: Uint8Array,
  token: string,
  storedHash: string,
): boolean {
  return constantTimeEqual(hashToken(key, token), storedHash);
}
