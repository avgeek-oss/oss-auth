import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/** What a sign-in or step-up is for. */
export type TransactionPurpose = "sign-in" | "step-up";

/**
 * The state of one sign-in attempt, kept in the browser between the redirect
 * to the provider and the callback. Sealed, so the browser can neither read
 * nor change it.
 */
export interface OidcTransaction {
  readonly state: string;
  readonly nonce: string;
  /** The PKCE code verifier. */
  readonly verifier: string;
  /** Where to send the person afterwards: a path on the web origin. */
  readonly returnTo: string;
  readonly purpose: TransactionPurpose;
  /** When the attempt started, in milliseconds since the epoch. */
  readonly requestedAt: number;
  /** For step-up: the hash of the session being stepped up. */
  readonly sessionIdHash?: string;
}

/** How long a transaction stays valid: 10 minutes. */
export const TRANSACTION_TTL_SECONDS = 600;

const VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Seals `transaction` with AES-256-GCM under `key` (the derived
 * `oidc-transaction` key). The result is base64url: a version byte, a random
 * 96-bit IV, the ciphertext and the tag. `aad` binds it to its use, such as
 * the cookie name.
 */
export function sealTransaction(
  key: Uint8Array,
  transaction: OidcTransaction,
  aad: string,
): string {
  if (key.byteLength !== 32)
    throw new RangeError("Transaction keys must be 32 bytes.");
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const body = Buffer.concat([
    cipher.update(JSON.stringify(transaction), "utf8"),
    cipher.final(),
  ]);
  return Buffer.concat([
    Buffer.from([VERSION]),
    iv,
    body,
    cipher.getAuthTag(),
  ]).toString("base64url");
}

function isTransaction(value: unknown): value is OidcTransaction {
  if (typeof value !== "object" || value === null) return false;
  const t = value as Record<string, unknown>;
  return (
    typeof t.state === "string" &&
    typeof t.nonce === "string" &&
    typeof t.verifier === "string" &&
    typeof t.returnTo === "string" &&
    (t.purpose === "sign-in" || t.purpose === "step-up") &&
    typeof t.requestedAt === "number" &&
    Number.isFinite(t.requestedAt) &&
    (t.sessionIdHash === undefined || typeof t.sessionIdHash === "string")
  );
}

/**
 * Opens a sealed transaction. Returns `null` when the value is malformed,
 * was sealed under another key or `aad`, was changed, or is older than
 * {@link TRANSACTION_TTL_SECONDS} at `now` (or claims to be from the future).
 */
export function openTransaction(
  key: Uint8Array,
  sealed: string,
  aad: string,
  now: number,
): OidcTransaction | null {
  const raw = Buffer.from(sealed, "base64url");
  if (
    raw.length < 1 + IV_BYTES + TAG_BYTES + 2 ||
    raw[0] !== VERSION ||
    raw.toString("base64url") !== sealed
  )
    return null;
  const iv = raw.subarray(1, 1 + IV_BYTES);
  const tag = raw.subarray(raw.length - TAG_BYTES);
  const body = raw.subarray(1 + IV_BYTES, raw.length - TAG_BYTES);
  let parsed: unknown;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv, {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(tag);
    parsed = JSON.parse(
      Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8"),
    );
  } catch {
    return null;
  }
  if (!isTransaction(parsed)) return null;
  const age = now - parsed.requestedAt;
  if (age < -60_000 || age > TRANSACTION_TTL_SECONDS * 1000) return null;
  return parsed;
}
