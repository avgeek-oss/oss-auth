import { randomBytes } from "node:crypto";
import { crc32 } from "node:zlib";
import { InvalidApiKeyError } from "./errors.js";

/**
 * API keys look like `posted_01JBX5E8W6TGGDFXR9NB7QH4PC_<43 characters>_<6 characters>`:
 *
 * | Part       | Format                                                     |
 * | ---------- | ---------------------------------------------------------- |
 * | `prefix`   | the app's key prefix: 2 to 16 lowercase letters or digits  |
 * | `id`       | 26 Crockford base32 characters (128 bits, ULID-compatible) |
 * | `secret`   | 43 base62 characters (256 bits)                            |
 * | `checksum` | CRC32 of `<prefix>_<id>_<secret>`, as 6 base62 characters  |
 *
 * Every part uses word characters only, so a double-click selects the whole
 * key. The checksum lets secret scanners and the app reject typos and
 * look-alikes without a database read. It is not a security control.
 */
export interface ApiKeyParts {
  /** The app's key prefix, such as `posted`. */
  readonly prefix: string;
  /** The key's public id. Safe to log and show. */
  readonly id: string;
  /** The secret. Store only its hash. */
  readonly secret: string;
}

/** Characters in an API key id. */
export const API_KEY_ID_LENGTH = 26;

/** Characters in an API key secret. */
export const API_KEY_SECRET_LENGTH = 43;

/** Characters in an API key checksum. */
export const API_KEY_CHECKSUM_LENGTH = 6;

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX = "[a-z][a-z0-9]{1,15}";
const ID = "[0-7][0-9A-HJKMNP-TV-Z]{25}";
const SECRET = "[0-9A-Za-z]{43}";
const CHECKSUM = "[0-9A-Za-z]{6}";
const PREFIX_PATTERN = new RegExp(`^${PREFIX}$`);
const KEY_PATTERN = new RegExp(
  `^(${PREFIX})_(${ID})_(${SECRET})_(${CHECKSUM})$`,
);

function assertPrefix(prefix: string): void {
  if (!PREFIX_PATTERN.test(prefix))
    throw new TypeError(
      `API key prefix "${prefix}" must be 2 to 16 lowercase letters or digits, starting with a letter.`,
    );
}

/** Uniformly random base62 characters, by rejection sampling. */
function randomBase62(length: number): string {
  let out = "";
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      // 248 = 4 * 62: bytes above it would bias the first characters.
      if (byte >= 248) continue;
      out += BASE62[byte % 62];
      if (out.length === length) break;
    }
  }
  return out;
}

/** A new random API key id: 128 bits as 26 Crockford base32 characters. */
export function generateApiKeyId(): string {
  let value = BigInt(`0x${randomBytes(16).toString("hex")}`);
  let out = "";
  for (let i = 0; i < API_KEY_ID_LENGTH; i++) {
    out = CROCKFORD[Number(value & 31n)] + out;
    value >>= 5n;
  }
  return out;
}

/**
 * The checksum for `<prefix>_<id>_<secret>`: its CRC32 as 6 base62
 * characters, zero-padded.
 */
export function apiKeyChecksum(body: string): string {
  let value = crc32(Buffer.from(body, "utf8"));
  let out = "";
  for (let i = 0; i < API_KEY_CHECKSUM_LENGTH; i++) {
    out = BASE62[value % 62] + out;
    value = Math.floor(value / 62);
  }
  return out;
}

/**
 * Assembles a key from its parts and appends the checksum.
 *
 * @throws `TypeError` when a part has the wrong format.
 */
export function formatApiKey(parts: ApiKeyParts): string {
  assertPrefix(parts.prefix);
  if (!new RegExp(`^${ID}$`).test(parts.id))
    throw new TypeError(
      "API key ids must be 26 Crockford base32 characters starting with 0-7.",
    );
  if (!new RegExp(`^${SECRET}$`).test(parts.secret))
    throw new TypeError("API key secrets must be 43 base62 characters.");
  const body = `${parts.prefix}_${parts.id}_${parts.secret}`;
  return `${body}_${apiKeyChecksum(body)}`;
}

/**
 * A new API key for `prefix`, with a random id and secret.
 *
 * @param id - Use this id instead of a random one, such as a ULID the app
 *   already allocated.
 * @returns The parts, and `key`, the full string to show the user once.
 */
export function generateApiKey(
  prefix: string,
  id: string = generateApiKeyId(),
): ApiKeyParts & { readonly key: string } {
  const parts = { prefix, id, secret: randomBase62(API_KEY_SECRET_LENGTH) };
  return { ...parts, key: formatApiKey(parts) };
}

/**
 * Splits and checks an API key.
 *
 * @param expectedPrefix - When given, keys for other prefixes are rejected.
 * @throws {@link InvalidApiKeyError} with reason `malformed`, `prefix` or
 *   `checksum`. Respond to all three exactly as to an unknown key.
 */
export function parseApiKey(
  value: string,
  expectedPrefix?: string,
): ApiKeyParts {
  if (expectedPrefix !== undefined) assertPrefix(expectedPrefix);
  const match = typeof value === "string" ? KEY_PATTERN.exec(value) : null;
  if (match === null) throw new InvalidApiKeyError("malformed");
  const [, prefix = "", id = "", secret = "", checksum = ""] = match;
  if (expectedPrefix !== undefined && prefix !== expectedPrefix)
    throw new InvalidApiKeyError("prefix");
  if (apiKeyChecksum(`${prefix}_${id}_${secret}`) !== checksum)
    throw new InvalidApiKeyError("checksum");
  return { prefix, id, secret };
}

/** True when {@link parseApiKey} would accept `value`. Never throws for input. */
export function isValidApiKey(
  value: unknown,
  expectedPrefix?: string,
): boolean {
  if (typeof value !== "string") return false;
  try {
    parseApiKey(value, expectedPrefix);
    return true;
  } catch (error) {
    if (error instanceof InvalidApiKeyError) return false;
    throw error;
  }
}

/**
 * A global regular expression that finds keys for `prefix` in text, for
 * secret scanning and log redaction. Matches still need
 * {@link isValidApiKey} to confirm the checksum.
 */
export function apiKeyPattern(prefix: string): RegExp {
  assertPrefix(prefix);
  return new RegExp(
    `(?<![0-9A-Za-z_])${prefix}_${ID}_${SECRET}_${CHECKSUM}(?![0-9A-Za-z_])`,
    "g",
  );
}
