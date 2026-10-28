/**
 * Stable error codes. Apps may branch on these, log them and map them to
 * responses; a code never changes meaning once released.
 */
export const AUTH_ERROR_CODES = [
  "config_invalid",
  "secret_too_short",
  "key_label_unknown",
  "api_key_invalid",
  "migration_invalid",
  "migration_modified",
  "migration_unknown",
] as const;

/** One of {@link AUTH_ERROR_CODES}. */
export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[number];

/**
 * Base class of every error auth-core throws on purpose. Errors from the
 * database driver or the runtime pass through unchanged.
 */
export class AuthError extends Error {
  /** Stable, machine-readable reason. */
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
  }
}

/** One problem found while reading configuration. */
export interface ConfigIssue {
  /** The environment variable at fault, such as `POSTED_OIDC_ISSUER`. */
  variable: string;
  /** What is wrong and what a valid value looks like. */
  message: string;
}

/**
 * The environment does not describe a valid configuration. The message lists
 * every problem, each starting with the variable's name, so operators can fix
 * them all at once. No values are echoed, because some are secrets.
 */
export class AuthConfigError extends AuthError {
  /** Every problem found, in variable order. */
  readonly issues: readonly ConfigIssue[];

  constructor(issues: readonly ConfigIssue[]) {
    super(
      "config_invalid",
      [
        "Invalid auth configuration:",
        ...issues.map((issue) => `- ${issue.variable}: ${issue.message}`),
      ].join("\n"),
    );
    this.issues = issues;
  }
}

/** A key derivation was asked to use a secret shorter than 32 bytes. */
export class SecretTooShortError extends AuthError {
  constructor(bytes: number) {
    super(
      "secret_too_short",
      `The app secret is ${bytes} bytes; it must be at least 32. Generate one with \`openssl rand -base64 48\`.`,
    );
  }
}

/** A key derivation named a label that is not in the registry. */
export class UnknownKeyLabelError extends AuthError {
  constructor(label: string) {
    super(
      "key_label_unknown",
      `"${label}" is not a registered key label. Use one of KEY_LABELS.`,
    );
  }
}

/** Why an API key failed to parse. */
export type InvalidApiKeyReason = "malformed" | "prefix" | "checksum";

/**
 * A string is not a well-formed API key for this app. Treat it exactly like
 * an unknown key: do not tell the caller which part was wrong.
 */
export class InvalidApiKeyError extends AuthError {
  /** For logs and tests only. */
  readonly reason: InvalidApiKeyReason;

  constructor(reason: InvalidApiKeyReason) {
    super("api_key_invalid", `The API key is invalid (${reason}).`);
    this.reason = reason;
  }
}

/** Why the migration runner refused to run. */
export class MigrationError extends AuthError {
  /** The migration file at fault. */
  readonly migration: string;

  constructor(
    code: "migration_invalid" | "migration_modified" | "migration_unknown",
    migration: string,
    message: string,
  ) {
    super(code, message);
    this.migration = migration;
  }
}

/**
 * True when `error` is an {@link AuthError}, optionally with the given code.
 * Works across duplicate installs of the package, where `instanceof` fails.
 */
export function isAuthError(
  error: unknown,
  code?: AuthErrorCode,
): error is AuthError {
  if (!(error instanceof Error)) return false;
  const value = (error as { code?: unknown }).code;
  if (typeof value !== "string") return false;
  if (!(AUTH_ERROR_CODES as readonly string[]).includes(value)) return false;
  return code === undefined || value === code;
}
