/**
 * The error codes the auth API answers with, as `{ "error": { "code" } }`
 * or as `?auth_error=` after a failed sign-in. A code never changes meaning
 * once released. Servers may add codes; {@link AuthClientError} passes
 * unknown ones through unchanged.
 */
export const AUTH_ERROR_CODES = [
  "unauthenticated",
  "forbidden",
  "step_up_required",
  "step_up_failed",
  "step_up_unavailable",
  "origin_invalid",
  "csrf_header_missing",
  "return_to_invalid",
  "oidc_unavailable",
  "oidc_transaction_invalid",
  "oidc_callback_invalid",
  "sign_in_denied",
  "logout_token_invalid",
  "invalid_request",
  "not_found",
  "conflict",
  "rate_limited",
  "unavailable",
] as const;

/** One of {@link AUTH_ERROR_CODES}. */
export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[number];

/**
 * Codes the client itself uses when there is no answer from the auth API to
 * read: `network_error` when the request could not be sent or its answer
 * not received, and `invalid_response` when the answer is not the API's
 * JSON.
 */
export type ClientErrorCode = "network_error" | "invalid_response";

/**
 * The code of an {@link AuthClientError}: a known server code, a client
 * code, or any other string a newer server sends.
 */
export type AnyAuthErrorCode = AuthErrorCode | ClientErrorCode | (string & {});

/** What {@link AuthClientError} is built from. */
export interface AuthClientErrorInit {
  readonly code: AnyAuthErrorCode;
  readonly status: number;
  readonly message: string;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly retryAfterSeconds?: number | null;
  readonly cause?: unknown;
}

/**
 * A request to the auth API failed. `code` is the server's stable code
 * (see {@link AUTH_ERROR_CODES}), passed through unchanged when the client
 * does not know it, or a {@link ClientErrorCode}. `message` is safe to show.
 */
export class AuthClientError extends Error {
  /** The stable, machine-readable code. */
  readonly code: AnyAuthErrorCode;
  /** The HTTP status, or 0 when no answer arrived. */
  readonly status: number;
  /**
   * Every other field of the server's error object, such as `stepUpUrl`.
   * Empty when there was none.
   */
  readonly details: Readonly<Record<string, unknown>>;
  /** For `step_up_required`: where to send the person to confirm. */
  readonly stepUpUrl: string | null;
  /** For `rate_limited`: whole seconds until a retry may succeed. */
  readonly retryAfterSeconds: number | null;

  constructor(init: AuthClientErrorInit) {
    super(
      init.message,
      init.cause === undefined ? undefined : { cause: init.cause },
    );
    this.name = "AuthClientError";
    this.code = init.code;
    this.status = init.status;
    this.details = init.details ?? {};
    const stepUpUrl = this.details.stepUpUrl;
    this.stepUpUrl = typeof stepUpUrl === "string" ? stepUpUrl : null;
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
  }
}

/**
 * True when `error` is an {@link AuthClientError}, optionally with the
 * given code. Works across duplicate copies of this package, where
 * `instanceof` fails.
 */
export function isAuthClientError(
  error: unknown,
  code?: AnyAuthErrorCode,
): error is AuthClientError {
  if (!(error instanceof Error) || error.name !== "AuthClientError")
    return false;
  const value = (error as { code?: unknown }).code;
  return typeof value === "string" && (code === undefined || value === code);
}
