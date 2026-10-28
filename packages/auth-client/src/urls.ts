import type { AnyAuthErrorCode } from "./errors.js";

/** A failed sign-in or step-up, as the callback reports it on the web page. */
export interface AuthRedirectError {
  /** Such as `sign_in_denied` or `step_up_failed`. */
  readonly code: AnyAuthErrorCode;
  /** A finer, stable detail, such as `no_role` or `mfa_missing`, or `null`. */
  readonly reason: string | null;
}

const ERROR = "auth_error";
const REASON = "auth_error_reason";
// Any absolute base works: relative input is parsed against it and returned
// relative again.
const BASE = "http://relative.invalid";

function parse(url: string | URL): { url: URL; relative: boolean } {
  if (url instanceof URL) return { url: new URL(url.href), relative: false };
  const parsed = new URL(url, BASE);
  return { url: parsed, relative: parsed.origin === BASE };
}

/**
 * The error a failed sign-in or step-up callback added to the page's URL
 * (`?auth_error=…&auth_error_reason=…`), or `null`. Pass `location.href`.
 */
export function readAuthRedirectError(
  url: string | URL,
): AuthRedirectError | null {
  const params = parse(url).url.searchParams;
  const code = params.get(ERROR);
  return code ? { code, reason: params.get(REASON) || null } : null;
}

/**
 * `url` without the `auth_error` parameters, keeping everything else. For
 * `history.replaceState` once the error is shown, so a reload does not show
 * it again. Relative input gives relative output.
 */
export function withoutAuthRedirectError(url: string | URL): string {
  const { url: parsed, relative } = parse(url);
  parsed.searchParams.delete(ERROR);
  parsed.searchParams.delete(REASON);
  const path = `${parsed.pathname}${parsed.search}${parsed.hash}`;
  return relative ? path : `${parsed.origin}${path}`;
}

/** `url` with `returnTo` added, when there is one. */
export function addReturnTo(url: string, returnTo?: string | null): string {
  if (!returnTo) return url;
  return `${url}${url.includes("?") ? "&" : "?"}returnTo=${encodeURIComponent(returnTo)}`;
}
