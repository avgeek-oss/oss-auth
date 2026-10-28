/**
 * Checks a `returnTo` value and returns it as a path on the web origin, or
 * `null` when it is unsafe.
 *
 * Only absolute paths are accepted: `/settings?tab=keys#top`. Rejected:
 * absolute and scheme-relative URLs (`https://evil`, `//evil`), backslashes
 * (browsers read `/\evil` as `//evil`), control characters and whitespace,
 * percent-encoded slashes or backslashes, and anything longer than 2048
 * characters. A missing or empty value means `/`.
 */
export function safeReturnTo(
  value: string | null | undefined,
  webOrigin: string,
): string | null {
  if (value === undefined || value === null || value === "") return "/";
  if (value.length > 2048) return null;
  if (!value.startsWith("/") || value.startsWith("//")) return null;
  if (/[\\\p{Cc}\s]/u.test(value)) return null;
  if (/%(2f|5c|00)/i.test(value)) return null;
  let url: URL;
  try {
    url = new URL(value, webOrigin);
  } catch {
    return null;
  }
  if (url.origin !== new URL(webOrigin).origin) return null;
  return `${url.pathname}${url.search}${url.hash}`;
}
