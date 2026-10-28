/** The longest redirect URI or client URL accepted, in characters. */
export const MAX_URI_LENGTH = 2048;

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);

/**
 * True for a redirect URI an OAuth client may register: `https`, or `http`
 * on a loopback host for native apps (RFC 8252), with no fragment and no
 * credentials.
 */
export function isValidRedirectUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length > MAX_URI_LENGTH) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return (
    !value.includes("#") &&
    url.username === "" &&
    url.password === "" &&
    (url.protocol === "https:" ||
      (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)))
  );
}

/** True when `value` is an `https` URL with no credentials or fragment. */
export function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length > MAX_URI_LENGTH) return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      !value.includes("#")
    );
  } catch {
    return false;
  }
}

const LOOPBACK_LITERAL =
  /^(http:\/\/(?:127\.0\.0\.1|\[::1\]))(?::\d{1,5})?(?=[/?]|$)/;

/**
 * Whether a redirect URI sent in a request matches a registered one: exactly,
 * or, for a registered `http` loopback IP literal, with any port (RFC 8252
 * §7.3). `localhost` gets no port variance, as RFC 8252 §8.3 advises.
 */
export function redirectMatches(registered: string, supplied: string): boolean {
  if (!isValidRedirectUri(registered) || !isValidRedirectUri(supplied))
    return false;
  if (registered === supplied) return true;
  if (!LOOPBACK_LITERAL.test(registered)) return false;
  const strip = (value: string) => value.replace(LOOPBACK_LITERAL, "$1");
  return (
    LOOPBACK_LITERAL.test(supplied) && strip(registered) === strip(supplied)
  );
}

/** True when the URI's host is a loopback address or `localhost`. */
export function isLoopbackRedirect(value: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(value).hostname);
  } catch {
    return false;
  }
}
