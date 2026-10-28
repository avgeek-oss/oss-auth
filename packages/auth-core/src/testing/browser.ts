/** One stored cookie. */
interface StoredCookie {
  value: string;
  path: string;
  secure: boolean;
  expires: number | null;
}

/** A step of {@link Browser.follow}. */
export interface BrowserHop {
  readonly url: string;
  readonly status: number;
}

/** What {@link Browser.follow} returns. */
export interface FollowResult {
  /** The last response: not a redirect, or the one `stopAt` matched. */
  readonly response: Response;
  /** The URL of the last request, or the redirect target `stopAt` matched. */
  readonly url: string;
  readonly hops: readonly BrowserHop[];
}

/** A `fetch` with a cookie jar, standing in for a browser in tests. */
export interface Browser {
  /** One request with the jar's cookies. Redirects are not followed. */
  fetch(url: string, init?: RequestInit): Promise<Response>;
  /**
   * Requests `url` and follows redirects like a browser navigation (303 and
   * 302 become GET), up to 20. Pages that only auto-submit a form, as
   * providers use for logout confirmations and `form_post`, are submitted
   * too. Stops early, without requesting it, at the first target `stopAt`
   * accepts, such as the web origin, which nothing serves in tests.
   */
  follow(
    url: string,
    options?: {
      readonly init?: RequestInit;
      readonly stopAt?: (url: URL) => boolean;
      /** Rewrites each URL before it is requested, to simulate tampering. */
      readonly rewrite?: (url: URL) => URL;
    },
  ): Promise<FollowResult>;
  /**
   * Submits the first POST form on a page `follow` stopped at, as a person
   * clicking its button would, then follows like {@link Browser.follow}.
   * `fields` adds or replaces values, such as the button's `name=value`.
   */
  submit(
    page: FollowResult,
    fields?: Readonly<Record<string, string>>,
    options?: { readonly stopAt?: (url: URL) => boolean },
  ): Promise<FollowResult>;
  /** The cookie `name` the jar would send to `url`, if any. */
  cookie(url: string, name: string): string | undefined;
  /** Stores a cookie for `url`'s host, as an attacker might plant one. */
  setCookie(url: string, name: string, value: string): void;
  /** Forgets every cookie for `url`'s host. */
  clear(url: string): void;
}

function decode(value: string): string {
  return value
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

/** The form a page submits on load, if it is that kind of page. */
function autoSubmitForm(
  html: string,
  base: URL,
): { action: URL; body: URLSearchParams } | null {
  if (!/\.submit\(\)/.test(html)) return null;
  return firstForm(html, base);
}

/** The first POST form on a page, with its inputs' values. */
function firstForm(
  html: string,
  base: URL,
): { action: URL; body: URLSearchParams } | null {
  const form =
    /<form[^>]*method="post"[^>]*action="([^"]+)"[^>]*>([\s\S]*?)<\/form>/i.exec(
      html,
    );
  if (!form) return null;
  const body = new URLSearchParams();
  for (const input of (form[2] ?? "").matchAll(/<input[^>]*>/gi)) {
    const name = /name="([^"]*)"/.exec(input[0])?.[1];
    const value = /value="([^"]*)"/.exec(input[0])?.[1] ?? "";
    if (name !== undefined) body.append(decode(name), decode(value));
  }
  return { action: new URL(decode(form[1] ?? ""), base), body };
}

/**
 * Creates a {@link Browser}. Cookies are host-only and keyed by hostname,
 * ignoring the port, as browsers do. `Path`, `Secure`, `Max-Age` and
 * `Expires` are honoured.
 */
export function createBrowser(): Browser {
  const jar = new Map<string, Map<string, StoredCookie>>();

  const store = (url: URL, header: string) => {
    const [pair = "", ...attributes] = header.split(";");
    const eq = pair.indexOf("=");
    if (eq <= 0) return;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    const cookie: StoredCookie = {
      value,
      path: "/",
      secure: false,
      expires: null,
    };
    for (const attribute of attributes) {
      const [key = "", ...rest] = attribute.split("=");
      const k = key.trim().toLowerCase();
      const v = rest.join("=").trim();
      if (k === "path") cookie.path = v || "/";
      else if (k === "secure") cookie.secure = true;
      else if (k === "max-age") cookie.expires = Date.now() + Number(v) * 1000;
      else if (k === "expires" && cookie.expires === null)
        cookie.expires = Date.parse(v);
    }
    if (cookie.secure && url.protocol !== "https:") return;
    const host = jar.get(url.hostname) ?? new Map<string, StoredCookie>();
    jar.set(url.hostname, host);
    if (cookie.expires !== null && cookie.expires <= Date.now())
      host.delete(name);
    else host.set(name, cookie);
  };

  const header = (url: URL) => {
    const host = jar.get(url.hostname);
    if (!host) return "";
    const out: string[] = [];
    for (const [name, cookie] of host) {
      if (cookie.expires !== null && cookie.expires <= Date.now()) continue;
      if (cookie.secure && url.protocol !== "https:") continue;
      if (!url.pathname.startsWith(cookie.path)) continue;
      out.push(`${name}=${cookie.value}`);
    }
    return out.join("; ");
  };

  const request = async (url: string, init: RequestInit = {}) => {
    const target = new URL(url);
    const headers = new Headers(init.headers);
    const cookies = header(target);
    if (cookies) headers.set("cookie", cookies);
    const response = await fetch(target, {
      ...init,
      headers,
      redirect: "manual",
    });
    for (const value of response.headers.getSetCookie()) store(target, value);
    return response;
  };

  return {
    fetch: request,
    async follow(url, options = {}) {
      const rewrite = options.rewrite ?? ((u: URL) => u);
      let current = rewrite(new URL(url));
      let init = options.init ?? {};
      const hops: BrowserHop[] = [];
      for (let i = 0; i <= 20; i++) {
        const response = await request(current.href, init);
        hops.push({ url: current.href, status: response.status });
        const location = response.headers.get("location");
        if (
          response.status === 200 &&
          /text\/html/.test(response.headers.get("content-type") ?? "")
        ) {
          const html = await response.text();
          const form = autoSubmitForm(html, current);
          if (form === null)
            return {
              response: new Response(html, response),
              url: current.href,
              hops,
            };
          if (options.stopAt?.(form.action))
            return { response, url: form.action.href, hops };
          current = rewrite(form.action);
          init = {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: form.body,
          };
          continue;
        }
        if (response.status < 300 || response.status > 399 || location === null)
          return { response, url: current.href, hops };
        await response.body?.cancel();
        const next = new URL(location, current);
        if (options.stopAt?.(next)) return { response, url: next.href, hops };
        current = rewrite(next);
        if (response.status !== 307 && response.status !== 308) init = {};
      }
      throw new Error(`More than 20 redirects starting at ${url}.`);
    },
    async submit(page, fields = {}, options = {}) {
      const form = firstForm(
        await page.response.clone().text(),
        new URL(page.url),
      );
      if (form === null) throw new Error(`${page.url} has no POST form.`);
      for (const [name, value] of Object.entries(fields))
        form.body.set(name, value);
      return this.follow(form.action.href, {
        init: {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: form.body,
        },
        ...(options.stopAt ? { stopAt: options.stopAt } : {}),
      });
    },
    cookie(url, name) {
      const target = new URL(url);
      return header(target)
        .split("; ")
        .find((pair) => pair.startsWith(`${name}=`))
        ?.slice(name.length + 1);
    },
    setCookie(url, name, value) {
      store(new URL(url), `${name}=${value}; Path=/`);
    },
    clear(url) {
      jar.delete(new URL(url).hostname);
    },
  };
}
