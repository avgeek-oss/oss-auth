import { AuthClientError } from "./errors.js";
import type {
  AdminApi,
  ApiKey,
  ApiKeysApi,
  AuthSession,
  ConnectedApp,
  ConnectedAppsApi,
  ConsentApi,
  ConsentDecision,
  ConsentRequest,
  IssuedApiKey,
  SignOutResult,
} from "./types.js";
import { addReturnTo } from "./urls.js";

/** The request options the client passes to {@link FetchLike}. */
export interface AuthRequestInit {
  readonly method: "GET" | "POST" | "DELETE";
  readonly headers: Record<string, string>;
  readonly credentials: "include";
  readonly body?: string;
}

/** The subset of `fetch` the client calls. The global `fetch` is one. */
export type FetchLike = (
  input: string,
  init: AuthRequestInit,
) => Promise<Response>;

/** Options for {@link createAuthClient}. */
export interface AuthClientOptions {
  /**
   * The API's origin, such as `https://api.posted.example.com`, or `""`
   * when the page and the API share an origin (for example through a
   * proxy).
   */
  readonly apiOrigin: string;
  /** Where the app mounts auth-core's routes. Default `/auth`. */
  readonly basePath?: string;
  /** Where the OAuth routes, and so the consent API, live. Default `/oauth`. */
  readonly oauthBasePath?: string;
  /**
   * The header auth-core requires on state-changing requests (its
   * `csrfHeader` option). Default `x-requested-with`.
   */
  readonly csrfHeader?: string;
  /** A `fetch` to use instead of the global one, for tests. */
  readonly fetch?: FetchLike;
}

/**
 * The auth API from the browser. Every request sends cookies
 * (`credentials: "include"`) and, unless it is a GET, the CSRF header.
 * Failures reject with {@link AuthClientError}. Methods that return a URL
 * never navigate: the app decides when to.
 *
 * @typeParam Ext - The app's own actor fields.
 */
export interface AuthClient<Ext extends object = Record<string, unknown>> {
  /** The options the client was created with, defaults filled in. */
  readonly options: Readonly<Required<Omit<AuthClientOptions, "fetch">>>;
  /** The signed-in caller, or `null` when nobody is signed in. */
  readonly getSession: () => Promise<AuthSession<Ext> | null>;
  /** The URL that starts sign-in, coming back to `returnTo` (a path on the web origin). */
  readonly signInUrl: (returnTo?: string | null) => string;
  /** The URL that re-confirms the person at the provider, then returns to `returnTo`. */
  readonly stepUpUrl: (returnTo?: string | null) => string;
  /**
   * Ends the session. Resolves to the identity provider's logout URL, to
   * navigate to next, or `null`.
   */
  readonly signOut: () => Promise<string | null>;
  readonly apiKeys: ApiKeysApi;
  readonly connectedApps: ConnectedAppsApi;
  readonly consent: ConsentApi;
  /** For admins: other people's keys and connected apps. */
  readonly admin: AdminApi;
}

/** `Retry-After` as whole seconds, or `null`. */
function retryAfter(response: Response): number | null {
  const value = response.headers.get("retry-after");
  if (value === null || !/^\d+$/.test(value.trim())) return null;
  return Number(value.trim());
}

/**
 * The {@link AuthClientError} for a failed response, read the way the
 * client reads its own. For the app's own routes behind auth-core's
 * middleware, such as one guarded by `requireRecentAuth`, so their
 * `step_up_required` works with `useStepUp`:
 *
 * ```ts
 * const response = await fetch("/api/export", { method: "POST", … });
 * if (!response.ok) throw await readAuthError(response);
 * ```
 */
export async function readAuthError(
  response: Response,
): Promise<AuthClientError> {
  const status = response.status;
  const retryAfterSeconds = retryAfter(response);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  const error = (body as { error?: unknown } | undefined)?.error;
  if (
    typeof error === "object" &&
    error !== null &&
    typeof (error as { code?: unknown }).code === "string"
  ) {
    const { code, message, ...details } = error as {
      code: string;
      message?: unknown;
    };
    return new AuthClientError({
      code,
      status,
      message: typeof message === "string" ? message : code,
      details,
      retryAfterSeconds,
    });
  }
  // Not auth-core's JSON: a proxy's page, or a plain-text refusal.
  const code =
    status === 429
      ? "rate_limited"
      : status === 503
        ? "unavailable"
        : "invalid_response";
  return new AuthClientError({
    code,
    status,
    message:
      code === "invalid_response"
        ? `The auth API answered ${status} without its usual error.`
        : "The service is busy. Try again shortly.",
    retryAfterSeconds,
  });
}

/** Creates a client for one app's auth API. */
export function createAuthClient<Ext extends object = Record<string, unknown>>(
  options: AuthClientOptions,
): AuthClient<Ext> {
  const trim = (value: string) => {
    let end = value.length;
    while (end > 0 && value[end - 1] === "/") end--;
    return value.slice(0, end);
  };
  const settings = {
    apiOrigin: trim(options.apiOrigin),
    basePath: trim(options.basePath ?? "/auth"),
    oauthBasePath: trim(options.oauthBasePath ?? "/oauth"),
    csrfHeader: options.csrfHeader ?? "x-requested-with",
  };
  const send: FetchLike =
    options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const auth = `${settings.apiOrigin}${settings.basePath}`;
  const oauth = `${settings.apiOrigin}${settings.oauthBasePath}`;
  const id = encodeURIComponent;

  async function request<T>(
    method: "GET" | "POST" | "DELETE",
    url: string,
    body?: unknown,
  ): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (method !== "GET") headers[settings.csrfHeader] = "fetch";
    if (body !== undefined) headers["content-type"] = "application/json";
    let response: Response;
    try {
      response = await send(url, {
        method,
        headers,
        credentials: "include",
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch (cause) {
      throw new AuthClientError({
        code: "network_error",
        status: 0,
        message: "Could not reach the server. Check your connection.",
        cause,
      });
    }
    if (!response.ok) throw await readAuthError(response);
    if (response.status === 204) return undefined as T;
    try {
      return (await response.json()) as T;
    } catch (cause) {
      throw new AuthClientError({
        code: "invalid_response",
        status: response.status,
        message: `The auth API answered ${response.status} without JSON.`,
        cause,
      });
    }
  }

  const keys = async (query: string) =>
    (await request<{ apiKeys: ApiKey[] }>("GET", `${auth}/api-keys${query}`))
      .apiKeys;
  const apps = async (query: string) =>
    (
      await request<{ connectedApps: ConnectedApp[] }>(
        "GET",
        `${auth}/connected-apps${query}`,
      )
    ).connectedApps;
  const revokeKey = (key: string) =>
    request<void>("DELETE", `${auth}/api-keys/${id(key)}`);
  const revokeApp = (app: string) =>
    request<void>("DELETE", `${auth}/connected-apps/${id(app)}`);

  return {
    options: settings,

    async getSession() {
      try {
        return await request<AuthSession<Ext>>("GET", `${auth}/session`);
      } catch (error) {
        if (
          error instanceof AuthClientError &&
          error.code === "unauthenticated"
        )
          return null;
        throw error;
      }
    },

    signInUrl: (returnTo) => addReturnTo(`${auth}/sign-in`, returnTo),
    stepUpUrl: (returnTo) => addReturnTo(`${auth}/step-up`, returnTo),

    async signOut() {
      return (await request<SignOutResult>("POST", `${auth}/sign-out`))
        .endSessionUrl;
    },

    apiKeys: {
      list: () => keys(""),
      create: (input) =>
        request<IssuedApiKey>("POST", `${auth}/api-keys`, input),
      rotate: (key, rotateOptions = {}) =>
        request<IssuedApiKey>("POST", `${auth}/api-keys/${id(key)}/rotate`, {
          graceSeconds: rotateOptions.graceSeconds ?? 0,
        }),
      revoke: revokeKey,
    },

    connectedApps: { list: () => apps(""), revoke: revokeApp },

    consent: {
      get: (requestId) =>
        request<ConsentRequest>("GET", `${oauth}/consent/${id(requestId)}`),
      decide: (requestId, input) =>
        request<ConsentDecision>("POST", `${oauth}/consent/${id(requestId)}`, {
          decision: input.approve ? "approve" : "deny",
          ...(input.ceiling === undefined ? {} : { ceiling: input.ceiling }),
          ...(input.restrictions === undefined
            ? {}
            : { restrictions: input.restrictions }),
        }),
    },

    admin: {
      apiKeys: {
        list: (userId) => keys(`?user=${id(userId)}`),
        revoke: revokeKey,
      },
      connectedApps: {
        list: (userId) => apps(`?user=${id(userId)}`),
        revoke: revokeApp,
      },
    },
  };
}
