# @avgeek-oss/auth-client

The browser side of [`@avgeek-oss/auth-core`](../auth-core): a small client for an app's auth API, and React hooks on top of it. It covers sign-in and step-up URLs, the session, sign-out, API keys, connected MCP apps and the MCP consent screen. It has no runtime dependencies and imports nothing from Node or from `auth-core`, so none of the server code reaches a browser bundle. React is an optional peer, for `@avgeek-oss/auth-client/react` only.

It draws nothing. The screens live in the design system (`@avgeek-oss/design-system` `patterns/auth`), which takes an `AuthClient` from this package.

```sh
pnpm add @avgeek-oss/auth-client
```

| Entry point                     | Size (min+gzip) | Contents                                                                    |
| ------------------------------- | --------------- | --------------------------------------------------------------------------- |
| `@avgeek-oss/auth-client`       | under 5 KB      | `createAuthClient`, `AuthClientError`, the wire types, the URL helpers.     |
| `@avgeek-oss/auth-client/react` | under 3 KB      | `AuthProvider`, `useSession`, `useRequireRole`, `useStepUp` and data hooks. |

`pnpm verify` fails if either entry point grows past its budget.

## Use it

```ts
import { createAuthClient } from "@avgeek-oss/auth-client";

export const auth = createAuthClient({
  apiOrigin: "https://api.posted.example.com", // or "" behind a same-origin proxy
});

const session = await auth.getSession(); // null when signed out
if (!session) location.assign(auth.signInUrl("/boards"));
```

Every request sends cookies (`credentials: "include"`) and, except GETs, the CSRF header auth-core checks (`x-requested-with` by default). The session cookie is `SameSite=Lax`, so the page and the API must be the same site. When they are different hosts, such as `posted.example.com` and `api.posted.example.com`, use auth-core's `auth.middleware.cors`: the auth and consent routes already have it, and the app adds it in front of its own browser routes (`app.use("/api/*", auth.middleware.cors, …)`). The alternative is a proxy that serves the API under the page's origin, as the reference app does, which needs no CORS.

### React with Vite

```tsx
import { createRoot } from "react-dom/client";
import { AuthProvider, useSession } from "@avgeek-oss/auth-client/react";
import { auth } from "./auth";

function Header() {
  const { status, actor } = useSession();
  if (status === "loading") return null;
  if (!actor) return <a href={auth.signInUrl(location.pathname)}>Sign in</a>;
  return <span>{actor.user.displayName}</span>;
}

createRoot(document.getElementById("root")!).render(
  <AuthProvider client={auth}>
    <Header />
  </AuthProvider>,
);
```

### Next.js

The hooks are client-only and there is no server-side rendering of the session: put the provider in a client component, and gate pages on the client.

```tsx
"use client";
import { AuthProvider } from "@avgeek-oss/auth-client/react";
import { auth } from "@/lib/auth";

export function Providers({ children }: { children: React.ReactNode }) {
  return <AuthProvider client={auth}>{children}</AuthProvider>;
}
```

During a server render, `useSession()` reports `loading`, and nothing touches `window` until the component mounts. For a server-checked page, ask your API from the server with the request's cookie instead.

## The client

`createAuthClient({ apiOrigin, basePath = "/auth", oauthBasePath = "/oauth", csrfHeader = "x-requested-with", fetch? })`

| Member                                            | Request                                    | Resolves to                                                               |
| ------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------- |
| `getSession()`                                    | `GET /auth/session`                        | `AuthSession` (`user`, `role`, `ext`, `session`), or `null` if signed out |
| `signInUrl(returnTo?)`                            | none                                       | `/auth/sign-in?returnTo=…`                                                |
| `stepUpUrl(returnTo?)`                            | none                                       | `/auth/step-up?returnTo=…`                                                |
| `signOut()`                                       | `POST /auth/sign-out`                      | the identity provider's logout URL to visit next, or `null`               |
| `sessions.list()`                                 | `GET /auth/sessions`                       | `ActiveSession[]`, newest first, the page's own with `current: true`      |
| `sessions.revoke(id)`                             | `DELETE /auth/sessions/:id`                | `{ current, endSessionUrl }`; `current` means this page is signed out     |
| `sessions.signOutEverywhere()`                    | `POST /auth/sessions/sign-out-everywhere`  | `{ revoked, endSessionUrl }`; this page is signed out too                 |
| `apiKeys.list()`                                  | `GET /auth/api-keys`                       | `ApiKey[]`                                                                |
| `apiKeys.create({ name, ceiling, … })`            | `POST /auth/api-keys`                      | `{ key, apiKey }`: `key` is the secret, shown this once                   |
| `apiKeys.rotate(id, { graceSeconds })`            | `POST /auth/api-keys/:id/rotate`           | `{ key, apiKey }`; the old key works for `graceSeconds`                   |
| `apiKeys.revoke(id)`                              | `DELETE /auth/api-keys/:id`                | nothing                                                                   |
| `connectedApps.list()`                            | `GET /auth/connected-apps`                 | `ConnectedApp[]`                                                          |
| `connectedApps.revoke(id)`                        | `DELETE /auth/connected-apps/:id`          | nothing                                                                   |
| `consent.get(id)`                                 | `GET /oauth/consent/:id`                   | `ConsentRequest`                                                          |
| `consent.decide(id, { approve, ceiling })`        | `POST /oauth/consent/:id`                  | `{ redirectUri }`: navigate there next                                    |
| `admin.apiKeys.list(userId)`, `.revoke(id)`       | `GET /auth/api-keys?user=`, `DELETE`       | another person's keys (admins only)                                       |
| `admin.connectedApps.list(userId)`, `.revoke(id)` | `GET /auth/connected-apps?user=`, `DELETE` | another person's connected apps (admins only)                             |
| `admin.users.list({ cursor, q, status, limit })`  | `GET /auth/admin/users`                    | `{ users, nextCursor }`: one page of the directory (admins only)          |

After `sessions.revoke` of the page's own session (`current: true`) or `sessions.signOutEverywhere()`, the page is signed out exactly as after `signOut()`: navigate to `endSessionUrl` when it is set, or refresh the session. `ActiveSession` has `id` (a public id, never the token), `createdAt`, `lastSeenAt`, `idleExpiresAt`, `expiresAt`, `authenticatedAt`, `browser` and `os` (such as `Firefox` and `macOS`, or `null`) and `current`; the app composes them into words, so they translate.

`admin.users.list` pages the directory newest first: pass the last page's `nextCursor` as `cursor` until it is `null`. `q` matches part of a name or email, ignoring case; `status` is `active`, `suspended` (no role), `deactivated` or `deleted`; `limit` is 1 to 100, default 50. Each `DirectoryUser` has `id`, `displayName`, `email`, `role` (`null` when suspended), `roleSource` (`claims`, `scim` or `app`), `status`, `createdAt`, `lastSignInAt`, `deactivatedAt` and `deletedAt`. The directory is read-only: roles and access are managed at the identity provider.

Methods that return a URL never navigate. `returnTo` is a path on the web origin, such as `/settings?tab=keys`; auth-core refuses anything else.

After a failed sign-in or step-up, the callback sends the browser to the app's error path with `?auth_error=<code>&auth_error_reason=<reason>`. `readAuthRedirectError(location.href)` reads them, and `withoutAuthRedirectError(location.href)` gives the URL without them, for `history.replaceState`.

The app's own routes behind auth-core's middleware answer in the same error format. `readAuthError(response)` turns a failed response into an `AuthClientError`, so `useStepUp` can handle a `requireRecentAuth` refusal from them too.

## Errors

Every failure rejects with `AuthClientError`:

- `code`: the stable code below;
- `status`: the HTTP status, or 0;
- `message`: safe to show;
- `details`: any other fields of the error;
- `stepUpUrl` and `retryAfterSeconds`, where they apply.

`isAuthClientError(error, code?)` also works across duplicate copies of the package. Codes a newer server sends pass through unchanged.

| Code                                                  | When                                                                                    |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `unauthenticated`                                     | Nobody is signed in. `getSession()` resolves to `null` instead.                         |
| `forbidden`                                           | Signed in, but the role is too low, or a key or connection would exceed it.             |
| `step_up_required`                                    | The action needs a recent sign-in at the provider. `stepUpUrl` is set; see `useStepUp`. |
| `step_up_unavailable`                                 | The action needs a session, not an API key.                                             |
| `rate_limited`                                        | Too many requests. `retryAfterSeconds` says when to try again.                          |
| `unavailable`                                         | The service is temporarily unavailable, such as its rate limiter's database.            |
| `origin_invalid`, `csrf_header_missing`               | The request did not come from the app's own pages, or lacked the CSRF header.           |
| `invalid_request`, `not_found`, `conflict`            | The request was malformed, named something that does not exist, or clashed.             |
| `sign_in_denied`, `step_up_failed`                    | On the page's URL after a callback (`readAuthRedirectError`), with a `reason`.          |
| `return_to_invalid`, `oidc_*`, `logout_token_invalid` | Sign-in and logout plumbing; seen in redirects and logs rather than by the client.      |
| `network_error`, `invalid_response` (client)          | The request did not reach the API, or the answer was not the API's JSON (status kept).  |

`sign_in_denied` comes with a `reason`: `no_role`, `unassigned`, `user_inactive` or `user_deleted`. `step_up_failed` comes with `session`, `user`, `stale` or `mfa_missing`.

## React

`@avgeek-oss/auth-client/react` needs React 19.

- **`<AuthProvider client navigate?>`** loads the session on mount, and again when the window regains focus or the page becomes visible. `navigate` defaults to `location.assign`; pass a router's.
- **`useSession()`** returns `{ status: "loading" | "signed-in" | "signed-out", actor, error, refresh }`. A failed refresh keeps the last status and sets `error`.
- **`useRequireRole(minimum)`** returns `{ status: "loading" | "signed-out" | "forbidden" | "allowed", actor }`. It renders and redirects nothing.
- **`useStepUp()`** returns `{ run, resumed, clear, error }`. `run(action, { resume })` runs `action`. On `step_up_required`, it navigates to `stepUpUrl` with the current page as `returnTo`, and resolves to `undefined`. When the person comes back to the same page, `resumed` is the `resume` value once, so the page can run the action again:

  ```tsx
  const stepUp = useStepUp();
  const remove = () =>
    stepUp.run(() => deleteBoard(id), { resume: `delete:${id}` });
  useEffect(() => {
    if (stepUp.resumed === `delete:${id}`) {
      stepUp.clear();
      void remove();
    }
  }, [stepUp.resumed]);
  ```

  Other failures are set as `error`, and `run` rejects with them.

- **`useApiKeys()`, `useConnectedApps()` and `useConsent(id)`** return `{ data, error, loading, refetch, mutate }`. `mutate((client) => …)` runs a change, reloads, and resolves to the change's result, such as a new key's secret. Its failures set `error` and reject, so it composes with `stepUp.run`.
- **`useAuthClient()`** returns the client given to the provider.

There is no styling and there are no components beyond the provider.
