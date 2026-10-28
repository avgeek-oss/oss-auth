# @avgeek-oss/auth-core

The server half of Avgeek OSS auth: sign-in through the organisation's OpenID provider, sessions, roles and the Postgres schema. See the [repository README](../../README.md) for the design and [ARCHITECTURE.md](../../ARCHITECTURE.md) for the contract apps implement.

| Import                           | What it holds                                                                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `@avgeek-oss/auth-core`          | `loadAuthConfig`, `deriveKey` and `createKeyring`, tokens, the API key format, roles and `resolveRole`, `Actor`, errors with stable codes. |
| `@avgeek-oss/auth-core/postgres` | The `Sql` interface, `fromPg(pool)` and `fromPostgresJs(sql)`, `migrate(sql, { schema })`.                                                 |
| `@avgeek-oss/auth-core/oidc`     | The relying party (`createOidcClient`), sealed sign-in transactions, `safeReturnTo`, `signInUser`, `verifyLogoutToken`.                    |
| `@avgeek-oss/auth-core/api-keys` | `createApiKeys`: personal API keys with a role ceiling. Issue, list, rotate, revoke, verify.                                               |
| `@avgeek-oss/auth-core/mcp`      | `createMcpAuth`: the OAuth 2.1 authorization server for MCP clients and `requireMcpToken` for its resources.                               |
| `@avgeek-oss/auth-core/sessions` | `createSessions`: create, look up, revoke, list, step-up and back-channel revocation.                                                      |
| `@avgeek-oss/auth-core/scim`     | `createScim`: the SCIM 2.0 server for Users and Groups, as a Hono sub-app.                                                                 |
| `@avgeek-oss/auth-core/hono`     | `createAuth`: the `/auth` routes and middleware for a Hono API.                                                                            |
| `@avgeek-oss/auth-core/testing`  | `startMockProvider` and `createBrowser`, for flow tests and local development.                                                             |

Runtime dependencies: `zod`, `openid-client` and `jose` (which `openid-client` already uses). Optional peers: `hono` for `/hono`, `pg` or `postgres` for the adapter you use, and `oidc-provider` for `/testing`.

## Add sign-in to a Hono API

```ts
import { Hono } from "hono";
import pg from "pg";
import { loadAuthConfig } from "@avgeek-oss/auth-core";
import { createAuth } from "@avgeek-oss/auth-core/hono";
import { fromPg, migrate } from "@avgeek-oss/auth-core/postgres";

const config = loadAuthConfig("posted", process.env);
const sql = fromPg(new pg.Pool({ connectionString: process.env.DATABASE_URL }));
await migrate(sql, { schema: config.schema });

const auth = createAuth({ config, sql });
const { actor, trustedOrigin, requireRole, requireRecentAuth } =
  auth.middleware;

const app = new Hono();
app.route("/auth", auth.routes);
app.use("/api/*", actor, trustedOrigin);
app.post("/api/members", requireRole("admin"), addMember);
app.delete(
  "/api/workspace",
  requireRole("admin"),
  requireRecentAuth(300),
  deleteWorkspace,
);
```

The routes, under `/auth` on the API origin:

| Route                       | What it does                                                                                                     |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `GET /sign-in?returnTo=`    | Redirects to the provider. `returnTo` must be a path on the web origin.                                          |
| `GET /callback`             | Finishes sign-in or step-up and redirects to `returnTo`; on failure, to the web origin with `auth_error=<code>`. |
| `POST /sign-out`            | Ends the session and returns `{ endSessionUrl }`, the provider's logout URL or `null`.                           |
| `GET /session`              | The current user, role and session, or 401.                                                                      |
| `GET /step-up?returnTo=`    | Re-authenticates at the provider with `prompt=login`.                                                            |
| `POST /backchannel-logout`  | Receives the provider's logout tokens.                                                                           |
| `GET /api-keys?user=`       | The caller's usable keys; an admin may name another user.                                                        |
| `POST /api-keys`            | Creates a key from `{ name, ceiling, workspace?, expiresInSeconds? }` and returns it once.                       |
| `POST /api-keys/:id/rotate` | Replaces one of the caller's keys; `{ graceSeconds }` keeps the old one working that long.                       |
| `DELETE /api-keys/:id`      | Revokes one of the caller's keys, or anyone's for an admin.                                                      |

Errors are JSON: `{ "error": { "code": "step_up_required", "message": "…", "stepUpUrl": "…" } }`. The browser sends `X-Requested-With` on every state-changing request; `trustedOrigin` refuses it otherwise, and refuses any `Origin` but the web origin.

## Configuration

Every variable is prefixed with the app id in capitals, such as `POSTED_`.

| Variable                            | Default                | Meaning                                                                                             |
| ----------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------- |
| `<APP>_SECRET`                      | required               | At least 32 bytes; every key is derived from it. `openssl rand -base64 48`.                         |
| `<APP>_OIDC_ISSUER`                 | required               | The provider's issuer, exactly as its discovery document states it.                                 |
| `<APP>_OIDC_CLIENT_ID`              | required               | The client registered for this app.                                                                 |
| `<APP>_OIDC_CLIENT_SECRET`          | required               | Its secret. The client authenticates with HTTP Basic.                                               |
| `<APP>_OIDC_SCOPES`                 | `openid email profile` | Scopes to request. authentik needs `entitlements` for its `roles` claim.                            |
| `<APP>_OIDC_ROLE_CLAIMS`            | `roles`                | Claims holding roles or groups, comma-separated.                                                    |
| `<APP>_OIDC_ROLE_MAP`               | each role to itself    | JSON from claim value to `viewer`, `member` or `admin`. The highest match wins.                     |
| `<APP>_ROLE_SOURCE`                 | `claims`               | `claims`: roles from the role claim at sign-in. `scim`: roles from SCIM group membership.           |
| `<APP>_SCIM_TOKENS`                 | unset                  | SCIM bearer tokens, comma-separated so they can rotate. Required by `createScim`.                   |
| `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT` | `false`                | Link a SCIM-provisioned user to their first sign-in when `externalId` equals the OIDC `sub`.        |
| `<APP>_WEB_ORIGIN`                  | required               | Where the pages live. `returnTo` and `Origin` are checked against it.                               |
| `<APP>_API_ORIGIN`                  | required               | Where the API lives. The callback is `<APP>_API_ORIGIN/auth/callback`.                              |
| `<APP>_API_KEY_PREFIX`              | the app id             | The first part of every API key, 2 to 16 lowercase letters or digits. API keys are off without one. |
| `<APP>_API_KEY_MAX_TTL_DAYS`        | `365`                  | The longest a key may live, and the default lifetime (1 to 3650).                                   |
| `<APP>_API_KEY_ALLOW_NO_EXPIRY`     | `false`                | Allow keys that never expire.                                                                       |
| `<APP>_OAUTH_CLIENTS`               | `[]`                   | Pre-registered OAuth clients, as a JSON array (see below).                                          |
| `<APP>_OAUTH_LEGACY_DCR`            | `false`                | Accept RFC 7591 dynamic client registration, which MCP has deprecated.                              |
| `<APP>_SESSION_MAX_AGE`             | `12h`                  | Absolute session lifetime.                                                                          |
| `<APP>_SESSION_IDLE_TIMEOUT`        | `2h`                   | Inactivity limit.                                                                                   |
| `<APP>_AUTH_SCHEMA`                 | `auth`                 | The Postgres schema for the auth tables.                                                            |

## API keys

People create personal API keys from a signed-in session, for scripts and CI. A key looks like `posted_<id>_<secret>_<checksum>`; it is shown once, and only its HMAC under the `api-key` key is stored.

```sh
curl -H "Authorization: Bearer $POSTED_API_KEY" https://api.posted.example.com/api/boards
```

- **Authentication.** `actor` accepts `Authorization: Bearer <key>` and nothing else: never a query parameter or a cookie. A request with a bearer header is authenticated by the key alone, and its session cookie is ignored. The actor's credential is `{ kind: "api_key", id, ceiling, workspace }`.
- **Roles.** A key acts with the lower of its ceiling and its owner's current role, so `requireRole` treats keys and sessions alike. A key cannot be created with a ceiling above the owner's role. When the owner's role is lowered, by SCIM, a sign-in claim or the app, a database trigger revokes their keys above the new role in the same transaction. Raising the role again does not restore them. Deactivating or deleting the owner revokes all of their keys for good.
- **No role is a suspension.** While the owner's role is NULL, their keys and sessions are refused but not revoked, and they work again when a role returns, still capped by it. Providers often move someone between groups as two requests, and removing before adding passes through NULL. Admin, then NULL, then member revokes the admin keys, just as admin to member does: no live key is ever above the last role the owner had.
- **Step-up and CSRF.** `requireRecentAuth` answers 403 `step_up_unavailable` for a key: sensitive actions need a session. `trustedOrigin` skips requests with a bearer header, since a cross-site page cannot send one and cookies are ignored for them.
- **Managing keys** needs a session; a key cannot list, create, rotate or revoke keys. Creating or rotating an `admin` key needs a sign-in within the last 10 minutes, so the routes answer `step_up_required` as `requireRecentAuth(600)` does.
- **Lifetime.** Keys expire after `<APP>_API_KEY_MAX_TTL_DAYS` unless created with less; `expiresInSeconds: null` needs `<APP>_API_KEY_ALLOW_NO_EXPIRY=true`. Rotation issues a new key with the same name, ceiling, workspace and lifetime, and the old key keeps working for `graceSeconds` (up to seven days). Of two concurrent rotations of one key, one wins and the other answers 409 `conflict`. `last_used_at` is recorded at most once a minute.
- **Workspaces.** A key may carry an app-defined `workspace`. auth-core stores and returns it but never interprets it: the app must check `actor.credential.workspace` on every request. Creating a key for a workspace calls `hooks.authorizeWorkspace(actor, workspace)` on `createAuth`; without that hook, keys cannot have a workspace.

```ts
const auth = createAuth({
  config,
  sql,
  hooks: {
    authorizeWorkspace: (actor, workspace) =>
      isMember(actor.user.id, workspace),
  },
});
```

`createApiKeys({ config, sql })` from `@avgeek-oss/auth-core/api-keys` offers the same operations without Hono, and `auth.apiKeys` is the instance `createAuth` uses.

## MCP authorization server

Each app is its own OAuth 2.1 authorization server for MCP clients, following the MCP authorization specification (2026-07-28). People still sign in through the organisation's provider; the app then asks them to approve the client on its consent page and issues its own short-lived, audience-bound tokens. The scopes are the role names, and a grant acts with the lower of the role it was approved with and the person's current role, exactly like an API key.

```ts
import { createMcpAuth } from "@avgeek-oss/auth-core/mcp";

const mcp = createMcpAuth({
  config,
  sql,
  auth, // from createAuth
  resources: [
    { path: "/mcp", name: "Posted MCP" },
    { path: "/v1", name: "Posted API" },
  ],
  hooks: {
    // Optional: let people limit a grant to some boards on the consent page.
    validateRestrictions: (actor, restrictions) =>
      checkBoards(actor, restrictions),
  },
});
app.route("/", mcp.routes);
app.post("/mcp", mcp.requireMcpToken({ resource: "/mcp" }), handleMcp);
app.get("/v1/boards", mcp.requireMcpToken({ resource: "/v1" }), listBoards);
```

- **Issuer and metadata.** The issuer is `<APP>_API_ORIGIN`. It serves `/.well-known/oauth-authorization-server` (RFC 8414), with S256 only, `authorization_response_iss_parameter_supported`, `client_id_metadata_document_supported` and the role names as `scopes_supported`. Each resource has its protected resource metadata (RFC 9728) at `/.well-known/oauth-protected-resource<path>`, and its identifier is the API origin plus the path.
- **Authorization.** `/oauth/authorize` takes the code flow with PKCE (S256), a `resource` that must be one of the configured ones (RFC 8707), `state`, and an optional `scope` naming roles. It returns `iss` (RFC 9207) on every redirect, errors included. Redirect URIs must be `https` or loopback `http` and match exactly, except for the port of a loopback IP literal (RFC 8252). Without a session it sends the person to `/auth/sign-in`; with one, to the web origin's `/oauth/consent?request=<id>`.
- **Consent.** The consent page calls `GET /oauth/consent/:id` with the session for the client's name, logo, redirect host (always show it) and whether it is on this computer, the resource, and the ceilings the person may choose, then `POST /oauth/consent/:id` with `{ decision: "approve" | "deny", ceiling, restrictions? }`, and navigates to the returned `redirectUri`. The ceiling cannot exceed the person's role, an `admin` ceiling needs a sign-in within 10 minutes, and restrictions need `hooks.validateRestrictions`. The request is bound to the first person who opens it, decided once, and expires after 10 minutes.
- **Tokens.** `/oauth/token` redeems a code (single use, 60 seconds) after checking the client, the redirect URI and the PKCE verifier; only a replay that passes all of them revokes the grant. Access tokens last 15 minutes. Refresh tokens rotate on every use, expire after 30 idle days and 90 days in all, and a reused one revokes its whole family and the grant. Tokens are bound to one resource, and the `resource` parameter must match. `/oauth/revoke` (RFC 7009) ends a token's family.
- **Clients.** A client is pre-registered in `<APP>_OAUTH_CLIENTS` (public, or confidential with a `client_secret` and HTTP Basic), or identified by the `https` URL of its client metadata document. Documents are fetched defensively: public addresses only after DNS, the connection pinned to the checked address, no redirects, `application/json`, at most 5 KB, 3 seconds in all; they are cached for their `max-age`, at most a day. Legacy dynamic registration is off unless `<APP>_OAUTH_LEGACY_DCR=true`.

  ```sh
  POSTED_OAUTH_CLIENTS='[{"client_id":"posted-cli","client_name":"Posted CLI","redirect_uris":["http://127.0.0.1/callback"]}]'
  ```

- **Resource server.** `requireMcpToken({ resource, role? })` answers 401 with `WWW-Authenticate: Bearer resource_metadata="…", scope="<role>"` without a valid token for that resource, and 403 `insufficient_scope` below `role`. It sets an actor whose credential is `{ kind: "oauth", id, ceiling, restrictions }`, so `requireRole` works as for sessions and keys. The app must enforce `restrictions` itself.
- **Grants follow their owner** as API keys do: a NULL role suspends them, a lower role revokes those above it, and deactivation or deletion revokes them all.
- **Connected apps.** `GET /auth/connected-apps` lists the person's grants with the client's name and logo, ceiling, resources, creation and last use; `DELETE /auth/connected-apps/:id` revokes one. Admins may pass `?user=` and revoke anyone's.
- **Housekeeping.** `mcp.purgeExpired()` deletes consent requests, codes and tokens that expired more than a day ago; run it from the app's scheduler.

With authentik, nothing changes at the provider: people sign in to the app as before, and the app, not authentik, is the authorization server for its MCP clients.

## SCIM

```ts
import { createScim } from "@avgeek-oss/auth-core/scim";

app.route(
  "/scim/v2",
  createScim({
    config,
    sql,
    sessions: auth.sessions,
    hooks: {
      onDeactivate: (userId, tx) => revokeApiKeys(tx, userId),
      onRoleChange: (userId, from, to, tx) => capCredentials(tx, userId, to),
    },
  }),
);
```

- **Endpoints:** `/Users` and `/Groups` (GET, POST, PUT, PATCH, DELETE), `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas`, authenticated with a bearer token from `<APP>_SCIM_TOKENS`. Errors use the SCIM Error schema with fixed messages, such as `userName must be unique.`, and never the database's text; any other error is rethrown to the app's error handler, which should log it, and answers 500.
- **Filters:** `eq` on `userName` (ignoring case), `externalId`, `id` and `emails.value` or `emails[type eq "work"].value`, joined with `and`; groups on `displayName`, `externalId` and `id`. Other operators answer 400 `invalidFilter`. Lists page with `startIndex` and `count` (at most 200) and honour `attributes` and `excludedAttributes`.
- **PATCH** accepts `add`, `replace` and `remove` in any case, with paths such as `active`, `name.givenName` and `emails[type eq "work"].value`, or path-less value objects. `"True"` and `"False"` count as booleans. Unknown attributes and the enterprise extension are ignored.
- **Lifecycle:** `active: false` deactivates and revokes sessions. `DELETE` tombstones the user, removes them from every group and revokes everything; both call `hooks.onDeactivate` in the same transaction. A tombstoned user is gone from SCIM and sign-in refuses them, until the provider provisions the same `externalId` again, as authentik does when someone is assigned back to the application: a `POST` (or a `PUT` to the old id) revives the same user, with the same id and no role until group membership, or in claims mode the next sign-in, gives one. Sessions ended by the deletion stay ended. Nothing else revives a deleted user.
- **Groups:** display names are unique ignoring case. A PUT without `members` keeps the members, so a rename never empties a group.

### Where roles come from

- **`<APP>_ROLE_SOURCE=claims`** (default). The role claim sets the role at each sign-in, and a claim that maps to nothing takes it away. SCIM manages users and stores groups but does not change roles.
- **`<APP>_ROLE_SOURCE=scim`** (recommended with authentik). A user's role is the highest role their groups' display names map to through `<APP>_OIDC_ROLE_MAP` (ignoring case), recomputed on every membership change in the same transaction, and `hooks.onRoleChange` runs on every change. With no mapped group the user has no access: their sessions and API keys are refused, without being revoked, until a mapped group returns, and sign-in refuses them as `unassigned`. Sign-in never creates users or changes roles in this mode, but still refuses a role claim that maps to nothing. **Switching an existing deployment from `claims` to `scim` signs everyone out** until SCIM assigns them a role, because sessions are only accepted for users whose role SCIM set.

With `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT=true`, the first sign-in of a SCIM-provisioned user (no `sub` yet) links to them by issuer and `externalId = sub`. People are never linked by email.

## authentik setup

For Posted, with authentik at `https://auth.example.com` and the API at `https://api.posted.example.com`:

- Groups `posted-viewers`, `posted-members`, `posted-admins`, bound to the `Posted` application (policy engine mode `Any`), and application entitlements `viewer`, `member` and `admin` bound to them.
- An OAuth2/OpenID provider: confidential client, redirect URI `https://api.posted.example.com/auth/callback` (strict), **Include claims in id_token** on, scopes `openid email profile entitlements`, an authenticator validation stage on every login so `amr` carries `mfa`, and an access-token validity at least as long as the authentik session so back-channel logout still fires. Logout URI `https://api.posted.example.com/auth/backchannel-logout`, method back-channel.

```sh
POSTED_OIDC_ISSUER=https://auth.example.com/application/o/posted/
POSTED_OIDC_CLIENT_ID=posted
POSTED_OIDC_CLIENT_SECRET=...
POSTED_OIDC_SCOPES="openid email profile entitlements"
POSTED_OIDC_ROLE_CLAIMS=roles
```

Roles come only from the provider, so put the first administrator in `posted-admins`. Anyone the provider makes `admin` can configure the app; first-run setup is gated on `requireRole("admin")` in the app.

For SCIM, add a SCIM provider `posted-scim` and attach it as a **backchannel provider** of the `Posted` application, or its user scope is not applied:

- URL `https://api.posted.example.com/scim/v2`, authentication mode **Static token**, set to one of `POSTED_SCIM_TOKENS`;
- group filters `posted-viewers`, `posted-members` and `posted-admins`, and **Exclude service accounts** on;
- the full-sync schedule changed from every four hours to `*/10 * * * *`, because assigning or unassigning a user from the application only syncs then.

```sh
POSTED_SCIM_TOKENS=$(openssl rand -base64 48)
POSTED_ROLE_SOURCE=scim
POSTED_OIDC_ROLE_MAP='{"posted-viewers":"viewer","posted-members":"member","posted-admins":"admin"}'
POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT=true
```

authentik sends user changes as `PUT` and never `PATCH`, membership as group `PATCH` `add` and `remove`, and removes users who leave the application's scope with `DELETE`; assigning them back POSTs them again, which revives the same user. Its `externalId` is the hashed user id, the same value as the OIDC `sub` in the default subject mode, which is what makes linking safe.

authentik sends no `iss` parameter in the authorization response and does not advertise it, so the callback validates the ID token's `iss` instead. It ignores `max_age=0`, so step-up always sends `prompt=login` and a positive `max_age`.

## Migrations

`migrate()` applies the SQL files in [`migrations/`](migrations) to the auth schema (default `auth`), creating it if needed. Run it from the app's existing migrate step: at boot, or as a separate job. It is safe to run from several instances at once.

Never edit a migration that has shipped. The runner refuses to run when an applied file changed, and when the database has a migration this version does not include.

## Testing

`startMockProvider` runs an OpenID provider in-process on a random port. It signs in whoever `setLogin` names, with the `amr` and `auth_time` you choose, honours `prompt=login` and `max_age`, and signs and sends back-channel logout tokens. `authentikLike: true` drops the `iss` parameter as authentik does. `createBrowser` follows the redirects with a cookie jar, so tests drive the whole flow without a browser.
