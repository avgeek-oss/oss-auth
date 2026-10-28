# @avgeek-oss/auth-core

The server half of Avgeek OSS auth: sign-in through the organisation's OpenID provider, sessions, roles and the Postgres schema. See the [repository README](../../README.md) for the design and [ARCHITECTURE.md](../../ARCHITECTURE.md) for the contract apps implement.

| Import                           | What it holds                                                                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `@avgeek-oss/auth-core`          | `loadAuthConfig`, `deriveKey` and `createKeyring`, tokens, the API key format, roles and `resolveRole`, `Actor`, errors with stable codes. |
| `@avgeek-oss/auth-core/postgres` | The `Sql` interface, `fromPg(pool)` and `fromPostgresJs(sql)`, `migrate(sql, { schema })`.                                                 |
| `@avgeek-oss/auth-core/oidc`     | The relying party (`createOidcClient`), sealed sign-in transactions, `safeReturnTo`, `signInUser`, `verifyLogoutToken`.                    |
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

| Route                      | What it does                                                                                                     |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `GET /sign-in?returnTo=`   | Redirects to the provider. `returnTo` must be a path on the web origin.                                          |
| `GET /callback`            | Finishes sign-in or step-up and redirects to `returnTo`; on failure, to the web origin with `auth_error=<code>`. |
| `POST /sign-out`           | Ends the session and returns `{ endSessionUrl }`, the provider's logout URL or `null`.                           |
| `GET /session`             | The current user, role and session, or 401.                                                                      |
| `GET /step-up?returnTo=`   | Re-authenticates at the provider with `prompt=login`.                                                            |
| `POST /backchannel-logout` | Receives the provider's logout tokens.                                                                           |

Errors are JSON: `{ "error": { "code": "step_up_required", "message": "…", "stepUpUrl": "…" } }`. The browser sends `X-Requested-With` on every state-changing request; `trustedOrigin` refuses it otherwise, and refuses any `Origin` but the web origin.

## Configuration

Every variable is prefixed with the app id in capitals, such as `POSTED_`.

| Variable                            | Default                | Meaning                                                                                                |
| ----------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------ |
| `<APP>_SECRET`                      | required               | At least 32 bytes; every key is derived from it. `openssl rand -base64 48`.                            |
| `<APP>_OIDC_ISSUER`                 | required               | The provider's issuer, exactly as its discovery document states it.                                    |
| `<APP>_OIDC_CLIENT_ID`              | required               | The client registered for this app.                                                                    |
| `<APP>_OIDC_CLIENT_SECRET`          | required               | Its secret. The client authenticates with HTTP Basic.                                                  |
| `<APP>_OIDC_SCOPES`                 | `openid email profile` | Scopes to request. authentik needs `entitlements` for its `roles` claim.                               |
| `<APP>_OIDC_ROLE_CLAIMS`            | `roles`                | Claims holding roles or groups, comma-separated.                                                       |
| `<APP>_OIDC_ROLE_MAP`               | each role to itself    | JSON from claim value to `viewer`, `member` or `admin`. The highest match wins.                        |
| `<APP>_BOOTSTRAP_ADMIN`             | unset                  | A verified email or a `sub` made `admin` while no role claim or SCIM says otherwise. Claims mode only. |
| `<APP>_ROLE_SOURCE`                 | `claims`               | `claims`: roles from the role claim at sign-in. `scim`: roles from SCIM group membership.              |
| `<APP>_SCIM_TOKENS`                 | unset                  | SCIM bearer tokens, comma-separated so they can rotate. Required by `createScim`.                      |
| `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT` | `false`                | Link a SCIM-provisioned user to their first sign-in when `externalId` equals the OIDC `sub`.           |
| `<APP>_WEB_ORIGIN`                  | required               | Where the pages live. `returnTo` and `Origin` are checked against it.                                  |
| `<APP>_API_ORIGIN`                  | required               | Where the API lives. The callback is `<APP>_API_ORIGIN/auth/callback`.                                 |
| `<APP>_SESSION_MAX_AGE`             | `12h`                  | Absolute session lifetime.                                                                             |
| `<APP>_SESSION_IDLE_TIMEOUT`        | `2h`                   | Inactivity limit.                                                                                      |
| `<APP>_AUTH_SCHEMA`                 | `auth`                 | The Postgres schema for the auth tables.                                                               |

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

- **Endpoints:** `/Users` and `/Groups` (GET, POST, PUT, PATCH, DELETE), `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas`, authenticated with a bearer token from `<APP>_SCIM_TOKENS`.
- **Filters:** `eq` on `userName` (ignoring case), `externalId`, `id` and `emails.value` or `emails[type eq "work"].value`, joined with `and`; groups on `displayName`, `externalId` and `id`. Other operators answer 400 `invalidFilter`. Lists page with `startIndex` and `count` (at most 200) and honour `attributes` and `excludedAttributes`.
- **PATCH** accepts `add`, `replace` and `remove` in any case, with paths such as `active`, `name.givenName` and `emails[type eq "work"].value`, or path-less value objects. `"True"` and `"False"` count as booleans. Unknown attributes and the enterprise extension are ignored.
- **Lifecycle:** `active: false` deactivates and revokes sessions. `DELETE` tombstones the user, removes them from every group and revokes everything. A tombstoned user is gone from SCIM: they cannot be reactivated, and their `externalId` cannot be reused. Both call `hooks.onDeactivate` in the same transaction.
- **Groups:** display names are unique ignoring case. A PUT without `members` keeps the members, so a rename never empties a group.

### Where roles come from

- **`<APP>_ROLE_SOURCE=claims`** (default). The role claim sets the role at each sign-in. SCIM manages users and stores groups but does not change roles.
- **`<APP>_ROLE_SOURCE=scim`** (recommended with authentik). A user's role is the highest role their groups' display names map to through `<APP>_OIDC_ROLE_MAP` (ignoring case), recomputed on every membership change in the same transaction, and `hooks.onRoleChange` runs on every change. With no mapped group the user has no access: their sessions end and sign-in refuses them as `unassigned`. Sign-in never creates users or changes roles in this mode, but still refuses a role claim that maps to nothing.

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
POSTED_BOOTSTRAP_ADMIN=you@example.com
```

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

authentik sends user changes as `PUT` and never `PATCH`, membership as group `PATCH` `add` and `remove`, and removes users who leave the application's scope with `DELETE`. Its `externalId` is the hashed user id, the same value as the OIDC `sub` in the default subject mode, which is what makes linking safe.

authentik sends no `iss` parameter in the authorization response and does not advertise it, so the callback validates the ID token's `iss` instead. It ignores `max_age=0`, so step-up always sends `prompt=login` and a positive `max_age`.

## Migrations

`migrate()` applies the SQL files in [`migrations/`](migrations) to the auth schema (default `auth`), creating it if needed. Run it from the app's existing migrate step: at boot, or as a separate job. It is safe to run from several instances at once.

Never edit a migration that has shipped. The runner refuses to run when an applied file changed, and when the database has a migration this version does not include.

## Testing

`startMockProvider` runs an OpenID provider in-process on a random port. It signs in whoever `setLogin` names, with the `amr` and `auth_time` you choose, honours `prompt=login` and `max_age`, and signs and sends back-channel logout tokens. `authentikLike: true` drops the `iss` parameter as authentik does. `createBrowser` follows the redirects with a cookie jar, so tests drive the whole flow without a browser.
