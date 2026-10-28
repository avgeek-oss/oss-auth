# @avgeek-oss/auth-core

The server half of Avgeek OSS auth: sign-in through the organisation's OpenID provider, sessions, roles and the Postgres schema. See the [repository README](../../README.md) for the design and [ARCHITECTURE.md](../../ARCHITECTURE.md) for the contract apps implement.

| Import                           | What it holds                                                                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `@avgeek-oss/auth-core`          | `loadAuthConfig`, `deriveKey` and `createKeyring`, tokens, the API key format, roles and `resolveRole`, `Actor`, errors with stable codes. |
| `@avgeek-oss/auth-core/postgres` | The `Sql` interface, `fromPg(pool)` and `fromPostgresJs(sql)`, `migrate(sql, { schema })`.                                                 |
| `@avgeek-oss/auth-core/oidc`     | The relying party (`createOidcClient`), sealed sign-in transactions, `safeReturnTo`, `signInUser`, `verifyLogoutToken`.                    |
| `@avgeek-oss/auth-core/sessions` | `createSessions`: create, look up, revoke, list, step-up and back-channel revocation.                                                      |
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

| Variable                     | Default                | Meaning                                                                         |
| ---------------------------- | ---------------------- | ------------------------------------------------------------------------------- |
| `<APP>_SECRET`               | required               | At least 32 bytes; every key is derived from it. `openssl rand -base64 48`.     |
| `<APP>_OIDC_ISSUER`          | required               | The provider's issuer, exactly as its discovery document states it.             |
| `<APP>_OIDC_CLIENT_ID`       | required               | The client registered for this app.                                             |
| `<APP>_OIDC_CLIENT_SECRET`   | required               | Its secret. The client authenticates with HTTP Basic.                           |
| `<APP>_OIDC_SCOPES`          | `openid email profile` | Scopes to request. authentik needs `entitlements` for its `roles` claim.        |
| `<APP>_OIDC_ROLE_CLAIMS`     | `roles`                | Claims holding roles or groups, comma-separated.                                |
| `<APP>_OIDC_ROLE_MAP`        | each role to itself    | JSON from claim value to `viewer`, `member` or `admin`. The highest match wins. |
| `<APP>_SCIM_TOKENS`          | unset                  | SCIM bearer tokens, comma-separated (used from the SCIM release).               |
| `<APP>_WEB_ORIGIN`           | required               | Where the pages live. `returnTo` and `Origin` are checked against it.           |
| `<APP>_API_ORIGIN`           | required               | Where the API lives. The callback is `<APP>_API_ORIGIN/auth/callback`.          |
| `<APP>_SESSION_MAX_AGE`      | `12h`                  | Absolute session lifetime.                                                      |
| `<APP>_SESSION_IDLE_TIMEOUT` | `2h`                   | Inactivity limit.                                                               |
| `<APP>_AUTH_SCHEMA`          | `auth`                 | The Postgres schema for the auth tables.                                        |

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

authentik sends no `iss` parameter in the authorization response and does not advertise it, so the callback validates the ID token's `iss` instead. It ignores `max_age=0`, so step-up always sends `prompt=login` and a positive `max_age`.

## Migrations

`migrate()` applies the SQL files in [`migrations/`](migrations) to the auth schema (default `auth`), creating it if needed. Run it from the app's existing migrate step: at boot, or as a separate job. It is safe to run from several instances at once.

Never edit a migration that has shipped. The runner refuses to run when an applied file changed, and when the database has a migration this version does not include.

## Testing

`startMockProvider` runs an OpenID provider in-process on a random port. It signs in whoever `setLogin` names, with the `amr` and `auth_time` you choose, honours `prompt=login` and `max_age`, and signs and sends back-channel logout tokens. `authentikLike: true` drops the `iss` parameter as authentik does. `createBrowser` follows the redirects with a cookie jar, so tests drive the whole flow without a browser.
