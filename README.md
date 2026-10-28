# Avgeek OSS Auth

Shared sign-in, provisioning and access control for Avgeek OSS apps: Mill, Posted, Rootset, Towbar and Vitalog. Each app signs people in through the organisation's OpenID Connect identity provider, accepts SCIM 2.0 provisioning from it, and gives every person one of three roles: `viewer`, `member` or `admin`. There are no passwords, passkeys or invitations in the apps.

| Package                                       | Runs in | What it does                                                                                      |
| --------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| [`@avgeek-oss/auth-core`](packages/auth-core) | server  | Configuration, key derivation, tokens, the API key format, roles and actors.                      |
| `@avgeek-oss/auth-core/postgres`              | server  | The `Sql` interface with `pg` and Postgres.js adapters, the migration runner and the auth schema. |
| `@avgeek-oss/auth-core/oidc`                  | server  | The OpenID Connect relying party: sign-in, step-up and back-channel logout tokens.                |
| `@avgeek-oss/auth-core/api-keys`              | server  | Personal API keys with a role ceiling: issue, list, rotate, revoke and verify.                    |
| `@avgeek-oss/auth-core/mcp`                   | server  | The OAuth 2.1 authorization server for MCP clients, and the middleware that checks its tokens.    |
| `@avgeek-oss/auth-core/rate-limits`           | server  | Rate limits in Postgres (GCRA), client IPs behind trusted proxies, and the default policies.      |
| `@avgeek-oss/auth-core/sessions`              | server  | Sessions with absolute and idle expiry, revocation and step-up.                                   |
| `@avgeek-oss/auth-core/scim`                  | server  | The SCIM 2.0 server for Users and Groups, with roles from group membership.                       |
| `@avgeek-oss/auth-core/hono`                  | server  | `createAuth`: the `/auth` routes and the role, step-up and CSRF middleware for a Hono API.        |
| `@avgeek-oss/auth-core/testing`               | tests   | A mock OpenID provider and a cookie-jar browser for flow tests.                                   |

The browser client and the operator CLI follow in later releases. [ARCHITECTURE.md](ARCHITECTURE.md) has the design, the contract each app implements and the roadmap.

The sign-in and settings screens belong in [`@avgeek-oss/design-system`](https://github.com/avgeek-oss/oss-ds-web) as `patterns/auth`.

## How access works

1. The identity provider decides who may use each app. The reference setup is authentik 2026.8 with Google as the login; any OIDC provider with SCIM works.
2. A person signs in to the app's API with OIDC. The app keys them by issuer and subject, never by email, and reads their role from the token's `roles` or `groups` claim.
3. The provider pushes changes over SCIM: new people, role changes, deactivation. Deactivating a person ends their sessions in the same transaction.
4. API keys and MCP grants carry a role ceiling. A request acts with the lower of the ceiling and the person's current role, and lowering someone's role revokes their keys above it. Deactivating them revokes all of their keys.

## Add it to an app

Configure the app through its environment, using its own prefix:

```sh
POSTED_SECRET=$(openssl rand -base64 48)
POSTED_OIDC_ISSUER=https://auth.example.com/application/o/posted/
POSTED_OIDC_CLIENT_ID=posted
POSTED_OIDC_CLIENT_SECRET=...
POSTED_WEB_ORIGIN=https://posted.example.com
POSTED_API_ORIGIN=https://api.posted.example.com
# Optional, with their defaults:
POSTED_OIDC_SCOPES="openid email profile"
POSTED_OIDC_ROLE_CLAIMS=roles
POSTED_OIDC_ROLE_MAP='{"viewer":"viewer","member":"member","admin":"admin"}'
POSTED_SCIM_TOKENS=
POSTED_API_KEY_PREFIX=posted
POSTED_API_KEY_MAX_TTL_DAYS=365
POSTED_API_KEY_ALLOW_NO_EXPIRY=false
POSTED_OAUTH_CLIENTS='[]'
POSTED_OAUTH_LEGACY_DCR=false
POSTED_TRUSTED_PROXIES=
POSTED_TRUSTED_PROXY_HEADER=x-forwarded-for
POSTED_RATE_LIMITS='{}'
POSTED_SESSION_MAX_AGE=12h
POSTED_SESSION_IDLE_TIMEOUT=2h
POSTED_AUTH_SCHEMA=auth
```

Then load the configuration, migrate the auth schema from the app's migrate step, and mount the routes:

```ts
import { loadAuthConfig } from "@avgeek-oss/auth-core";
import { createAuth } from "@avgeek-oss/auth-core/hono";
import { fromPostgresJs, migrate } from "@avgeek-oss/auth-core/postgres";

const config = loadAuthConfig("posted", process.env);
const db = fromPostgresJs(sql);
await migrate(db, { schema: config.schema });

const auth = createAuth({ config, sql: db });
app.route("/auth", auth.routes);
app.use("/api/*", auth.middleware.actor, auth.middleware.trustedOrigin);
app.post("/api/members", auth.middleware.requireRole("admin"), addMember);
```

The [package README](packages/auth-core/README.md) lists the routes, every variable and an authentik setup.

`loadAuthConfig` throws one error that lists every invalid variable by name. The auth tables live in their own schema, so they never collide with the app's tables.

## Develop

The packages require Node 26 or later, the version every avgeek-oss app runs on (`.nvmrc`). Requires pnpm 11.

```sh
pnpm install
pnpm verify          # format, lint, typecheck, test, build
pnpm test:watch
DATABASE_URL=postgres://... pnpm dev:example   # the reference app on http://localhost:5173
```

[`examples/hono-vite`](examples/hono-vite) is a Hono API and a Vite page using `createAuth`, signing in through the mock provider in `@avgeek-oss/auth-core/testing`.

The Postgres suites run when `AUTH_TEST_DATABASE_URL` points at a disposable database; without it they are skipped. CI runs them against Postgres 18, and they also pass on Postgres 16. To run them locally:

```sh
docker run --rm -d --name auth-test -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=auth_test postgres:18-alpine
AUTH_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/auth_test pnpm test
```

Each test creates schemas with random names and drops them afterwards. One test uses the default `auth` schema and drops it, so do not point the variable at a database you care about.

## Release

All packages carry the same version. Bump them together, add a `## <version> (YYYY-MM-DD)` section to `CHANGELOG.md` dated the release day, and merge. Then run the **Cut release** workflow from `main` in GitHub Actions. It tags the head of `main` as `v<version>` and starts the publish run, which takes the tarballs that `main`'s verification built for that commit and publishes them through npm trusted publishing, with provenance. A separate job then creates the `v<version>` GitHub release from that version's changelog section.

## Feedback and contributions

We are not accepting contributions from public sources, to curb automated pull requests and because there are no dedicated resources to review and sign them off. Feedback and issues are welcome in [GitHub Issues](https://github.com/avgeek-oss/oss-auth/issues); we triage them and strive to fix them at the earliest. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
