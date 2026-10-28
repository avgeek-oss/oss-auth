# Architecture

Avgeek OSS Auth replaces the five separate auth stacks in Mill, Posted, Rootset, Towbar and Vitalog with one shared implementation. Each app delegates authentication to the organisation's identity provider and keeps only what the provider cannot know: sessions, credentials for programs, and the app's own resources.

## Decisions

| Topic        | Decision                                                                                                                                                                 |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Sign-in      | SSO only, for every app. OIDC authorization code with PKCE, `state` and `nonce` against the organisation's provider. No passwords, passkeys, email codes or invitations. |
| Provider     | Any OIDC provider. The reference is authentik 2026.8 with Google as the login source.                                                                                    |
| Provisioning | A SCIM 2.0 server in each app. The provider creates, updates, deactivates and deletes users and pushes group membership.                                                 |
| Roles        | `viewer` < `member` < `admin`, the same three in every app. No granular scopes. OAuth scope strings are the role names.                                                  |
| Credentials  | API keys and MCP grants carry a role ceiling. Effective role = `min(ceiling, user's current role)`, computed on every request.                                           |
| MCP          | Each app is its own OAuth 2.1 authorization server for MCP clients. It sends the person to the provider to authenticate, then issues its own audience-bound tokens.      |
| Vitalog      | A team app. Each member's records are private to that member, enforced by row-level isolation in Vitalog, not in auth-core.                                              |
| Break-glass  | The `oss-auth break-glass` CLI only. No in-app recovery paths.                                                                                                           |
| Storage      | Postgres, in a schema of its own (default `auth`), through a small `Sql` interface with `pg` and Postgres.js adapters. Plain SQL migrations shipped with the package.    |

## Packages and subpaths

Subpaths are added as each part is implemented. Names of the later ones are provisional.

| Import                                      | Status              | Contents                                                                                      |
| ------------------------------------------- | ------------------- | --------------------------------------------------------------------------------------------- |
| `@avgeek-oss/auth-core`                     | this PR             | Config, key derivation, tokens, API key format, roles, actors, audit events, errors.          |
| `@avgeek-oss/auth-core/postgres`            | this PR             | `Sql`, `fromPg`, `fromPostgresJs`, `migrate`, `insertAuditEvent`, the auth schema migrations. |
| `@avgeek-oss/auth-core/hono`                | PR 2                | Session middleware, the OIDC routes, back-channel logout, CSRF origin checks.                 |
| `@avgeek-oss/auth-core/scim`                | PR 3                | The SCIM 2.0 server routes.                                                                   |
| `@avgeek-oss/auth-core/mcp`                 | PR 5                | The MCP authorization server and resource-server middleware.                                  |
| `@avgeek-oss/auth-client`                   | PR 6                | Browser client for the auth API, used by the design-system patterns.                          |
| `@avgeek-oss/design-system` `patterns/auth` | PR 6, in oss-ds-web | Sign-in, sessions, API keys and consent screens.                                              |

### What exists now

- **Configuration.** `loadAuthConfig(app, env)` reads `<APP>_SECRET` (at least 32 bytes), the OIDC issuer, client id and secret, the role claims and role map, SCIM bearer tokens, the web and API origins, session lengths and the auth schema name. It reports every invalid variable by name in one error and redacts secrets when logged.
- **Keys.** `deriveKey(secret, app, label)` is HKDF-SHA256 with salt `avgeek-oss/auth-core` and info `<app>:<label>:v1`. The labels are a fixed registry (`session`, `oidc-transaction`, `scim-token`, `api-key`, `oauth-code`, `oauth-access-token`, `oauth-refresh-token`, `idempotency`, `break-glass`), so a value made for one purpose is useless for another, and two apps sharing a secret still get different keys.
- **Tokens.** 256-bit random tokens as base64url, stored as HMAC-SHA256 under the purpose's derived key, compared in constant time.
- **API keys.** `<prefix>_<id>_<secret>_<checksum>`: a 2–16 character app prefix, a 26-character Crockford base32 id, a 43-character base62 secret (256 bits) and a 6-character CRC32 checksum, so secret scanners can find keys and reject look-alikes without a database.
- **Roles.** `resolveRole(claims, roleMap)` returns the highest mapped role, `"none"` when the claim is present but nothing maps, and `null` when the claim is missing, which means "unknown, keep the current role". Providers drop group claims on overage or never send them, so a missing claim must not demote anyone; removal arrives through SCIM.
- **Schema.** `0001_core.sql` creates `users`, `sessions` and `audit_events`. Constraints and triggers hold the invariants: roles are one of three; `(iss, sub)` and `(iss, external_id)` are unique; deletion is a permanent tombstone; only an active user can get a session; deactivating a user revokes their live sessions in the same transaction; a session's id, owner and absolute expiry never change, revocation is final, and its authentication time only moves forward; audit rows are never updated.
- **Migrations.** `migrate()` runs in one transaction under an advisory lock per schema, records SHA-256 checksums, and refuses to run when an applied migration changed, when the database is newer than the package, or when a new migration sorts before an applied one.

## The contract each app implements

An app adopting auth-core provides:

1. **Configuration** through `<APP>_*` environment variables, and a lowercase app id (`mill`, `posted`, `rootset`, `towbar`, `vitalog`) that is part of every derived key.
2. **A Postgres connection** wrapped with `fromPg` or `fromPostgresJs`, and a call to `migrate()` in its existing migrate step. The auth tables stay in their schema; the app's tables may reference `users.id`.
3. **Two origins on one site.** The OIDC callback, session cookie, SCIM endpoint and MCP authorization server live on the API origin; the sign-in, consent and settings pages live on the web origin.
4. **Authorization beyond roles.** auth-core answers "who is this and what role do they act with". The app decides what that role may do with its resources, and puts any extra context (a workspace, a board restriction) in the `Actor` extension.
5. **Audit continuity.** The app writes its own domain events wherever it likes; auth events go to `audit_events` through `insertAuditEvent`, inside the transaction that made the change.

## Reference identity provider: authentik 2026.8

The reference setup runs on authentik's free edition. Per app (Posted shown):

- **Groups** `posted-viewers`, `posted-members`, `posted-admins`, bound to the `Posted` application with policy engine mode `Any`, so nobody else can authorize.
- **Application entitlements** `viewer`, `member` and `admin`, bound to those groups. authentik's `entitlements` scope then emits `roles: ["admin"]`, which the default role map reads as is.
- **OAuth2/OpenID provider**: confidential client; strict redirect URI on the API origin; RS256 signing; hashed-user-ID subjects (equal to the SCIM `externalId`); **Include claims in id_token** on; scopes `openid email profile entitlements`; access-token validity at least the authentik session length, so back-channel logout still fires; back-channel logout to the app.
- **SCIM provider** attached as a **backchannel provider** of the application, with a static bearer token (one of `<APP>_SCIM_TOKENS`), group filters set to the three groups, and the full-sync schedule shortened from four hours to about ten minutes.
- **Login**: the Google OAuth source with an Internal consent screen and a domain check, followed by an authenticator validation stage (WebAuthn or TOTP, never email) on every authentik login. Step-up is then `prompt=login` and a check of `auth_time` and `amr` in the app.

Constraints the apps must handle: authentik does not return `iss` in the authorization response (RFC 9207), so the app validates the ID token's `iss` instead; `max_age=0` is ignored, so step-up uses `prompt=login`; users leaving an application's scope are deleted at the next full sync rather than deactivated; and an unauthorised user stays on authentik's "Access denied" page instead of returning to the app.

## Roadmap

Each step is its own pull request, in this order.

1. **Foundation** (this PR): repository, configuration, key derivation, tokens, API key format, roles, actors and audit events, the Postgres interface, adapters, migration runner and core schema.
2. **Sessions and sign-in**: sessions, the Hono integration, the OIDC relying party with a mock identity provider for tests, back-channel logout, and a reference app.
3. **SCIM**: the SCIM 2.0 server for users and groups, with group-to-role mapping shared with sign-in.
4. **API keys and role middleware**: personal API keys with role ceilings, and middleware that enforces a minimum role.
5. **MCP authorization server**: OAuth 2.1 with PKCE S256, resource indicators, CIMD clients, refresh-token rotation and protected-resource metadata.
6. **Client and screens**: `@avgeek-oss/auth-client` and the design-system `patterns/auth`.
7. **Operations**: background jobs (expiry sweeps), the `oss-auth break-glass` CLI and `auth-google-guard`, which deactivates suspended Google accounts in the provider.
