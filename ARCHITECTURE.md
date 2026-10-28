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

| Import                                      | Status              | Contents                                                                                                                             |
| ------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `@avgeek-oss/auth-core`                     | PR 1                | Config, key derivation, tokens, API key format, roles, actors, errors.                                                               |
| `@avgeek-oss/auth-core/postgres`            | PR 1                | `Sql`, `fromPg`, `fromPostgresJs`, `migrate`, the auth schema migrations.                                                            |
| `@avgeek-oss/auth-core/oidc`                | PR 2                | The relying party on `openid-client`: sign-in and step-up, sealed transactions, claims to user, logout tokens.                       |
| `@avgeek-oss/auth-core/api-keys`            | PR 4                | `createApiKeys`: personal API keys with a role ceiling: issue, list, rotate with grace, revoke and verify.                           |
| `@avgeek-oss/auth-core/sessions`            | PR 2                | Session create, lookup with idle and absolute expiry, revoke, list, step-up and back-channel revocation.                             |
| `@avgeek-oss/auth-core/hono`                | PR 2                | `createAuth`: the `/auth` routes and the `actor`, `requireActor`, `requireRole`, `requireRecentAuth` and `trustedOrigin` middleware. |
| `@avgeek-oss/auth-core/testing`             | PR 2                | A mock OpenID provider on `oidc-provider`, and a cookie-jar browser for flow tests.                                                  |
| `@avgeek-oss/auth-core/scim`                | PR 3                | `createScim`: the SCIM 2.0 server for Users and Groups, roles from groups, hooks for deactivation and role changes.                  |
| `@avgeek-oss/auth-core/mcp`                 | PR 5                | The MCP authorization server and resource-server middleware.                                                                         |
| `@avgeek-oss/auth-client`                   | PR 6                | Browser client for the auth API, used by the design-system patterns.                                                                 |
| `@avgeek-oss/design-system` `patterns/auth` | PR 6, in oss-ds-web | Sign-in, sessions, API keys and consent screens.                                                                                     |

[`examples/hono-vite`](examples/hono-vite) is a private reference app: a Hono API with `createAuth` and a Vite page, run against the mock provider with `pnpm dev:example`.

### What exists now

- **Configuration.** `loadAuthConfig(app, env)` reads `<APP>_SECRET` (at least 32 bytes), the OIDC issuer, client id and secret, the role claims, role map and requested scopes, the role source, SCIM bearer tokens and linking, the web and API origins, session lengths and the auth schema name. It reports every invalid variable by name in one error and redacts secrets when logged.
- **Keys.** `deriveKey(secret, app, label)` is HKDF-SHA256 with salt `avgeek-oss/auth-core` and info `<app>:<label>:v1`. The labels are a fixed registry (`session`, `oidc-transaction`, `scim-token`, `api-key`, `oauth-code`, `oauth-access-token`, `oauth-refresh-token`, `idempotency`, `break-glass`), so a value made for one purpose is useless for another, and two apps sharing a secret still get different keys.
- **Tokens.** 256-bit random tokens as base64url, stored as HMAC-SHA256 under the purpose's derived key, compared in constant time.
- **API keys.** `<prefix>_<id>_<secret>_<checksum>`: a 2–16 character app prefix, a 26-character Crockford base32 id, a 43-character base62 secret (256 bits) and a 6-character CRC32 checksum, so secret scanners can find keys and reject look-alikes without a database.
- **Roles.** `resolveRole(claims, roleMap)` returns the highest mapped role, `"none"` when the claim is present but nothing maps, and `null` when the claim is missing, which means "unknown, keep the current role". Providers drop group claims on overage or never send them, so a missing claim must not demote anyone; removal arrives through SCIM.
- **Schema.** `0001_core.sql` creates `users` and `sessions`. Constraints and triggers hold the invariants: a role is one of three, or NULL for no access, with no default; `(iss, sub)` and `(iss, external_id)` are unique; deletion is a tombstone that only SCIM can revive (`0003_scim.sql`); only an active user can get a session; deactivating a user revokes their live sessions in the same transaction; a session's id, owner and absolute expiry never change, revocation is final, and its authentication time only moves forward.
- **Sign-in.** The callback lives on the API origin. Sign-in sends the authorization code flow with S256 PKCE, `state` and `nonce`; the transaction (state, nonce, verifier, `returnTo`, purpose, start time) is sealed with AES-256-GCM under the `oidc-transaction` key in a 10-minute `__Host-<app>-oidc` cookie. The callback checks the transaction and `state`, then the RFC 9207 `iss` parameter (required when the provider advertises it, as authentik does not), then lets `openid-client` redeem the code and validate the ID token. `returnTo` accepts only paths on the web origin.
- **Users at sign-in.** People are found by `(iss, sub)`; email and name are refreshed. The role claim decides the role: `"none"` sets it to NULL and refuses the sign-in, and a missing claim keeps a returning user's role but refuses a user without one, so a role only ever comes from the provider; `users.role_source` records where it was last set. Session lookup refuses a user whose role is NULL, so the actor always has a role. Deactivated and deleted users are refused.
- **First-run setup.** Anyone the provider makes `admin` can configure the app, and first-run setup is gated on `requireRole("admin")` in the app, which keeps its own setup state.
- **Sessions.** A new 256-bit token on every sign-in, stored as its HMAC; the cookie is `__Host-<app>-session` (Secure, HttpOnly, SameSite=Lax), dropping the prefix and `Secure` only for a loopback HTTP API. Lookups enforce the absolute and idle expiry and slide the idle expiry at most once a minute. A new sign-in revokes the browser's previous session.
- **Step-up.** `requireRecentAuth(seconds)` answers 401 `step_up_required` with a step-up URL. Step-up sends `prompt=login` and `max_age` (never 0, which authentik ignores), then requires the same person, `auth_time` no earlier than the request (less a 5-second clock tolerance), and `mfa` in `amr` unless disabled. It updates the existing session rather than creating one.
- **Back-channel logout.** Logout tokens are verified against the provider's JWKS with `jose` (already a dependency of `openid-client`): asymmetric signature, `iss`, `aud`, fresh `iat`, the logout event, `sid` or `sub`, no `nonce`, and a `jti`. The route records the `jti` in `logout_jtis` and revokes the matching sessions in one transaction, so a failed revocation leaves the token usable for the provider's retry, and a second use is refused as a replay. authentik only sends these while the app holds a live access token for the session, so its access-token validity must cover the session length.
- **SCIM.** `createScim` serves `/Users` and `/Groups` (RFC 7643 and 7644) behind bearer tokens compared as HMACs in constant time. It accepts what authentik, Okta and Entra send: authentik's user `PUT`s and group `PATCH`es, Okta's path-less replaces, and Entra's capitalised ops, path-less value objects and `"True"`/`"False"` strings. Deactivation revokes sessions through the schema trigger; `DELETE` tombstones the user and removes their memberships. Provisioning the same `externalId` again (a `POST`, or a `PUT` to the old id) revives that row with the same id, so the OIDC link still works, and with no role until a group maps one; the trigger only allows this when the transaction announces it with `set_config('auth_core.revive_user', id, true)`, and sessions revoked by the deletion stay revoked. `hooks.onDeactivate` and `hooks.onRoleChange` run in the same transaction for later credential types. Groups and members live in `0003_scim.sql`.
- **Roles from SCIM.** With `<APP>_ROLE_SOURCE=scim`, the role is the highest mapping of the user's group display names, recomputed in the transaction of every membership change. Members are locked in id order with `FOR NO KEY UPDATE`, so concurrent changes serialise without deadlocking and the last one sees every membership. No mapped group means no access. With `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT=true`, the first sign-in links to the provisioned user whose `externalId` is the OIDC `sub`.
- **API key storage.** `0004_api_keys.sql` keeps each key's public id, owner, name, ceiling, optional workspace, HMAC (under the `api-key` key), expiry, last use, revocation and rotation (`replaced_by`, `grace_until`). Triggers make the identity, owner, ceiling, workspace, secret and expiry immutable, revocation final and rotation happen once, and give keys only to active users with a role. `verify` checks the format and checksum before any database read, looks the key up by id, compares the HMAC in constant time (an unknown id costs the same comparison), checks expiry, revocation and rotation grace, refuses an inactive owner or one without a role, and records `last_used_at` at most once a minute.
- **Keys follow their owner.** Deactivation or deletion revokes all of a user's keys, and a change to a non-NULL role revokes the keys whose ceiling is above it, in a trigger on `users` like the one that ends sessions. A NULL role suspends instead: keys and sessions are refused while it lasts, and work again when a role returns, because a move between groups in two requests can pass through NULL. Comparing with the new role alone also covers admin, then NULL, then member: no live key is above the last non-NULL role. A trigger rather than `onRoleChange` because roles change in three places: SCIM in `scim` mode, the role claim at sign-in in `claims` mode, and the app. The key list then shows what keys can really do. The effective role is still capped at `min(ceiling, role)` on every request.
- **Bearer keys in Hono.** `actor` accepts `Authorization: Bearer <key>`, never a query parameter or cookie, and ignores the session cookie when a bearer header is present. `requireRole` checks the effective role for both credentials; `requireRecentAuth` refuses keys with 403 `step_up_unavailable`. The `/auth/api-keys` routes need a session; creating or rotating an `admin` key needs a sign-in within 10 minutes; admins may list and revoke other people's keys. Keys for a workspace need the app's `hooks.authorizeWorkspace`.
- **CSRF.** `trustedOrigin` requires `Origin` to equal the web origin and an `X-Requested-With` header on every state-changing request. Requests with a bearer header skip it: no page on another origin can send one, and they ignore cookies.
- **Migrations.** `migrate()` runs in one transaction under an advisory lock per schema, records SHA-256 checksums, and refuses to run when an applied migration changed, when the database is newer than the package, or when a new migration sorts before an applied one.

## The contract each app implements

An app adopting auth-core provides:

1. **Configuration** through `<APP>_*` environment variables, and a lowercase app id (`mill`, `posted`, `rootset`, `towbar`, `vitalog`) that is part of every derived key.
2. **A Postgres connection** wrapped with `fromPg` or `fromPostgresJs`, and a call to `migrate()` in its existing migrate step. The auth tables stay in their schema; the app's tables may reference `users.id`.
3. **Two origins on one site.** The OIDC callback, session cookie, SCIM endpoint and MCP authorization server live on the API origin; the sign-in, consent and settings pages live on the web origin.
4. **Authorization beyond roles.** auth-core answers "who is this and what role do they act with". The app decides what that role may do with its resources, and puts any extra context (a workspace, a board restriction) in the `Actor` extension.

## Reference identity provider: authentik 2026.8

The reference setup runs on authentik's free edition. Per app (Posted shown):

- **Groups** `posted-viewers`, `posted-members`, `posted-admins`, bound to the `Posted` application with policy engine mode `Any`, so nobody else can authorize.
- **Application entitlements** `viewer`, `member` and `admin`, bound to those groups. authentik's `entitlements` scope then emits `roles: ["admin"]`, which the default role map reads as is.
- **OAuth2/OpenID provider**: confidential client; strict redirect URI on the API origin; RS256 signing; hashed-user-ID subjects (equal to the SCIM `externalId`); **Include claims in id_token** on; scopes `openid email profile entitlements`, so set `<APP>_OIDC_SCOPES` to the same; access-token validity at least the authentik session length, so back-channel logout still fires; back-channel logout to the app.
- **SCIM provider** attached as a **backchannel provider** of the application, with a static bearer token (one of `<APP>_SCIM_TOKENS`), group filters set to the three groups, and the full-sync schedule shortened from four hours to ten minutes. Set `<APP>_ROLE_SOURCE=scim` and `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT=true`.
- **Login**: the Google OAuth source with an Internal consent screen and a domain check, followed by an authenticator validation stage (WebAuthn or TOTP, never email) on every authentik login. Step-up is then `prompt=login` and a check of `auth_time` and `amr` in the app.

Constraints the apps must handle: authentik does not return `iss` in the authorization response (RFC 9207), so the app validates the ID token's `iss` instead; `max_age=0` is ignored, so step-up uses `prompt=login`; users leaving an application's scope are deleted at the next full sync rather than deactivated; and an unauthorised user stays on authentik's "Access denied" page instead of returning to the app.

## Roadmap

Each step is its own pull request, in this order.

1. **Foundation**: repository, configuration, key derivation, tokens, API key format, roles and actors, the Postgres interface, adapters, migration runner and core schema.
2. **Sessions and sign-in**: sessions, the Hono integration, the OIDC relying party with a mock identity provider for tests, back-channel logout, and a reference app.
3. **SCIM** (this PR): the SCIM 2.0 server for users and groups, with group-to-role mapping shared with sign-in.
4. **API keys and role middleware**: personal API keys with role ceilings, and middleware that enforces a minimum role.
5. **MCP authorization server**: OAuth 2.1 with PKCE S256, resource indicators, CIMD clients, refresh-token rotation and protected-resource metadata.
6. **Client and screens**: `@avgeek-oss/auth-client` and the design-system `patterns/auth`.
7. **Operations**: background jobs (expiry sweeps), the `oss-auth break-glass` CLI and `auth-google-guard`, which deactivates suspended Google accounts in the provider.
