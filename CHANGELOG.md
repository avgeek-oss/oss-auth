# Changelog

All packages release together with the same version.

## Unreleased

- `@avgeek-oss/auth-core`: typed configuration from `<APP>_*` environment variables, HKDF-SHA256 key derivation with a fixed label registry, 256-bit tokens stored as HMAC-SHA256, the `<prefix>_<id>_<secret>_<checksum>` API key format, the `viewer`/`member`/`admin` roles with claim mapping, actors and typed errors.
- `@avgeek-oss/auth-core/postgres`: the `Sql` interface with `pg` and Postgres.js adapters, a migration runner for plain SQL files, and the `0001_core` migration (users and sessions).
- `@avgeek-oss/auth-core`: `<APP>_OIDC_SCOPES`, and `AuthRequestError` with an HTTP status per code.
- `@avgeek-oss/auth-core/oidc`: the OpenID Connect relying party on `openid-client`, with S256 PKCE, `state` and `nonce`, AES-256-GCM sealed sign-in transactions, the RFC 9207 `iss` check when the provider advertises it, step-up with `prompt=login`, safe `returnTo` paths, claims-to-user mapping (a role only ever comes from the provider), and back-channel logout token verification. The `jti` replay cache is written in the same transaction as the revocation.
- `@avgeek-oss/auth-core/sessions`: sessions with a new token on every sign-in, absolute and idle expiry, revocation, listing and step-up.
- `@avgeek-oss/auth-core/hono`: `createAuth`, with the `/auth` sign-in, callback, sign-out, session, step-up and back-channel logout routes, and the `actor`, `requireActor`, `requireRole`, `requireRecentAuth` and `trustedOrigin` middleware.
- `@avgeek-oss/auth-core/testing`: a mock OpenID provider on `oidc-provider`, with an authentik-like mode, and a cookie-jar browser.
- `@avgeek-oss/auth-core/postgres`: the `0002_sessions_oidc` migration (`users.role_source`, `logout_jtis` and a sessions index).
- `@avgeek-oss/auth-core/scim`: `createScim`, a SCIM 2.0 server for Users and Groups with bearer-token auth, `eq` filters, pagination, attribute selection, PATCH as authentik, Okta and Entra send it, deactivation and tombstoning with `onDeactivate`, revival when the provider provisions a deleted user's `externalId` again, and group membership in `0003_scim.sql`.
- `@avgeek-oss/auth-core`: `<APP>_ROLE_SOURCE` (`claims` or `scim`, roles from SCIM groups recomputed on every membership change with `onRoleChange`) and `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT`, which links a provisioned user to their first sign-in by `externalId = sub`. Sign-in refuses `unassigned` users in `scim` mode and never-assigned users in `claims` mode.
- `@avgeek-oss/auth-core/api-keys`: `createApiKeys`, personal API keys with a role ceiling and an optional opaque workspace: issue (never above the owner's role), list, rotate with a grace period, revoke, and verify in constant time with the effective role `min(ceiling, role)`. `<APP>_API_KEY_PREFIX`, `<APP>_API_KEY_MAX_TTL_DAYS` and `<APP>_API_KEY_ALLOW_NO_EXPIRY`.
- `@avgeek-oss/auth-core/postgres`: the `0004_api_keys` migration. Deactivating or deleting a user revokes their keys, and lowering their role revokes the keys above it, in the same transaction.
- `@avgeek-oss/auth-core/hono`: `Authorization: Bearer` API keys in `actor`, `step_up_unavailable` for keys in `requireRecentAuth`, no CSRF check for bearer requests, the `/auth/api-keys` routes, and `hooks.authorizeWorkspace`. `ActorCredential` gains `workspace`; errors gain `step_up_unavailable`, `invalid_request`, `not_found` and `conflict`.
