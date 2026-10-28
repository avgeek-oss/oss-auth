# Changelog

All packages release together with the same version.

## Unreleased

- `@avgeek-oss/auth-core`: typed configuration from `<APP>_*` environment variables, HKDF-SHA256 key derivation with a fixed label registry, 256-bit tokens stored as HMAC-SHA256, the `<prefix>_<id>_<secret>_<checksum>` API key format, the `viewer`/`member`/`admin` roles with claim mapping, actors and typed errors.
- `@avgeek-oss/auth-core/postgres`: the `Sql` interface with `pg` and Postgres.js adapters, a migration runner for plain SQL files, and the `0001_core` migration (users and sessions).
- `@avgeek-oss/auth-core`: `<APP>_OIDC_SCOPES` and `<APP>_BOOTSTRAP_ADMIN`, and `AuthRequestError` with an HTTP status per code.
- `@avgeek-oss/auth-core/oidc`: the OpenID Connect relying party on `openid-client`, with S256 PKCE, `state` and `nonce`, AES-256-GCM sealed sign-in transactions, the RFC 9207 `iss` check when the provider advertises it, step-up with `prompt=login`, safe `returnTo` paths, claims-to-user mapping with the bootstrap admin, and back-channel logout token verification. The `jti` replay cache is written in the same transaction as the revocation.
- `@avgeek-oss/auth-core/sessions`: sessions with a new token on every sign-in, absolute and idle expiry, revocation, listing and step-up.
- `@avgeek-oss/auth-core/hono`: `createAuth`, with the `/auth` sign-in, callback, sign-out, session, step-up and back-channel logout routes, and the `actor`, `requireActor`, `requireRole`, `requireRecentAuth` and `trustedOrigin` middleware.
- `@avgeek-oss/auth-core/testing`: a mock OpenID provider on `oidc-provider`, with an authentik-like mode, and a cookie-jar browser.
- `@avgeek-oss/auth-core/postgres`: the `0002_sessions_oidc` migration (`users.role_source`, `logout_jtis` and a sessions index).
