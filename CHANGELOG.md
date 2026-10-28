# Changelog

All packages release together with the same version.

## Unreleased

- `@avgeek-oss/auth-core`: typed configuration from `<APP>_*` environment variables, HKDF-SHA256 key derivation with a fixed label registry, 256-bit tokens stored as HMAC-SHA256, the `<prefix>_<id>_<secret>_<checksum>` API key format, the `viewer`/`member`/`admin` roles with claim mapping, actors, audit events and typed errors.
- `@avgeek-oss/auth-core/postgres`: the `Sql` interface with `pg` and Postgres.js adapters, a migration runner for plain SQL files, the `0001_core` migration (users, sessions and the audit log) and `insertAuditEvent`.
