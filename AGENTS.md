# Avgeek OSS Auth

## Purpose and boundaries

This repository owns authentication and access control for Avgeek OSS apps: configuration, key derivation, tokens, roles, the auth schema and, in later releases, sessions, the OIDC relying party, the SCIM server, API keys and the MCP authorization server. Apps own their resources, their authorization beyond the three roles, their routes and their branding. The design system owns how the auth screens look.

Never import app code or add app-specific behaviour here. App-specific data enters through the `Actor` extension and through options.

## Decisions that are settled

- Sign-in is SSO only, through OIDC. No passwords, passkeys, email codes or invitations.
- Provisioning is SCIM 2.0. A missing role claim means "unknown, keep the current role", never "no role".
- Roles only: `viewer` < `member` < `admin`, the same in every app. Credentials carry a role ceiling; the effective role is the lower of the ceiling and the user's current role. OAuth scope strings are the role names.
- Each app is its own MCP authorization server and sends people to the identity provider to authenticate.
- Break-glass access is the `oss-auth break-glass` CLI only.

## Invariants

- People are keyed by `(iss, sub)`. Email is an attribute; never match or link on it.
- Never trust `returnTo`, `state`, `iss` or a logout token without the checks in `oidc/`. A refused sign-in returns an outcome, not an exception.
- Store only HMAC-SHA256 hashes of tokens and secrets, under a key from `deriveKey`. Never log a token, a secret or a configuration object's secret fields.
- `KEY_LABELS`, `KEY_DERIVATION_SALT`, the API key format and `migrationChecksum` are stored-data formats. Never change or reuse one; add new labels and versions instead. The known-answer tests pin them.
- Never edit a migration that has shipped. Add a new numbered file. Every SQL function pins `search_path` and reaches tables through `TG_TABLE_SCHEMA`, because the schema name is configurable.
- Database invariants (roles, tombstones, session revocation) live in constraints and triggers, not only in TypeScript.

## Code rules

- Strict TypeScript with `noUncheckedIndexedAccess`. Use `.js` extensions on relative imports and type-only imports for types. The packages ship ESM.
- Every exported function and type has TSDoc. Errors are `AuthError` subclasses with a stable `code`; messages say what happened and how to fix it, and never contain secret values.
- Runtime dependencies are limited to `zod`. Database drivers are optional peers, described structurally so their types are not needed.
- Every behaviour change comes with a test. SQL behaviour is tested against a real Postgres through both adapters. Sign-in behaviour is tested end to end with the mock provider and the cookie-jar browser in `@avgeek-oss/auth-core/testing`; add an attack test with every new check.

## Verify

Run `pnpm verify` before every commit. Set `AUTH_TEST_DATABASE_URL` to a disposable database to include the Postgres suites. `DATABASE_URL=… pnpm dev:example` runs the reference app against the mock provider.

## Release

All packages share one version and release together. Bump every `packages/*/package.json`, add a `## <version> (YYYY-MM-DD)` section to `CHANGELOG.md` dated the release day, and merge. Once `main` is green, run the **Cut release** workflow from `main`: it checks the versions, changelog, tag and npm state, and that the verified `main` run for the commit still has its tarballs, then creates the annotated `v<version>` tag, and starts the publish run on it. The publish run does not verify again: it checks that the tag is on `main`, downloads the tarballs from the successful `main` run for that commit (kept 30 days), dry-runs them against npm and publishes. A separate job then creates the GitHub release from the version's `CHANGELOG.md` section. Pushing the same tag by hand does the same.
