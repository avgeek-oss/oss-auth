# @avgeek-oss/auth-core

The server half of Avgeek OSS auth. See the [repository README](../../README.md) for the design and [ARCHITECTURE.md](../../ARCHITECTURE.md) for the contract apps implement.

- `loadAuthConfig(app, process.env)`: reads and validates `<APP>_SECRET`, `<APP>_OIDC_ISSUER`, `<APP>_OIDC_CLIENT_ID`, `<APP>_OIDC_CLIENT_SECRET`, `<APP>_OIDC_ROLE_CLAIMS`, `<APP>_OIDC_ROLE_MAP`, `<APP>_SCIM_TOKENS`, `<APP>_WEB_ORIGIN`, `<APP>_API_ORIGIN`, `<APP>_SESSION_MAX_AGE`, `<APP>_SESSION_IDLE_TIMEOUT` and `<APP>_AUTH_SCHEMA`. Errors name every bad variable and never echo values.
- `deriveKey(secret, app, label)` and `createKeyring(secret, app)`: HKDF-SHA256 keys from the app secret, one per label in `KEY_LABELS`.
- `generateToken()`, `hashToken(key, token)`, `verifyTokenHash()`, `constantTimeEqual()`: 256-bit bearer tokens, stored as HMAC-SHA256.
- `generateApiKey(prefix)`, `parseApiKey(key, prefix)`, `isValidApiKey()`, `apiKeyPattern(prefix)`: the `<prefix>_<id>_<secret>_<checksum>` key format with a CRC32 checksum.
- `Role`, `roleRank`, `roleAtLeast`, `minRole`, `resolveRole(claims, roleMap)`: the `viewer` < `member` < `admin` roles and claim mapping.
- `Actor`, `createActor()`, `effectiveRole()`, `AuditEvent`: who is calling, with what ceiling, and what gets recorded.
- `AuthError` and its subclasses, each with a stable `code`.
- `@avgeek-oss/auth-core/postgres`: the `Sql` interface, `fromPg(pool)` and `fromPostgresJs(sql)`, `migrate(sql, { schema })`, and `insertAuditEvent()`.

Runtime dependency: `zod`. Optional peer dependencies: `pg` or `postgres`, for the adapter you use.

## Migrations

`migrate()` applies the SQL files in [`migrations/`](migrations) to the auth schema (default `auth`), creating it if needed. Run it from the app's existing migrate step: at boot, or as a separate job. It is safe to run from several instances at once.

```ts
import pg from "pg";
import { loadAuthConfig } from "@avgeek-oss/auth-core";
import { fromPg, migrate } from "@avgeek-oss/auth-core/postgres";

const config = loadAuthConfig("posted", process.env);
const sql = fromPg(new pg.Pool({ connectionString: process.env.DATABASE_URL }));
await migrate(sql, { schema: config.schema });
```

Never edit a migration that has shipped. The runner refuses to run when an applied file changed, and when the database has a migration this version does not include.
