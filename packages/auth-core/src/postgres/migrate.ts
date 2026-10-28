import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { MigrationError } from "../errors.js";
import { isValidSchemaName, quoteIdent } from "../identifiers.js";
import type { Sql } from "./sql.js";

/** One migration: a plain `.sql` file. */
export interface Migration {
  /** The file name, such as `0001_core.sql`. Migrations run in name order. */
  readonly name: string;
  /** The file's contents. */
  readonly sql: string;
}

/** What {@link migrate} did. */
export interface MigrateResult {
  readonly schema: string;
  /** Migrations applied by this run, in order. */
  readonly applied: readonly string[];
  /** Migrations that were already applied. */
  readonly existing: readonly string[];
}

/** Options for {@link migrate}. */
export interface MigrateOptions {
  /** The schema to migrate, created if missing. Defaults to `auth`. */
  readonly schema?: string;
  /**
   * The migrations to apply. Defaults to the migrations this package ships,
   * which is what apps should use.
   */
  readonly migrations?: readonly Migration[];
}

/** The schema used when none is configured. */
export const DEFAULT_AUTH_SCHEMA = "auth";

/** The ledger table, inside the auth schema. */
export const MIGRATIONS_TABLE = "schema_migrations";

const NAME_PATTERN = /^\d{4}_[a-z0-9_]+\.sql$/;
const BUNDLED = new URL("../../migrations/", import.meta.url);

/**
 * The checksum recorded for a migration: SHA-256 of its text with line
 * endings normalised to `\n`, so a Windows checkout does not look edited.
 */
export function migrationChecksum(sql: string): string {
  return createHash("sha256")
    .update(sql.replaceAll("\r\n", "\n"))
    .digest("hex");
}

/**
 * The advisory lock key a migration run holds for `schema`. Runs against the
 * same schema wait for each other; runs against different schemas do not.
 */
export function migrationLockKey(schema: string): bigint {
  return createHash("sha256")
    .update(`avgeek-oss/auth-core:migrate:${schema}`)
    .digest()
    .readBigInt64BE(0);
}

/**
 * Reads the `.sql` files in `dir`, which defaults to the migrations this
 * package ships, sorted by name. Other files are ignored.
 */
export async function loadMigrations(
  dir: string | URL = BUNDLED,
): Promise<Migration[]> {
  const base =
    typeof dir === "string"
      ? dir.replace(/\/?$/, "/")
      : new URL(dir.href.endsWith("/") ? dir.href : `${dir.href}/`);
  const names = (await readdir(base))
    .filter((name) => name.endsWith(".sql"))
    .sort();
  return Promise.all(
    names.map(async (name) => ({
      name,
      sql: await readFile(
        typeof base === "string" ? `${base}${name}` : new URL(name, base),
        "utf8",
      ),
    })),
  );
}

function checkMigrations(migrations: readonly Migration[]): void {
  let previous = "";
  for (const migration of migrations) {
    if (!NAME_PATTERN.test(migration.name))
      throw new MigrationError(
        "migration_invalid",
        migration.name,
        `Migration "${migration.name}" must be named like 0002_add_api_keys.sql: four digits, an underscore, then lowercase letters, digits or underscores.`,
      );
    if (migration.name <= previous)
      throw new MigrationError(
        "migration_invalid",
        migration.name,
        `Migration ${migration.name} is out of order or repeated; migrations must be sorted by name with no duplicates.`,
      );
    if (migration.sql.trim() === "")
      throw new MigrationError(
        "migration_invalid",
        migration.name,
        `Migration ${migration.name} is empty.`,
      );
    previous = migration.name;
  }
}

/**
 * Brings the auth schema up to date.
 *
 * Everything happens in one transaction that holds an advisory lock for the
 * schema, so concurrent runs (several app instances starting at once)
 * apply each migration once. The run:
 *
 * 1. creates the schema and the `schema_migrations` ledger if missing;
 * 2. refuses to continue if an applied migration's file changed, if the
 *    database has a migration this package does not ship (it was migrated by
 *    a newer version), or if a new migration sorts before an applied one;
 * 3. applies the pending migrations in order with `search_path` set to the
 *    schema, recording each with its checksum.
 *
 * Nothing is applied if any check or migration fails. Re-running is a no-op.
 *
 * @throws {@link MigrationError} with code `migration_invalid`,
 *   `migration_modified` or `migration_unknown`.
 */
export async function migrate(
  sql: Sql,
  options: MigrateOptions = {},
): Promise<MigrateResult> {
  const schema = options.schema ?? DEFAULT_AUTH_SCHEMA;
  if (!isValidSchemaName(schema))
    throw new TypeError(
      `"${schema}" is not a valid auth schema name: use 1 to 63 bytes with no control characters or surrounding spaces, not starting with pg_.`,
    );
  const migrations = options.migrations ?? (await loadMigrations());
  checkMigrations(migrations);
  const qschema = quoteIdent(schema);
  const ledger = `${qschema}.${MIGRATIONS_TABLE}`;

  return sql.transaction(async (tx) => {
    await tx.lock(migrationLockKey(schema));
    await tx.query(`CREATE SCHEMA IF NOT EXISTS ${qschema}`);
    await tx.query(
      `CREATE TABLE IF NOT EXISTS ${ledger} (
        name text PRIMARY KEY,
        checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
        applied_at timestamptz NOT NULL DEFAULT now()
      )`,
    );
    const rows = await tx.query<{ name: string; checksum: string }>(
      `SELECT name, checksum FROM ${ledger} ORDER BY name`,
    );
    const applied = new Map(rows.map((row) => [row.name, row.checksum]));
    const known = new Map(migrations.map((m) => [m.name, m]));

    for (const name of applied.keys())
      if (!known.has(name))
        throw new MigrationError(
          "migration_unknown",
          name,
          `Schema ${schema} has migration ${name}, which this version of @avgeek-oss/auth-core does not include. A newer version migrated it; upgrade the package instead of running an older one. Nothing was applied.`,
        );

    const pending: Migration[] = [];
    const existing: string[] = [];
    for (const migration of migrations) {
      const recorded = applied.get(migration.name);
      if (recorded === undefined) {
        pending.push(migration);
        continue;
      }
      if (recorded !== migrationChecksum(migration.sql))
        throw new MigrationError(
          "migration_modified",
          migration.name,
          `Migration ${migration.name} changed after it was applied to schema ${schema}. Restore the original file; to change the schema, add a new migration. Nothing was applied.`,
        );
      existing.push(migration.name);
    }

    const lastApplied = existing.at(-1);
    const early = pending.find(
      (m) => lastApplied !== undefined && m.name < lastApplied,
    );
    if (early !== undefined)
      throw new MigrationError(
        "migration_invalid",
        early.name,
        `Migration ${early.name} is new but sorts before ${lastApplied}, which is already applied to schema ${schema}. Give it a later number. Nothing was applied.`,
      );

    if (pending.length > 0)
      await tx.query(`SET LOCAL search_path TO ${qschema}`);
    for (const migration of pending) {
      await tx.query(migration.sql);
      await tx.query(`INSERT INTO ${ledger} (name, checksum) VALUES ($1, $2)`, [
        migration.name,
        migrationChecksum(migration.sql),
      ]);
    }
    return {
      schema,
      applied: pending.map((m) => m.name),
      existing,
    };
  });
}
