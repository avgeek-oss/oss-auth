import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MigrationError } from "../../src/index.js";
import {
  loadMigrations,
  migrate,
  migrationChecksum,
  migrationLockKey,
  quoteIdent,
  type Migration,
  type Sql,
} from "../../src/postgres/index.js";
import { adapters, databaseUrl, dropSchemas, uniqueSchema } from "./support.js";

const core = await loadMigrations();
const BUNDLED = ["0001_core.sql", "0002_sessions_oidc.sql", "0003_scim.sql"];
const extra = (
  name: string,
  body = "CREATE TABLE extra (n int);",
): Migration => ({
  name,
  sql: body,
});

async function migrationError(
  promise: Promise<unknown>,
): Promise<MigrationError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(MigrationError);
    return error as MigrationError;
  }
  throw new Error("expected the migration run to be refused");
}

describe("loadMigrations", () => {
  it("loads the bundled migrations in order", () => {
    expect(core.map((m) => m.name)).toEqual(BUNDLED);
    expect(core[0]?.sql).toContain("CREATE TABLE users");
  });

  it("reads .sql files from a directory, sorted, ignoring other files", async () => {
    const dir = await mkdtemp(join(tmpdir(), "auth-core-migrations-"));
    await writeFile(join(dir, "0002_b.sql"), "SELECT 2;");
    await writeFile(join(dir, "0001_a.sql"), "SELECT 1;");
    await writeFile(join(dir, "README.md"), "notes");
    const expected = [
      { name: "0001_a.sql", sql: "SELECT 1;" },
      { name: "0002_b.sql", sql: "SELECT 2;" },
    ];
    expect(await loadMigrations(dir)).toEqual(expected);
    expect(await loadMigrations(`${dir}/`)).toEqual(expected);
    expect(await loadMigrations(pathToFileURL(dir))).toEqual(expected);
  });
});

describe("migrationChecksum", () => {
  it("is SHA-256 of the text with LF line endings", () => {
    expect(migrationChecksum("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(migrationChecksum("SELECT 1;\r\nSELECT 2;\r\n")).toBe(
      migrationChecksum("SELECT 1;\nSELECT 2;\n"),
    );
    expect(migrationChecksum("SELECT 1;")).not.toBe(
      migrationChecksum("SELECT 1; "),
    );
  });
});

describe("migrationLockKey", () => {
  it("is a stable signed 64-bit key per schema", () => {
    const key = migrationLockKey("auth");
    expect(key).toBe(migrationLockKey("auth"));
    expect(key).not.toBe(migrationLockKey("other"));
    expect(key >= -(2n ** 63n) && key < 2n ** 63n).toBe(true);
  });
});

describe("migrate input checks", () => {
  // These fail before any query, so no database is needed.
  const unused: Sql = {
    query: () => Promise.reject(new Error("no query expected")),
    transaction: () => Promise.reject(new Error("no transaction expected")),
  };

  it("refuses badly named, unsorted, repeated or empty migrations", async () => {
    for (const [migrations, name] of [
      [[extra("1_core.sql")], "1_core.sql"],
      [[extra("0001_Core.sql")], "0001_Core.sql"],
      [[extra("0001_core.SQL")], "0001_core.SQL"],
      [[extra("0002_b.sql"), extra("0001_a.sql")], "0001_a.sql"],
      [[extra("0001_a.sql"), extra("0001_a.sql")], "0001_a.sql"],
      [[extra("0001_a.sql", "  \n")], "0001_a.sql"],
    ] as const) {
      const error = await migrationError(migrate(unused, { migrations }));
      expect(error.code).toBe("migration_invalid");
      expect(error.migration).toBe(name);
    }
  });

  it("refuses an invalid schema name", async () => {
    for (const schema of ["", "pg_auth", " auth", "a".repeat(64), "x\ny"])
      await expect(
        migrate(unused, { schema, migrations: core }),
      ).rejects.toThrow(TypeError);
  });
});

describe.skipIf(!databaseUrl).each(adapters)(
  "migrate with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    const schemas = new Set<string>();
    const fresh = (label: string) => {
      const schema = uniqueSchema(label);
      schemas.add(schema);
      return schema;
    };

    beforeAll(() => {
      ({ sql, close } = adapter.open());
    });
    afterAll(async () => {
      await dropSchemas(sql, schemas);
      await close();
    });

    const tables = (schema: string) =>
      sql.query<{ name: string }>(
        `SELECT table_name AS "name" FROM information_schema.tables
       WHERE table_schema = $1 ORDER BY table_name`,
        [schema],
      );
    const ledger = (schema: string) =>
      sql.query<{ name: string; checksum: string; appliedAt: Date }>(
        `SELECT name, checksum, applied_at AS "appliedAt"
       FROM ${quoteIdent(schema)}.schema_migrations ORDER BY name`,
      );

    it("installs into the default auth schema", async () => {
      // Only this test uses the fixed name, one adapter at a time.
      await dropSchemas(sql, ["auth"]);
      try {
        const result = await migrate(sql);
        expect(result).toEqual({
          schema: "auth",
          applied: BUNDLED,
          existing: [],
        });
        expect((await tables("auth")).map((t) => t.name)).toEqual([
          "logout_jtis",
          "schema_migrations",
          "scim_group_members",
          "scim_groups",
          "sessions",
          "users",
        ]);
        const [row] = await ledger("auth");
        expect(row?.name).toBe("0001_core.sql");
        expect(row?.checksum).toBe(migrationChecksum(core[0]?.sql ?? ""));
        expect(row?.appliedAt).toBeInstanceOf(Date);
      } finally {
        await dropSchemas(sql, ["auth"]);
      }
    });

    it("installs into a quoted custom schema and nowhere else", async () => {
      const schema = fresh("custom");
      expect(await migrate(sql, { schema })).toMatchObject({
        schema,
        applied: BUNDLED,
      });
      expect((await tables(schema)).map((t) => t.name)).toEqual([
        "logout_jtis",
        "schema_migrations",
        "scim_group_members",
        "scim_groups",
        "sessions",
        "users",
      ]);
      const [elsewhere] = await sql.query<{ count: number }>(
        `SELECT count(*)::int AS "count" FROM information_schema.tables
         WHERE table_schema = 'public'
           AND table_name IN ('users', 'sessions', 'logout_jtis', 'schema_migrations')`,
      );
      expect(elsewhere?.count).toBe(0);
    });

    it("pins search_path on every function it creates", async () => {
      const schema = fresh("functions");
      await migrate(sql, { schema });
      const functions = await sql.query<{
        name: string;
        config: string[] | null;
      }>(
        `SELECT p.proname AS "name", p.proconfig AS "config"
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = $1 ORDER BY p.proname`,
        [schema],
      );
      expect(functions.map((f) => f.name)).toEqual([
        "scim_group_members_before_insert",
        "scim_groups_before_update",
        "sessions_before_insert",
        "sessions_before_update",
        "users_before_update",
        "users_revoke_sessions",
      ]);
      for (const f of functions)
        expect(f.config).toEqual(["search_path=pg_catalog, pg_temp"]);
    });

    it("does nothing when run again", async () => {
      const schema = fresh("rerun");
      await migrate(sql, { schema });
      const first = await ledger(schema);
      for (let i = 0; i < 2; i++)
        expect(await migrate(sql, { schema })).toEqual({
          schema,
          applied: [],
          existing: BUNDLED,
        });
      expect(await ledger(schema)).toEqual(first);
    });

    it("applies only the new migrations on a later run", async () => {
      const schema = fresh("later");
      await migrate(sql, { schema, migrations: core });
      const result = await migrate(sql, {
        schema,
        migrations: [...core, extra("0902_extra.sql")],
      });
      expect(result.applied).toEqual(["0902_extra.sql"]);
      expect(result.existing).toEqual(BUNDLED);
      expect((await tables(schema)).map((t) => t.name)).toContain("extra");
    });

    it("refuses a migration edited after it was applied", async () => {
      const schema = fresh("edited");
      await migrate(sql, { schema });
      const edited = core.map((m, i) =>
        i === 0 ? { name: m.name, sql: `${m.sql}\n-- edited\n` } : m,
      );
      const error = await migrationError(
        migrate(sql, {
          schema,
          migrations: [...edited, extra("0902_extra.sql")],
        }),
      );
      expect(error.code).toBe("migration_modified");
      expect(error.migration).toBe("0001_core.sql");
      expect(error.message).toContain("Nothing was applied");
      expect((await tables(schema)).map((t) => t.name)).not.toContain("extra");
    });

    it("accepts the same migration with Windows line endings", async () => {
      const schema = fresh("crlf");
      await migrate(sql, { schema });
      const crlf = core.map((m) => ({
        name: m.name,
        sql: m.sql.replaceAll("\n", "\r\n"),
      }));
      expect(
        (await migrate(sql, { schema, migrations: crlf })).applied,
      ).toEqual([]);
    });

    it("refuses to run when the database has a migration it does not know", async () => {
      const schema = fresh("newer");
      await migrate(sql, {
        schema,
        migrations: [...core, extra("0902_extra.sql")],
      });
      const error = await migrationError(
        migrate(sql, { schema, migrations: core }),
      );
      expect(error.code).toBe("migration_unknown");
      expect(error.migration).toBe("0902_extra.sql");
    });

    it("refuses a new migration that sorts before an applied one", async () => {
      const schema = fresh("gap");
      await migrate(sql, {
        schema,
        migrations: [...core, extra("0903_c.sql", "SELECT 3;")],
      });
      const error = await migrationError(
        migrate(sql, {
          schema,
          migrations: [
            ...core,
            extra("0902_b.sql", "SELECT 2;"),
            extra("0903_c.sql", "SELECT 3;"),
          ],
        }),
      );
      expect(error.code).toBe("migration_invalid");
      expect(error.migration).toBe("0902_b.sql");
    });

    it("applies nothing, not even the schema, when a migration fails", async () => {
      const schema = fresh("failing");
      await expect(
        migrate(sql, {
          schema,
          migrations: [
            ...core,
            extra("0902_broken.sql", "CREATE TABLE users (id int);"),
          ],
        }),
      ).rejects.toThrow(/already exists/);
      const [row] = await sql.query<{ present: boolean }>(
        `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1) AS "present"`,
        [schema],
      );
      expect(row?.present).toBe(false);
    });

    it("serialises concurrent runs so each migration applies once", async () => {
      const schema = fresh("concurrent");
      const results = await Promise.all(
        Array.from({ length: 6 }, () => migrate(sql, { schema })),
      );
      expect(
        results.filter((r) => r.applied.length === BUNDLED.length),
      ).toHaveLength(1);
      expect(
        results.filter((r) => r.existing.length === BUNDLED.length),
      ).toHaveLength(5);
      expect((await ledger(schema)).map((r) => r.name)).toEqual(BUNDLED);
    });

    it("waits for a run that holds the schema's lock", async () => {
      const schema = fresh("waiting");
      let release!: () => void;
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      let locked!: () => void;
      const holding = new Promise<void>((resolve) => {
        locked = resolve;
      });
      const holder = sql.transaction(async (tx) => {
        await tx.lock(migrationLockKey(schema));
        locked();
        await released;
      });
      await holding;
      let settled = false;
      const run = migrate(sql, { schema }).finally(() => {
        settled = true;
      });
      // Wait until the run is blocked on the advisory lock, not for a time.
      // A bigint advisory key shows in pg_locks as its high and low halves.
      const key = BigInt.asUintN(64, migrationLockKey(schema));
      const halves = [(key >> 32n).toString(), (key & 0xffffffffn).toString()];
      const deadline = Date.now() + 10_000;
      for (;;) {
        const [row] = await sql.query<{ waiting: number }>(
          `SELECT count(*)::int AS "waiting" FROM pg_locks
         WHERE locktype = 'advisory' AND NOT granted
           AND classid = $1::oid AND objid = $2::oid AND objsubid = 1
           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
          halves,
        );
        if ((row?.waiting ?? 0) > 0) break;
        if (Date.now() > deadline)
          throw new Error("the run never waited for the lock");
      }
      expect(settled).toBe(false);
      expect(
        (
          await sql.query<{ present: boolean }>(
            `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1) AS "present"`,
            [schema],
          )
        )[0]?.present,
      ).toBe(false);
      release();
      await holder;
      expect((await run).applied).toEqual(BUNDLED);
    });
  },
);
