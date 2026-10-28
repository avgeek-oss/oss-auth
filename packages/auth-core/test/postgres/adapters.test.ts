import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  advisoryLock,
  quoteIdent,
  type Sql,
} from "../../src/postgres/index.js";
import { adapters, databaseUrl, dropSchemas, uniqueSchema } from "./support.js";

describe.skipIf(!databaseUrl).each(adapters)("$name adapter", (adapter) => {
  let sql: Sql;
  let close: () => Promise<void>;
  // A schema of its own, so parallel test files never see the probe table.
  const schema = uniqueSchema("adapter");
  const probe = `${quoteIdent(schema)}.probe`;
  beforeAll(async () => {
    ({ sql, close } = adapter.open());
    await sql.query(`CREATE SCHEMA ${quoteIdent(schema)}`);
    await sql.query(`CREATE TABLE ${probe} (name text PRIMARY KEY)`);
  });
  afterAll(async () => {
    await dropSchemas(sql, [schema]);
    await close();
  });

  it("binds parameters and returns the agreed value types", async () => {
    const [row] = await sql.query(
      `SELECT $1::int4 AS "small", $2::int8 AS "big", $3::text AS "text",
              $4::boolean AS "flag", $5::text AS "missing",
              $6::timestamptz AS "at", $7::bytea AS "bytes",
              $8::text::jsonb AS "json", ARRAY['a', 'b']::text[] AS "list",
              1.50::numeric AS "decimal"`,
      [
        7,
        "9007199254740993",
        "héllo",
        true,
        null,
        new Date("2026-10-28T12:00:00.000Z"),
        Buffer.from([0, 255]),
        JSON.stringify({ a: [1, "x"] }),
      ],
    );
    expect(row).toEqual({
      small: 7,
      big: "9007199254740993",
      text: "héllo",
      flag: true,
      missing: null,
      at: new Date("2026-10-28T12:00:00.000Z"),
      bytes: Buffer.from([0, 255]),
      json: { a: [1, "x"] },
      list: ["a", "b"],
      decimal: "1.50",
    });
  });

  it("returns plain arrays", async () => {
    const rows = await sql.query("SELECT 1 AS n");
    expect(Object.getPrototypeOf(rows)).toBe(Array.prototype);
    expect(await sql.query("SELECT 1 AS n WHERE false")).toEqual([]);
  });

  it("runs several statements without parameters and returns the last rows", async () => {
    expect(
      await sql.query(`SELECT 1 AS "first"; SELECT 2 AS "second"`),
    ).toEqual([{ second: 2 }]);
    expect(
      await sql.query(
        `CREATE TEMP TABLE IF NOT EXISTS adapter_probe (n int); DROP TABLE adapter_probe`,
      ),
    ).toEqual([]);
  });

  it("commits a transaction and returns its value", async () => {
    const name = `commit-${adapter.name}-${Date.now()}`;
    const value = await sql.transaction(async (tx) => {
      await tx.query(`INSERT INTO ${probe} VALUES ($1)`, [name]);
      return "done";
    });
    expect(value).toBe("done");
    expect(
      await sql.query(`SELECT name FROM ${probe} WHERE name = $1`, [name]),
    ).toEqual([{ name }]);
    await sql.query(`DELETE FROM ${probe} WHERE name = $1`, [name]);
  });

  it("rolls back and rethrows when the function throws", async () => {
    const name = `rollback-${adapter.name}-${Date.now()}`;
    const failure = new Error("stop");
    await expect(
      sql.transaction(async (tx) => {
        await tx.query(`INSERT INTO ${probe} VALUES ($1)`, [name]);
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(
      await sql.query(`SELECT name FROM ${probe} WHERE name = $1`, [name]),
    ).toEqual([]);
  });

  it("leaves the pool usable after a statement fails inside a transaction", async () => {
    for (let i = 0; i < 10; i++)
      await expect(
        sql.transaction(async (tx) => {
          await tx.query("SELECT 1 / 0");
        }),
      ).rejects.toThrow(/division by zero/);
    expect(await sql.query("SELECT 1 AS ok")).toEqual([{ ok: 1 }]);
  });

  it("holds an advisory lock until the transaction ends", async () => {
    const key = -1234567890123456789n;
    const tryLock = async () => {
      const [row] = await sql.transaction((tx) =>
        tx.query<{ got: boolean }>(
          `SELECT pg_try_advisory_xact_lock($1::bigint) AS "got"`,
          [key.toString()],
        ),
      );
      return row?.got;
    };
    await sql.transaction(async (tx) => {
      await tx.lock(key);
      expect(await tryLock()).toBe(false);
    });
    expect(await tryLock()).toBe(true);
  });

  it("refuses lock keys outside the signed 64-bit range", async () => {
    await sql.transaction(async (tx) => {
      await expect(tx.lock(2n ** 63n)).rejects.toThrow(RangeError);
      await expect(advisoryLock(tx, -(2n ** 63n) - 1n)).rejects.toThrow(
        RangeError,
      );
      await tx.lock(-(2n ** 63n));
      await tx.lock(2n ** 63n - 1n);
    });
  });
});
