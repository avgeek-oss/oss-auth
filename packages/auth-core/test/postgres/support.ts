import { randomBytes } from "node:crypto";
import pg from "pg";
import postgres from "postgres";
import {
  fromPg,
  fromPostgresJs,
  quoteIdent,
  type Sql,
} from "../../src/postgres/index.js";

/**
 * The Postgres suites run when AUTH_TEST_DATABASE_URL points at a disposable
 * database. Each test works in schemas with random names and drops them.
 */
export const databaseUrl = process.env.AUTH_TEST_DATABASE_URL;

/** A driver under test: the same suite runs once per adapter. */
export interface Adapter {
  readonly name: string;
  open(): { sql: Sql; close: () => Promise<void> };
}

export const adapters: readonly Adapter[] = [
  {
    name: "pg",
    open() {
      const pool = new pg.Pool({ connectionString: databaseUrl, max: 8 });
      return { sql: fromPg(pool), close: () => pool.end() };
    },
  },
  {
    name: "postgres.js",
    open() {
      const client = postgres(databaseUrl ?? "", {
        max: 8,
        onnotice: () => {},
      });
      return { sql: fromPostgresJs(client), close: () => client.end() };
    },
  },
  {
    // Mill and Posted configure their instance this way.
    name: "postgres.js with postgres.camel",
    open() {
      const client = postgres(databaseUrl ?? "", {
        max: 8,
        onnotice: () => {},
        transform: postgres.camel,
      });
      return { sql: fromPostgresJs(client), close: () => client.end() };
    },
  },
];

/** A fresh schema name that needs quoting, as a hostile operator might pick. */
export function uniqueSchema(label: string): string {
  return `Auth ${label} "${randomBytes(4).toString("hex")}"`;
}

/** Drops schemas made by a test. */
export async function dropSchemas(
  sql: Sql,
  schemas: Iterable<string>,
): Promise<void> {
  for (const schema of schemas)
    await sql.query(`DROP SCHEMA IF EXISTS ${quoteIdent(schema)} CASCADE`);
}
