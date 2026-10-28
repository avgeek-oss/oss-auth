/** A result row: column name to value. */
export type Row = Record<string, unknown>;

/**
 * Runs SQL. Implemented by {@link fromPg} and {@link fromPostgresJs}, or by
 * the app for any other driver.
 *
 * Both adapters return values as their driver parses them, which agree for
 * the types auth-core uses: `timestamptz` as `Date`, `bigint` and `numeric`
 * as strings, `bytea` as `Buffer`, `jsonb` and arrays parsed. Pass JSON
 * parameters as text and cast them (`$1::text::jsonb`): the drivers encode
 * objects and arrays differently.
 */
export interface SqlQueryable {
  /**
   * Runs `text` with `$1`, `$2`… bound to `params` and returns the rows.
   * Without `params`, `text` may hold several statements; the rows of the
   * last one are returned.
   */
  query<T extends object = Row>(
    text: string,
    params?: readonly unknown[],
  ): Promise<T[]>;
}

/** A connection inside an open transaction. */
export interface SqlTransaction extends SqlQueryable {
  /**
   * Takes the transaction-scoped advisory lock `key`
   * (`pg_advisory_xact_lock`), waiting while another transaction holds it.
   * It is released when the transaction ends.
   */
  lock(key: bigint): Promise<void>;
}

/** A connection pool. */
export interface Sql extends SqlQueryable {
  /**
   * Runs `fn` in a transaction on one connection. Commits when `fn`
   * resolves and rolls back when it throws, rethrowing the error.
   */
  transaction<R>(fn: (tx: SqlTransaction) => Promise<R>): Promise<R>;
}

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;

/** Takes an advisory lock through `query`; shared by the adapters. */
export async function advisoryLock(
  tx: SqlQueryable,
  key: bigint,
): Promise<void> {
  if (typeof key !== "bigint" || key < INT64_MIN || key > INT64_MAX)
    throw new RangeError("Advisory lock keys must be signed 64-bit integers.");
  await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [key.toString()]);
}
