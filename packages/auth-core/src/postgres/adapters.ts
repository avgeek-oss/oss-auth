import {
  advisoryLock,
  type Row,
  type Sql,
  type SqlQueryable,
  type SqlTransaction,
} from "./sql.js";

// The adapters describe the drivers structurally, so this package's types do
// not import `pg` or `postgres`: an app installs only the driver it uses.

/** The part of a `pg` query result the adapter reads. */
export interface PgResultLike {
  readonly rows: readonly unknown[];
}

/** The part of a `pg` `PoolClient` the adapter uses. */
export interface PgClientLike {
  query(
    text: string,
    values?: unknown[],
  ): Promise<PgResultLike | PgResultLike[]>;
  release(destroy?: boolean | Error): void;
}

/** The part of a `pg` `Pool` the adapter uses. Pass the app's pool. */
export interface PgPoolLike {
  query(
    text: string,
    values?: unknown[],
  ): Promise<PgResultLike | PgResultLike[]>;
  connect(): Promise<PgClientLike>;
}

/** The part of a Postgres.js `sql` or transaction the adapter uses. */
export interface PostgresJsQueryLike {
  unsafe(query: string, parameters?: unknown[]): PromiseLike<unknown>;
}

/** The part of a Postgres.js `sql` instance the adapter uses. */
export interface PostgresJsLike extends PostgresJsQueryLike {
  begin(
    fn: (tx: PostgresJsQueryLike) => Promise<unknown>,
  ): PromiseLike<unknown>;
}

function lastRows<T>(result: PgResultLike | PgResultLike[]): T[] {
  // pg returns one result per statement for a multi-statement string.
  const last = Array.isArray(result) ? result.at(-1) : result;
  return last === undefined ? [] : ([...last.rows] as T[]);
}

function pgQueryable(target: Pick<PgPoolLike, "query">): SqlQueryable["query"] {
  return async <T extends Row = Row>(
    text: string,
    params?: readonly unknown[],
  ) =>
    lastRows<T>(
      await target.query(text, params === undefined ? undefined : [...params]),
    );
}

/**
 * Wraps a node-postgres `Pool` as a {@link Sql}.
 *
 * Transactions check out one client, run `BEGIN` and `COMMIT`, and release
 * it. A client whose `ROLLBACK` fails is destroyed rather than returned to
 * the pool.
 */
export function fromPg(pool: PgPoolLike): Sql {
  return {
    query: pgQueryable(pool),
    async transaction<R>(fn: (tx: SqlTransaction) => Promise<R>): Promise<R> {
      const client = await pool.connect();
      const tx: SqlTransaction = {
        query: pgQueryable(client),
        lock: (key) => advisoryLock(tx, key),
      };
      let destroy: Error | undefined;
      try {
        await client.query("BEGIN");
        const result = await fn(tx);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        try {
          await client.query("ROLLBACK");
        } catch (rollbackError) {
          destroy =
            rollbackError instanceof Error
              ? rollbackError
              : new Error(String(rollbackError));
        }
        throw error;
      } finally {
        client.release(destroy);
      }
    },
  };
}

function postgresJsQueryable(
  target: PostgresJsQueryLike,
): SqlQueryable["query"] {
  return async <T extends Row = Row>(
    text: string,
    params?: readonly unknown[],
  ) => {
    const result = (await (params === undefined
      ? target.unsafe(text)
      : target.unsafe(text, [...params]))) as unknown[];
    // Postgres.js returns an array of results for a multi-statement string.
    const multi =
      params === undefined &&
      result.length > 0 &&
      result.every((entry) => Array.isArray(entry));
    const rows = multi ? (result.at(-1) as unknown[]) : result;
    return [...rows] as T[];
  };
}

/**
 * Wraps a Postgres.js `sql` instance as a {@link Sql}. Transactions use
 * `sql.begin`.
 *
 * Column-name transforms such as `postgres.camel` apply to these queries
 * too. auth-core aliases every column it reads to a camelCase name, which
 * those transforms leave unchanged.
 */
export function fromPostgresJs(sql: PostgresJsLike): Sql {
  return {
    query: postgresJsQueryable(sql),
    async transaction<R>(fn: (tx: SqlTransaction) => Promise<R>): Promise<R> {
      return (await sql.begin(async (raw) => {
        const tx: SqlTransaction = {
          query: postgresJsQueryable(raw),
          lock: (key) => advisoryLock(tx, key),
        };
        return fn(tx);
      })) as R;
    },
  };
}
