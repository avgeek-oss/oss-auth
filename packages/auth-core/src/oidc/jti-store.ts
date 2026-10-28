import { quoteIdent } from "../identifiers.js";
import type { SqlQueryable } from "../postgres/sql.js";
import type { JtiStore } from "./logout.js";

/**
 * A {@link JtiStore} in `<schema>.logout_jtis`. Each call also deletes up to
 * 100 expired ids, so the table stays small without a separate job.
 */
export function postgresJtiStore(sql: SqlQueryable, schema: string): JtiStore {
  const table = `${quoteIdent(schema)}.logout_jtis`;
  return {
    async remember(issuer, jti, expiresAt) {
      await sql.query(
        `DELETE FROM ${table} WHERE ctid IN (
           SELECT ctid FROM ${table} WHERE expires_at < now() LIMIT 100)`,
      );
      const rows = await sql.query(
        `INSERT INTO ${table} (iss, jti, expires_at) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING RETURNING jti`,
        [issuer, jti, expiresAt],
      );
      return rows.length === 1;
    },
  };
}
