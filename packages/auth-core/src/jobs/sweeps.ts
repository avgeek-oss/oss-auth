import type { AuthConfig } from "../config.js";
import { quoteIdent } from "../identifiers.js";
import type { Sql } from "../postgres/sql.js";

/** Options every sweep takes. */
export interface SweepOptions {
  readonly sql: Sql;
  /** Uses `schema`. */
  readonly config: Pick<AuthConfig, "schema">;
  /** The current time. Defaults to the database's `now()`. For tests. */
  readonly now?: () => Date;
  /** Rows deleted per statement. Default 1000. */
  readonly batchSize?: number;
  /**
   * When to stop starting new batches, as `Date.now()` milliseconds. A
   * sweep that runs out of time says so with `complete: false`; the next run
   * carries on. Default: no limit.
   */
  readonly deadline?: number;
  /**
   * How long revoked sessions, API keys, grants and tokens are kept after
   * they end, in days, for support questions and the connected-apps
   * history. Default 7.
   */
  readonly retentionDays?: number;
}

/** What one sweep did. */
export interface SweepResult {
  /** Rows deleted. */
  readonly deleted: number;
  /** False when the deadline stopped it with rows left to delete. */
  readonly complete: boolean;
}

/** The default number of rows each statement deletes. */
export const DEFAULT_SWEEP_BATCH_SIZE = 1000;

/** The default retention of revoked credentials, in days. */
export const DEFAULT_RETENTION_DAYS = 7;

// $1 is always the clock (null means the database's now()), $2 the batch
// size and $3 the retention in days.
const T = "coalesce($1::timestamptz, now())";
const RETAINED = `${T} - $3::double precision * interval '1 day'`;

/**
 * Deletes the rows of `table` matching `where` (written against alias `x`),
 * `batchSize` at a time, each batch its own statement, until a batch finds
 * none or the deadline passes. Rows another sweep has locked are skipped, so two
 * sweeps never wait on each other.
 */
async function deleteInBatches(
  options: SweepOptions,
  table: string,
  keyColumns: readonly string[],
  where: string,
): Promise<SweepResult> {
  const batchSize = options.batchSize ?? DEFAULT_SWEEP_BATCH_SIZE;
  if (!Number.isInteger(batchSize) || batchSize < 1)
    throw new RangeError("batchSize must be a positive integer.");
  const retention = options.retentionDays ?? DEFAULT_RETENTION_DAYS;
  if (!Number.isFinite(retention) || retention < 0)
    throw new RangeError("retentionDays must be zero or more.");
  const qualified = `${quoteIdent(options.config.schema)}.${table}`;
  const target = keyColumns.map((c) => `d.${c}`).join(", ");
  const source = keyColumns.map((c) => `x.${c}`).join(", ");
  let deleted = 0;
  for (;;) {
    const rows = await options.sql.query(
      `DELETE FROM ${qualified} d WHERE (${target}) IN (
         SELECT ${source} FROM ${qualified} x
         WHERE (${where}) AND $3::double precision >= 0
         LIMIT $2 FOR UPDATE SKIP LOCKED)
       RETURNING 1`,
      [options.now?.() ?? null, batchSize, retention],
    );
    deleted += rows.length;
    // Until a batch finds nothing: deleting one row can free another, such
    // as the key an older, rotated key named as its replacement.
    if (rows.length === 0) return { deleted, complete: true };
    if (options.deadline !== undefined && Date.now() >= options.deadline)
      return { deleted, complete: false };
  }
}

/**
 * Sessions past their absolute expiry, past their idle expiry for longer
 * than the retention, or revoked longer ago than the retention.
 */
export function sweepSessions(options: SweepOptions): Promise<SweepResult> {
  return deleteInBatches(
    options,
    "sessions",
    ["id_hash"],
    `x.expires_at < ${T} OR x.idle_expires_at < ${RETAINED}
     OR x.revoked_at < ${RETAINED}`,
  );
}

/** Back-channel logout token ids past the token's expiry. */
export function sweepLogoutJtis(options: SweepOptions): Promise<SweepResult> {
  return deleteInBatches(
    options,
    "logout_jtis",
    ["iss", "jti"],
    `x.expires_at < ${T}`,
  );
}

/**
 * Consent requests that expired more than a day ago, decided or not. They
 * live ten minutes; the day keeps them for a slow consent page's error.
 */
export function sweepOAuthRequests(
  options: SweepOptions,
): Promise<SweepResult> {
  return deleteInBatches(
    options,
    "oauth_requests",
    ["id_hash"],
    `x.expires_at < ${T} - interval '1 day'`,
  );
}

/**
 * Authorization codes that expired more than a day ago. A consumed code is
 * kept until then, so that a replay of it is still recognised and revokes
 * the grant.
 */
export function sweepOAuthCodes(options: SweepOptions): Promise<SweepResult> {
  return deleteInBatches(
    options,
    "oauth_codes",
    ["code_hash"],
    `x.expires_at < ${T} - interval '1 day'`,
  );
}

/**
 * Access and refresh tokens that expired more than a day ago (a refresh
 * token's expiry is its idle limit, never past its family's absolute one),
 * and revoked tokens past the retention. Rotated refresh tokens are kept
 * until they expire, so that reuse is still detected.
 */
export function sweepOAuthTokens(options: SweepOptions): Promise<SweepResult> {
  return deleteInBatches(
    options,
    "oauth_tokens",
    ["token_hash"],
    `x.expires_at < ${T} - interval '1 day' OR x.revoked_at < ${RETAINED}`,
  );
}

/**
 * Grants revoked longer ago than the retention, with their codes and
 * tokens (by cascade).
 */
export function sweepOAuthGrants(options: SweepOptions): Promise<SweepResult> {
  return deleteInBatches(
    options,
    "oauth_grants",
    ["id"],
    `x.revoked_at < ${RETAINED}`,
  );
}

/**
 * API keys revoked, expired or past their rotation grace for longer than
 * the retention. A key that a kept key names as its replacement waits for
 * that one, so rotation chains go oldest first.
 */
export function sweepApiKeys(options: SweepOptions): Promise<SweepResult> {
  const keys = `${quoteIdent(options.config.schema)}.api_keys`;
  return deleteInBatches(
    options,
    "api_keys",
    ["id"],
    `(x.revoked_at < ${RETAINED} OR x.expires_at < ${RETAINED}
      OR x.grace_until < ${RETAINED})
     AND NOT EXISTS (SELECT 1 FROM ${keys} o WHERE o.replaced_by = x.id)`,
  );
}

/** Rate limit buckets that have emptied. */
export function sweepRateLimitBuckets(
  options: SweepOptions,
): Promise<SweepResult> {
  return deleteInBatches(
    options,
    "rate_limit_buckets",
    ["key_hash"],
    `x.expires_at < ${T}`,
  );
}
