import { createHash } from "node:crypto";
import {
  DEFAULT_RETENTION_DAYS,
  DEFAULT_SWEEP_BATCH_SIZE,
  sweepApiKeys,
  sweepLogoutJtis,
  sweepOAuthCodes,
  sweepOAuthGrants,
  sweepOAuthRequests,
  sweepOAuthTokens,
  sweepRateLimitBuckets,
  sweepSessions,
  type SweepOptions,
  type SweepResult,
} from "./sweeps.js";

export {
  DEFAULT_RETENTION_DAYS,
  DEFAULT_SWEEP_BATCH_SIZE,
  sweepApiKeys,
  sweepLogoutJtis,
  sweepOAuthCodes,
  sweepOAuthGrants,
  sweepOAuthRequests,
  sweepOAuthTokens,
  sweepRateLimitBuckets,
  sweepSessions,
  type SweepOptions,
  type SweepResult,
};

/** Options for {@link runAuthJobs}. */
export interface AuthJobsOptions extends Omit<SweepOptions, "deadline"> {
  /**
   * How long one run may take, in seconds. Sweeps stop starting batches
   * after it and report `complete: false`; the next run continues. Default
   * 60.
   */
  readonly timeBudgetSeconds?: number;
  /**
   * Run only if no other run against this schema is in progress, holding a
   * Postgres advisory lock for the run's duration (on a second connection
   * from the pool). When another holds it, resolves to `null` at once.
   * Default false: a job runner that already schedules one run at a time
   * does not need it.
   */
  readonly exclusive?: boolean;
}

/** What one {@link runAuthJobs} run deleted. */
export interface AuthJobsSummary {
  /** Rows deleted per sweep. */
  readonly deleted: {
    readonly sessions: number;
    readonly logoutJtis: number;
    readonly oauthGrants: number;
    readonly oauthRequests: number;
    readonly oauthCodes: number;
    readonly oauthTokens: number;
    readonly apiKeys: number;
    readonly rateLimitBuckets: number;
  };
  /** False when the time budget ran out with rows left. */
  readonly complete: boolean;
  readonly durationMs: number;
}

/** The advisory lock key of auth jobs for `schema`. */
export function authJobsLockKey(schema: string): bigint {
  return createHash("sha256")
    .update(`avgeek-oss/auth-core:jobs:${schema}`)
    .digest()
    .readBigInt64BE(0);
}

/**
 * Runs every auth-core sweep once, in bounded batches, and returns what
 * each deleted. Safe to run concurrently with traffic and with itself.
 * Call it from the app's own job runner, or use {@link runAuthWorker}.
 *
 * Sign-in transactions need no sweep: they live in a cookie, not the
 * database.
 */
export async function runAuthJobs(
  options: AuthJobsOptions,
): Promise<AuthJobsSummary | null> {
  if (options.exclusive) {
    const { exclusive: _, ...rest } = options;
    return options.sql.transaction(async (tx) => {
      const [lock] = await tx.query<{ locked: boolean }>(
        `SELECT pg_try_advisory_xact_lock($1::bigint) AS "locked"`,
        [authJobsLockKey(options.config.schema).toString()],
      );
      // The transaction only holds the lock; the sweeps run on other
      // connections, each batch committed on its own.
      return lock?.locked ? runAuthJobs(rest) : null;
    });
  }
  const started = Date.now();
  const budget = options.timeBudgetSeconds ?? 60;
  const sweep: SweepOptions = { ...options, deadline: started + budget * 1000 };
  const results: [keyof AuthJobsSummary["deleted"], SweepResult][] = [];
  // Grants first: deleting one takes its codes and tokens with it.
  for (const [name, run] of [
    ["sessions", sweepSessions],
    ["logoutJtis", sweepLogoutJtis],
    ["oauthGrants", sweepOAuthGrants],
    ["oauthRequests", sweepOAuthRequests],
    ["oauthCodes", sweepOAuthCodes],
    ["oauthTokens", sweepOAuthTokens],
    ["apiKeys", sweepApiKeys],
    ["rateLimitBuckets", sweepRateLimitBuckets],
  ] as const) {
    if (Date.now() >= (sweep.deadline ?? Infinity)) {
      results.push([name, { deleted: 0, complete: false }]);
      continue;
    }
    results.push([name, await run(sweep)]);
  }
  return {
    deleted: Object.fromEntries(
      results.map(([name, result]) => [name, result.deleted]),
    ) as AuthJobsSummary["deleted"],
    complete: results.every(([, result]) => result.complete),
    durationMs: Date.now() - started,
  };
}

/** Options for {@link runAuthWorker}. */
export interface AuthWorkerOptions extends Omit<AuthJobsOptions, "exclusive"> {
  /** Seconds between runs, give or take 10%. Default 300. */
  readonly intervalSeconds?: number;
  /** Stops the loop. The run in progress finishes first. */
  readonly signal: AbortSignal;
  /** Called with each run's summary, or `null` when another replica ran. */
  readonly onRun?: (summary: AuthJobsSummary | null) => void;
  /**
   * Called when a run fails. The loop carries on with the next run.
   * Default: a line on standard error.
   */
  readonly onError?: (error: unknown) => void;
}

/** Waits `ms`, or less if `signal` aborts. Never rejects. */
function pause(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });
}

/**
 * Runs {@link runAuthJobs} in this process every `intervalSeconds` (with
 * 10% jitter, and the first run within the first tenth of an interval),
 * for apps without a job runner. Every replica can run it: an advisory lock
 * makes one sweep at a time. Resolves once `signal` aborts and the current
 * run has finished.
 *
 * ```ts
 * const stop = new AbortController();
 * const worker = runAuthWorker({ sql, config, signal: stop.signal });
 * process.on("SIGTERM", () => stop.abort());
 * ```
 */
export async function runAuthWorker(options: AuthWorkerOptions): Promise<void> {
  const { signal, onRun, onError, intervalSeconds = 300, ...jobs } = options;
  if (!(intervalSeconds > 0))
    throw new RangeError("intervalSeconds must be more than 0.");
  const interval = intervalSeconds * 1000;
  const report =
    onError ??
    ((error: unknown) =>
      process.stderr.write(
        `auth jobs failed: ${error instanceof Error ? error.message : String(error)}\n`,
      ));
  await pause(Math.random() * interval * 0.1, signal);
  while (!signal.aborted) {
    try {
      const summary = await runAuthJobs({ ...jobs, exclusive: true });
      onRun?.(summary);
    } catch (error) {
      try {
        report(error);
      } catch {
        // A failing reporter must not stop the loop either.
      }
    }
    await pause(interval * (0.9 + Math.random() * 0.2), signal);
  }
}
