import { randomBytes, randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { generateApiKeyId } from "../../src/api-keys/format.js";
import {
  authJobsLockKey,
  runAuthJobs,
  runAuthWorker,
  sweepApiKeys,
  sweepSessions,
  type AuthJobsSummary,
} from "../../src/jobs/index.js";
import { migrate, quoteIdent, type Sql } from "../../src/postgres/index.js";
import {
  adapters,
  databaseUrl,
  dropSchemas,
  uniqueSchema,
} from "../postgres/support.js";

const NOW = new Date("2026-06-01T12:00:00.000Z");
const at = (days: number) => new Date(NOW.getTime() + days * 86400_000);
const hex = () => randomBytes(32).toString("hex");
const CHALLENGE = "c".repeat(43);

describe.skipIf(!databaseUrl).each(adapters)(
  "auth jobs with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    const schema = uniqueSchema("jobs");
    const t = (table: string) => `${quoteIdent(schema)}.${table}`;
    const config = { schema };
    let userId = "";

    beforeAll(async () => {
      ({ sql, close } = adapter.open());
      await migrate(sql, { schema });
    });
    afterAll(async () => {
      await dropSchemas(sql, [schema]);
      await close();
    });
    beforeEach(async () => {
      for (const table of [
        "rate_limit_buckets",
        "logout_jtis",
        "oauth_tokens",
        "oauth_codes",
        "oauth_requests",
        "oauth_grants",
        "oauth_clients",
        "api_keys",
        "sessions",
        "users",
      ])
        await sql.query(`DELETE FROM ${t(table)}`);
      const [user] = await sql.query<{ id: string }>(
        `INSERT INTO ${t("users")} (iss, sub, role, created_at)
       VALUES ('https://idp.example', $1, 'admin', $2) RETURNING id`,
        [randomUUID(), at(-60)],
      );
      userId = user?.id ?? "";
    });

    const count = async (table: string) =>
      Number(
        (
          await sql.query<{ n: string }>(
            `SELECT count(*) AS "n" FROM ${t(table)}`,
          )
        )[0]?.n,
      );
    const remaining = async (table: string, column: string) =>
      (
        await sql.query<Record<string, string>>(
          `SELECT ${column} AS "v" FROM ${t(table)} ORDER BY 1`,
        )
      ).map((row) => row.v);

    async function session(
      name: string,
      created: number,
      fields: { expires: number; idle: number; revoked?: number },
    ) {
      await sql.query(
        `INSERT INTO ${t("sessions")}
         (id_hash, user_id, created_at, authenticated_at, expires_at, idle_expires_at, revoked_at, provider_sid)
       VALUES ($1, $2, $3, $3, $4, $5, $6, $7)`,
        [
          hex(),
          userId,
          at(created),
          at(fields.expires),
          at(fields.idle),
          fields.revoked === undefined ? null : at(fields.revoked),
          name,
        ],
      );
    }

    async function apiKey(fields: {
      created: number;
      expires?: number | null;
      revoked?: number;
      replacedBy?: string;
      grace?: number;
    }): Promise<string> {
      const id = generateApiKeyId();
      await sql.query(
        `INSERT INTO ${t("api_keys")} (id, user_id, name, ceiling, secret_hash, created_at, expires_at, revoked_at)
       VALUES ($1, $2, 'k', 'viewer', $3, $4, $5, $6)`,
        [
          id,
          userId,
          hex(),
          at(fields.created),
          fields.expires === null || fields.expires === undefined
            ? null
            : at(fields.expires),
          fields.revoked === undefined ? null : at(fields.revoked),
        ],
      );
      return id;
    }

    async function grant(revoked?: number): Promise<string> {
      await sql.query(
        `INSERT INTO ${t("oauth_clients")} (client_id, kind, client_name, redirect_uris)
       VALUES ('cli', 'configured', 'CLI', ARRAY['http://127.0.0.1/cb'])
       ON CONFLICT DO NOTHING`,
      );
      const [row] = await sql.query<{ id: string }>(
        `INSERT INTO ${t("oauth_grants")} (user_id, client_id, client_name, ceiling, resources, created_at, revoked_at)
       VALUES ($1, 'cli', 'CLI', 'viewer', ARRAY['https://api.example/mcp'], $2, $3) RETURNING id`,
        [userId, at(-30), revoked === undefined ? null : at(revoked)],
      );
      return row?.id ?? "";
    }

    async function token(
      grantId: string,
      kind: "access" | "refresh",
      fields: { created: number; expires: number; revoked?: number },
    ) {
      await sql.query(
        `INSERT INTO ${t("oauth_tokens")}
         (token_hash, kind, grant_id, family_id, resource, created_at, expires_at, family_expires_at, revoked_at)
       VALUES ($1, $2, $3, $4, 'https://api.example/mcp', $5, $6, $7, $8)`,
        [
          hex(),
          kind,
          grantId,
          randomUUID(),
          at(fields.created),
          at(fields.expires),
          kind === "refresh" ? at(fields.expires + 60) : null,
          fields.revoked === undefined ? null : at(fields.revoked),
        ],
      );
    }

    it("deletes what has ended, keeps what is live or within retention, and reports counts", async () => {
      // Sessions: live; absolute expiry passed; revoked 8 and 6 days ago;
      // idle for 8 days and for 1 day.
      await session("live", -1, { expires: 1, idle: 0.5 });
      await session("expired", -2, { expires: -0.01, idle: -0.5 });
      await session("revoked-8d", -9, { expires: 1, idle: 0.5, revoked: -8 });
      await session("revoked-6d", -7, { expires: 1, idle: 0.5, revoked: -6 });
      await session("idle-8d", -9, { expires: 1, idle: -8 });
      await session("idle-1d", -2, { expires: 1, idle: -1 });

      await sql.query(
        `INSERT INTO ${t("logout_jtis")} (iss, jti, expires_at)
       VALUES ('i', 'old', $1), ('i', 'live', $2)`,
        [at(-0.01), at(0.01)],
      );

      // API keys: live, expired and revoked within and past retention, and
      // a rotation chain whose both ends are past it.
      const live = await apiKey({ created: -30, expires: 30 });
      const neverExpires = await apiKey({ created: -30, expires: null });
      await apiKey({ created: -30, expires: -8 });
      const recentlyExpired = await apiKey({ created: -30, expires: -6 });
      await apiKey({ created: -30, expires: 30, revoked: -8 });
      const newer = await apiKey({ created: -20, expires: 30, revoked: -8 });
      const older = await apiKey({ created: -30, expires: 30 });
      await sql.query(
        `UPDATE ${t("api_keys")} SET replaced_by = $2, grace_until = $3 WHERE id = $1`,
        [older, newer, at(-9)],
      );

      // OAuth: a live grant with expired and live tokens, codes and
      // requests; a grant revoked 8 days ago (its tokens go with it).
      const liveGrant = await grant();
      const oldGrant = await grant(-8);
      await token(liveGrant, "access", { created: -3, expires: -2 });
      await token(liveGrant, "access", { created: -0.5, expires: -0.4 });
      await token(liveGrant, "refresh", { created: -3, expires: 20 });
      await token(liveGrant, "refresh", {
        created: -20,
        expires: 1,
        revoked: -8,
      });
      await token(oldGrant, "refresh", { created: -20, expires: 20 });
      await sql.query(
        `INSERT INTO ${t("oauth_codes")} (code_hash, grant_id, client_id, redirect_uri, resource, code_challenge, created_at, expires_at, consumed_at)
       VALUES ($1, $2, 'cli', 'http://127.0.0.1/cb', 'r', $5, $3, $4, $3),
              ($6, $2, 'cli', 'http://127.0.0.1/cb', 'r', $5, $7, $8, $7)`,
        [
          hex(),
          liveGrant,
          at(-2),
          at(-1.99),
          CHALLENGE,
          hex(),
          at(-0.001),
          at(0.001),
        ],
      );
      await sql.query(
        `INSERT INTO ${t("oauth_requests")} (id_hash, client_id, redirect_uri, resource, code_challenge, created_at, expires_at)
       VALUES ($1, 'cli', 'http://127.0.0.1/cb', 'r', $4, $2, $3), ($5, 'cli', 'http://127.0.0.1/cb', 'r', $4, $6, $7)`,
        [hex(), at(-2), at(-1.99), CHALLENGE, hex(), at(-0.5), at(-0.49)],
      );

      await sql.query(
        `INSERT INTO ${t("rate_limit_buckets")} (key_hash, tat, allowed, expires_at)
       VALUES ($1, $2, true, $2), ($3, $4, true, $4)`,
        [hex(), at(-0.01), hex(), at(0.01)],
      );

      const summary = await runAuthJobs({ sql, config, now: () => NOW });
      expect(summary).toMatchObject({
        complete: true,
        deleted: {
          sessions: 3,
          logoutJtis: 1,
          oauthGrants: 1,
          oauthRequests: 1,
          oauthCodes: 1,
          oauthTokens: 2,
          apiKeys: 4,
          rateLimitBuckets: 1,
        },
      } satisfies Partial<AuthJobsSummary>);
      expect(await remaining("sessions", "provider_sid")).toEqual([
        "idle-1d",
        "live",
        "revoked-6d",
      ]);
      expect(await remaining("logout_jtis", "jti")).toEqual(["live"]);
      expect(new Set(await remaining("api_keys", "id"))).toEqual(
        new Set([live, neverExpires, recentlyExpired]),
      );
      expect(await count("oauth_grants")).toBe(1);
      // The live grant's fresh access token and live refresh token remain;
      // the old grant's token went with it.
      expect(await count("oauth_tokens")).toBe(2);
      expect(await count("oauth_codes")).toBe(1);
      expect(await count("oauth_requests")).toBe(1);
      expect(await count("rate_limit_buckets")).toBe(1);

      // Nothing left: a second run deletes nothing.
      const again = await runAuthJobs({ sql, config, now: () => NOW });
      expect(Object.values(again?.deleted ?? {}).every((n) => n === 0)).toBe(
        true,
      );
    });

    it("uses the retention given", async () => {
      await session("revoked-3d", -4, { expires: 1, idle: 0.5, revoked: -3 });
      expect(
        (await sweepSessions({ sql, config, now: () => NOW, retentionDays: 7 }))
          .deleted,
      ).toBe(0);
      expect(
        (await sweepSessions({ sql, config, now: () => NOW, retentionDays: 2 }))
          .deleted,
      ).toBe(1);
    });

    it("deletes in bounded batches and stops at the deadline", async () => {
      for (let i = 0; i < 25; i++) await apiKey({ created: -30, expires: -10 });
      const statements: string[] = [];
      const counting: Sql = {
        query: (text, params) => {
          if (text.startsWith("DELETE")) statements.push(text);
          return sql.query(text, params);
        },
        transaction: (work) => sql.transaction(work),
      };
      expect(
        await sweepApiKeys({
          sql: counting,
          config,
          now: () => NOW,
          batchSize: 10,
        }),
      ).toEqual({ deleted: 25, complete: true });
      // 10, 10, 5, then one that finds nothing.
      expect(statements).toHaveLength(4);

      for (let i = 0; i < 25; i++) await apiKey({ created: -30, expires: -10 });
      expect(
        await sweepApiKeys({
          sql,
          config,
          now: () => NOW,
          batchSize: 10,
          deadline: Date.now() - 1,
        }),
      ).toEqual({ deleted: 10, complete: false });
      const budget = await runAuthJobs({
        sql,
        config,
        now: () => NOW,
        batchSize: 10,
        timeBudgetSeconds: 0,
      });
      expect(budget?.complete).toBe(false);
      expect(await count("api_keys")).toBeGreaterThan(0);
      await runAuthJobs({ sql, config, now: () => NOW });
      expect(await count("api_keys")).toBe(0);
    });

    it("runs exclusively when asked: a second run while one holds the lock does nothing", async () => {
      await session("expired", -2, { expires: -0.01, idle: -0.5 });
      let release = () => {};
      const held = new Promise<void>((resolve) => (release = resolve));
      const holder = sql.transaction(async (tx) => {
        await tx.query(`SELECT pg_advisory_xact_lock($1::bigint)`, [
          authJobsLockKey(schema).toString(),
        ]);
        await held;
      });
      // Let the holder take the lock.
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(
        await runAuthJobs({ sql, config, now: () => NOW, exclusive: true }),
      ).toBeNull();
      release();
      await holder;
      expect(
        (await runAuthJobs({ sql, config, now: () => NOW, exclusive: true }))
          ?.deleted.sessions,
      ).toBe(1);
    });

    it("runs as a worker until aborted, reporting errors without stopping", async () => {
      await session("expired", -2, { expires: -0.01, idle: -0.5 });
      const stop = new AbortController();
      const runs: (AuthJobsSummary | null)[] = [];
      const errors: unknown[] = [];
      let failures = 1;
      const flaky: Sql = {
        query: (text, params) => {
          if (text.startsWith("DELETE") && failures > 0) {
            failures--;
            return Promise.reject(new Error("connection reset"));
          }
          return sql.query(text, params);
        },
        transaction: (work) => sql.transaction(work),
      };
      const worker = runAuthWorker({
        sql: flaky,
        config,
        now: () => NOW,
        intervalSeconds: 0.05,
        signal: stop.signal,
        onRun: (summary) => {
          runs.push(summary);
          if (runs.length === 2) stop.abort();
        },
        onError: (error) => errors.push(error),
      });
      await worker;
      expect(errors).toHaveLength(1);
      expect((errors[0] as Error).message).toBe("connection reset");
      expect(runs[0]?.deleted.sessions).toBe(1);
      expect(runs[1]?.deleted.sessions).toBe(0);
      expect(await count("sessions")).toBe(0);
      // Aborted before it starts: returns at once.
      await runAuthWorker({ sql, config, signal: AbortSignal.abort() });
      await expect(
        runAuthWorker({ sql, config, signal: stop.signal, intervalSeconds: 0 }),
      ).rejects.toThrow(RangeError);
    });
  },
);
