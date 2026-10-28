import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadAuthConfig } from "../src/index.js";
import { postgresJtiStore } from "../src/oidc/index.js";
import { migrate, quoteIdent, type Sql } from "../src/postgres/index.js";
import { createSessions, type Sessions } from "../src/sessions/index.js";
import {
  adapters,
  databaseUrl,
  dropSchemas,
  uniqueSchema,
} from "./postgres/support.js";

const ISS = "https://auth.example.com/application/o/posted/";
const HOUR = 3600;

describe.skipIf(!databaseUrl).each(adapters)(
  "sessions with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    const schema = uniqueSchema("sessions");
    const t = (table: string) => `${quoteIdent(schema)}.${table}`;
    const config = loadAuthConfig("posted", {
      POSTED_SECRET: "s".repeat(32),
      POSTED_OIDC_ISSUER: ISS,
      POSTED_OIDC_CLIENT_ID: "posted",
      POSTED_OIDC_CLIENT_SECRET: "x",
      POSTED_WEB_ORIGIN: "https://posted.example.com",
      POSTED_API_ORIGIN: "https://api.posted.example.com",
      POSTED_SESSION_MAX_AGE: "12h",
      POSTED_SESSION_IDLE_TIMEOUT: "2h",
      POSTED_AUTH_SCHEMA: schema,
    });
    // A clock the tests move; it starts at the database's present.
    let now = new Date();
    const advance = (seconds: number) => {
      now = new Date(now.getTime() + seconds * 1000);
    };
    let sessions: Sessions<{ tier: string }>;

    beforeAll(async () => {
      ({ sql, close } = adapter.open());
      await migrate(sql, { schema });
      sessions = createSessions({
        sql,
        config,
        now: () => now,
        extendActor: (user) => ({
          tier: user.role === "admin" ? "gold" : "basic",
        }),
      });
    });
    afterAll(async () => {
      await dropSchemas(sql, [schema]);
      await close();
    });

    let counter = 0;
    async function user(role = "member"): Promise<string> {
      const [row] = await sql.query<{ id: string }>(
        `INSERT INTO ${t("users")} (iss, sub, role, email) VALUES ($1, $2, $3, $4) RETURNING id`,
        [ISS, `s-${++counter}`, role, `u${counter}@example.com`],
      );
      return row?.id ?? "";
    }
    const start = async (
      userId: string,
      fields: { sid?: string; amr?: string[] } = {},
    ) =>
      sessions.create({
        userId,
        authenticatedAt: new Date(now.getTime() - 5000),
        amr: fields.amr ?? ["mfa"],
        providerSid: fields.sid ?? null,
      });
    const idle = async (idHash: string) =>
      (
        await sql.query<{ at: Date }>(
          `SELECT idle_expires_at AS "at" FROM ${t("sessions")} WHERE id_hash = $1`,
          [idHash],
        )
      )[0]?.at.getTime();

    it("creates a session and finds its actor by token", async () => {
      now = new Date();
      const userId = await user("admin");
      const { token, session } = await start(userId);
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(session.idHash).toBe(sessions.hash(token));
      expect(session.expiresAt.getTime() - session.createdAt.getTime()).toBe(
        12 * HOUR * 1000,
      );
      expect(
        session.idleExpiresAt.getTime() - session.createdAt.getTime(),
      ).toBe(2 * HOUR * 1000);
      const found = await sessions.lookup(token);
      expect(found?.actor).toEqual({
        user: {
          id: userId,
          role: "admin",
          email: expect.any(String),
          displayName: null,
        },
        credential: { kind: "session", id: session.idHash, ceiling: null },
        role: "admin",
        ext: { tier: "gold" },
      });
      expect(found?.session.amr).toEqual(["mfa"]);
    });

    it("issues a different token for every session", async () => {
      const userId = await user();
      const tokens = new Set<string>();
      for (let i = 0; i < 5; i++) tokens.add((await start(userId)).token);
      expect(tokens.size).toBe(5);
    });

    it("clamps an authentication time in the future to now", async () => {
      now = new Date();
      const userId = await user();
      const { session } = await sessions.create({
        userId,
        authenticatedAt: new Date(now.getTime() + 3_600_000),
        amr: [],
        providerSid: null,
      });
      expect(session.authenticatedAt.getTime()).toBe(
        session.createdAt.getTime(),
      );
    });

    it("finds nothing for malformed, unknown or missing tokens", async () => {
      for (const token of [
        undefined,
        "",
        "short",
        "A".repeat(42) + "w",
        "x".repeat(43),
      ])
        expect(await sessions.lookup(token)).toBeNull();
      expect(sessions.hash(undefined)).toBeNull();
      expect(sessions.hash("not a token")).toBeNull();
    });

    it("expires after the idle timeout, sliding at most once a minute", async () => {
      now = new Date();
      const { token, session } = await start(await user());
      const first = await idle(session.idHash);

      advance(30);
      expect(await sessions.lookup(token)).not.toBeNull();
      expect(await idle(session.idHash)).toBe(first);

      advance(31);
      const slid = await sessions.lookup(token);
      expect(slid?.session.idleExpiresAt.getTime()).toBe(
        now.getTime() + 2 * HOUR * 1000,
      );
      expect(await idle(session.idHash)).toBe(now.getTime() + 2 * HOUR * 1000);

      advance(2 * HOUR - 1);
      expect(await sessions.lookup(token)).not.toBeNull();
      advance(2 * HOUR + 1);
      expect(await sessions.lookup(token)).toBeNull();
    });

    it("expires at the absolute limit however active it is", async () => {
      now = new Date();
      const { token, session } = await start(await user());
      for (let hour = 1; hour < 12; hour++) {
        advance(HOUR);
        expect(await sessions.lookup(token)).not.toBeNull();
      }
      // The idle expiry never passes the absolute one.
      expect(await idle(session.idHash)).toBe(session.expiresAt.getTime());
      advance(HOUR - 1);
      expect(await sessions.lookup(token)).not.toBeNull();
      advance(1);
      expect(await sessions.lookup(token)).toBeNull();
    });

    it("revokes one session or all of a user's, and lists the live ones", async () => {
      now = new Date();
      const userId = await user();
      const a = await start(userId);
      advance(1);
      const b = await start(userId);
      advance(1);
      const c = await start(userId);
      expect((await sessions.list(userId)).map((s) => s.idHash)).toEqual([
        c.session.idHash,
        b.session.idHash,
        a.session.idHash,
      ]);
      expect(await sessions.revoke(a.session.idHash, "sign_out")).toBe(true);
      expect(await sessions.revoke(a.session.idHash, "sign_out")).toBe(false);
      expect(await sessions.lookup(a.token)).toBeNull();
      expect(await sessions.revokeAll(userId, "sign_out_everywhere")).toBe(2);
      expect(await sessions.list(userId)).toEqual([]);
      const reasons = await sql.query<{ reason: string }>(
        `SELECT data->>'reason' AS "reason" FROM ${t("audit_events")}
       WHERE type = 'session.revoked' AND subject_user_id = $1 ORDER BY id`,
        [userId],
      );
      expect(reasons.map((r) => r.reason)).toEqual([
        "sign_out",
        "sign_out_everywhere",
        "sign_out_everywhere",
      ]);
    });

    it("records a step-up, moving authentication forward only", async () => {
      now = new Date();
      const { token, session } = await start(await user(), { amr: ["pwd"] });
      expect(
        await sessions.reauthenticate(session.idHash, {
          authenticatedAt: now,
          amr: ["mfa"],
        }),
      ).toBe(true);
      const after = await sessions.lookup(token);
      expect(after?.session.amr).toEqual(["mfa"]);
      expect(after?.session.authenticatedAt.getTime()).toBe(now.getTime());
      await sessions.reauthenticate(session.idHash, {
        authenticatedAt: new Date(now.getTime() - 60_000),
        amr: ["mfa", "pwd"],
      });
      expect(
        (await sessions.lookup(token))?.session.authenticatedAt.getTime(),
      ).toBe(now.getTime());
      await sessions.revoke(session.idHash, "sign_out");
      expect(
        await sessions.reauthenticate(session.idHash, {
          authenticatedAt: now,
          amr: [],
        }),
      ).toBe(false);
    });

    it("revokes by provider sid, by sub, or by both", async () => {
      now = new Date();
      const alice = await user();
      const bob = await user();
      const subOf = async (id: string) =>
        (
          await sql.query<{ sub: string }>(
            `SELECT sub FROM ${t("users")} WHERE id = $1`,
            [id],
          )
        )[0]?.sub ?? "";
      const aliceSub = await subOf(alice);
      const a1 = await start(alice, { sid: "sid-1" });
      const a2 = await start(alice, { sid: "sid-2" });
      const b1 = await start(bob, { sid: "sid-1" });

      expect(
        await sessions.revokeForProvider({ iss: ISS, sub: null, sid: null }),
      ).toBe(0);
      expect(
        await sessions.revokeForProvider({
          iss: "https://other",
          sub: null,
          sid: "sid-1",
        }),
      ).toBe(0);
      expect(
        await sessions.revokeForProvider({
          iss: ISS,
          sub: aliceSub,
          sid: "sid-1",
        }),
      ).toBe(1);
      expect(await sessions.lookup(a1.token)).toBeNull();
      expect(await sessions.lookup(b1.token)).not.toBeNull();
      expect(
        await sessions.revokeForProvider({ iss: ISS, sub: null, sid: "sid-1" }),
      ).toBe(1);
      expect(await sessions.lookup(b1.token)).toBeNull();
      expect(
        await sessions.revokeForProvider({
          iss: ISS,
          sub: aliceSub,
          sid: null,
        }),
      ).toBe(1);
      expect(await sessions.lookup(a2.token)).toBeNull();
    });

    it("refuses a session for a deactivated user and hides an existing one", async () => {
      now = new Date();
      const userId = await user();
      const { token } = await start(userId);
      await sql.query(
        `UPDATE ${t("users")} SET active = false, deactivated_at = now() WHERE id = $1`,
        [userId],
      );
      expect(await sessions.lookup(token)).toBeNull();
      await expect(start(userId)).rejects.toThrow(/not active/);
    });

    it("remembers logout token ids once and cleans up expired ones", async () => {
      const jtis = postgresJtiStore(schema);
      const later = new Date(Date.now() + 600_000);
      expect(await jtis.remember(sql, ISS, "jti-1", later)).toBe(true);
      expect(await jtis.remember(sql, ISS, "jti-1", later)).toBe(false);
      expect(await jtis.remember(sql, "https://other", "jti-1", later)).toBe(
        true,
      );
      expect(
        await jtis.remember(sql, ISS, "old", new Date(Date.now() - 1000)),
      ).toBe(true);
      await jtis.remember(sql, ISS, "jti-2", later);
      const rows = await sql.query<{ jti: string }>(
        `SELECT jti FROM ${t("logout_jtis")} ORDER BY jti, iss`,
      );
      expect(rows.map((r) => r.jti)).toEqual(["jti-1", "jti-1", "jti-2"]);
    });

    it("records a logout id and its revocations together or not at all", async () => {
      now = new Date();
      const userId = await user();
      const { token } = await start(userId, { sid: "sid-atomic" });
      const jtis = postgresJtiStore(schema);
      const later = new Date(Date.now() + 600_000);
      const failure = new Error("stop");
      await expect(
        sql.transaction(async (tx) => {
          await jtis.remember(tx, ISS, "jti-atomic", later);
          await sessions.revokeForProvider(
            { iss: ISS, sub: null, sid: "sid-atomic" },
            tx,
          );
          throw failure;
        }),
      ).rejects.toBe(failure);
      expect(await sessions.lookup(token)).not.toBeNull();
      expect(await jtis.remember(sql, ISS, "jti-atomic", later)).toBe(true);
      expect(
        await sql.transaction((tx) =>
          sessions.revokeForProvider(
            { iss: ISS, sub: null, sid: "sid-atomic" },
            tx,
          ),
        ),
      ).toBe(1);
      expect(await sessions.lookup(token)).toBeNull();
    });
  },
);
