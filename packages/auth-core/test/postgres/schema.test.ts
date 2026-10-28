import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deriveKey, generateToken, hashToken } from "../../src/index.js";
import { migrate, quoteIdent, type Sql } from "../../src/postgres/index.js";
import { adapters, databaseUrl, dropSchemas, uniqueSchema } from "./support.js";

const ISS = "https://auth.example.com/application/o/posted/";
const sessionKey = deriveKey("s".repeat(32), "posted", "session");

describe.skipIf(!databaseUrl).each(adapters)(
  "0001_core with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    // A quoted name, so the triggers' TG_TABLE_SCHEMA quoting is exercised.
    const schema = uniqueSchema("core");
    const t = (table: string) => `${quoteIdent(schema)}.${table}`;

    beforeAll(async () => {
      ({ sql, close } = adapter.open());
      await migrate(sql, { schema });
    });
    afterAll(async () => {
      await dropSchemas(sql, [schema]);
      await close();
    });

    let counter = 0;
    async function createUser(
      fields: Record<string, unknown> = {},
    ): Promise<string> {
      const values = {
        iss: ISS,
        sub: `sub-${++counter}-${Date.now()}`,
        ...fields,
      };
      const names = Object.keys(values);
      const [row] = await sql.query<{ id: string }>(
        `INSERT INTO ${t("users")} (${names.join(", ")})
       VALUES (${names.map((_, i) => `$${i + 1}`).join(", ")}) RETURNING id`,
        Object.values(values),
      );
      if (row === undefined) throw new Error("no user");
      return row.id;
    }

    async function createSession(
      userId: string,
      fields: { sid?: string } = {},
    ) {
      const idHash = hashToken(sessionKey, generateToken());
      await sql.query(
        `INSERT INTO ${t("sessions")}
         (id_hash, user_id, authenticated_at, amr, expires_at, idle_expires_at, provider_sid)
       VALUES ($1, $2, now(), $3::text::text[], now() + interval '12 hours',
               now() + interval '2 hours', $4)`,
        [idHash, userId, "{mfa}", fields.sid ?? null],
      );
      return idHash;
    }

    const fails = (
      text: string,
      params: unknown[] = [],
      pattern: RegExp = /violates|check_violation|cannot|never|stays|tombstone|not active/,
    ) => expect(sql.query(text, params)).rejects.toThrow(pattern);

    describe("users", () => {
      it("fills defaults", async () => {
        const id = await createUser({
          email: "ada@example.com",
          display_name: "Ada",
        });
        const [row] = await sql.query(
          `SELECT role, active, created_at = updated_at AS "fresh", deactivated_at AS "deactivatedAt",
                deleted_at AS "deletedAt"
         FROM ${t("users")} WHERE id = $1`,
          [id],
        );
        expect(row).toEqual({
          role: "viewer",
          active: true,
          fresh: true,
          deactivatedAt: null,
          deletedAt: null,
        });
        expect(id).toMatch(
          /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
        );
      });

      it("accepts only the three roles", async () => {
        for (const role of ["viewer", "member", "admin"])
          await createUser({ role });
        await fails(
          `INSERT INTO ${t("users")} (iss, sub, role) VALUES ($1, 'x-owner', 'owner')`,
          [ISS],
        );
        await fails(
          `INSERT INTO ${t("users")} (iss, sub, role) VALUES ($1, 'x-null', NULL)`,
          [ISS],
          /null value/,
        );
      });

      it("keys people by (iss, sub)", async () => {
        await createUser({ sub: "same-sub" });
        await fails(
          `INSERT INTO ${t("users")} (iss, sub) VALUES ($1, 'same-sub')`,
          [ISS],
          /users_iss_sub_key/,
        );
        // The same subject at another provider is another person.
        await createUser({
          iss: "https://accounts.google.com",
          sub: "same-sub",
        });
      });

      it("keeps external ids unique per provider", async () => {
        await createUser({ external_id: "ext-1" });
        await fails(
          `INSERT INTO ${t("users")} (iss, sub, external_id) VALUES ($1, 'other', 'ext-1')`,
          [ISS],
          /users_iss_external_id_key/,
        );
        await createUser({
          iss: "https://accounts.google.com",
          external_id: "ext-1",
        });
      });

      it("lets SCIM create a user before the first sign-in, but not an anonymous one", async () => {
        await createUser({ sub: null, external_id: "scim-only-1" });
        await createUser({ sub: null, external_id: "scim-only-2" });
        await fails(
          `INSERT INTO ${t("users")} (iss, sub) VALUES ($1, NULL)`,
          [ISS],
          /users_identified/,
        );
      });

      it("rejects empty identifiers and attributes", async () => {
        const users = t("users");
        await fails(`INSERT INTO ${users} (iss, sub) VALUES ('', 'x')`);
        await fails(`INSERT INTO ${users} (iss, sub) VALUES ($1, '')`, [ISS]);
        await fails(`INSERT INTO ${users} (iss, sub) VALUES ($1, $2)`, [
          ISS,
          "x".repeat(256),
        ]);
        await fails(
          `INSERT INTO ${users} (iss, sub, external_id) VALUES ($1, 'e1', '')`,
          [ISS],
        );
        await fails(
          `INSERT INTO ${users} (iss, sub, email) VALUES ($1, 'e2', '')`,
          [ISS],
        );
        await fails(
          `INSERT INTO ${users} (iss, sub, display_name) VALUES ($1, 'e3', $2)`,
          [ISS, "x".repeat(257)],
        );
      });

      it("keeps active and deactivated_at consistent", async () => {
        const id = await createUser();
        await fails(
          `UPDATE ${t("users")} SET active = false WHERE id = $1`,
          [id],
          /users_active_matches_deactivated_at/,
        );
        await sql.query(
          `UPDATE ${t("users")} SET active = false, deactivated_at = now() WHERE id = $1`,
          [id],
        );
        await fails(
          `UPDATE ${t("users")} SET active = true WHERE id = $1`,
          [id],
          /users_active_matches_deactivated_at/,
        );
        await sql.query(
          `UPDATE ${t("users")} SET active = true, deactivated_at = NULL WHERE id = $1`,
          [id],
        );
      });

      it("makes deletion a permanent tombstone", async () => {
        const id = await createUser({ email: "gone@example.com" });
        await fails(
          `UPDATE ${t("users")} SET deleted_at = now() WHERE id = $1`,
          [id],
          /users_deleted_is_inactive/,
        );
        await sql.query(
          `UPDATE ${t("users")} SET active = false, deactivated_at = now(), deleted_at = now(), email = NULL
         WHERE id = $1`,
          [id],
        );
        await fails(
          `UPDATE ${t("users")} SET deleted_at = NULL, active = true, deactivated_at = NULL WHERE id = $1`,
          [id],
        );
        await fails(
          `UPDATE ${t("users")} SET deleted_at = now() + interval '1 day' WHERE id = $1`,
          [id],
        );
        // Other fields on a tombstone may still change, such as scrubbing data.
        await sql.query(
          `UPDATE ${t("users")} SET display_name = NULL WHERE id = $1`,
          [id],
        );
      });

      it("moves updated_at on every update and never changes the id", async () => {
        const id = await createUser({
          created_at: new Date("2026-01-01T00:00:00Z"),
          updated_at: new Date("2026-01-01T00:00:00Z"),
        });
        await sql.query(
          `UPDATE ${t("users")} SET display_name = 'Grace' WHERE id = $1`,
          [id],
        );
        const [row] = await sql.query<{ moved: boolean }>(
          `SELECT updated_at > created_at AS "moved" FROM ${t("users")} WHERE id = $1`,
          [id],
        );
        expect(row?.moved).toBe(true);
        await fails(
          `UPDATE ${t("users")} SET id = gen_random_uuid() WHERE id = $1`,
          [id],
        );
      });
    });

    describe("0002", () => {
      it("records where a role came from, defaulting to none", async () => {
        const id = await createUser();
        const [row] = await sql.query<{ source: string }>(
          `SELECT role_source AS "source" FROM ${t("users")} WHERE id = $1`,
          [id],
        );
        expect(row?.source).toBe("none");
        for (const source of ["oidc", "scim", "admin", "operator"])
          await sql.query(
            `UPDATE ${t("users")} SET role_source = $2 WHERE id = $1`,
            [id, source],
          );
        await fails(
          `UPDATE ${t("users")} SET role_source = 'claims' WHERE id = $1`,
          [id],
        );
      });

      it("keys logout token ids by issuer and refuses empty ones", async () => {
        const insert = (iss: string, jti: string) =>
          sql.query(
            `INSERT INTO ${t("logout_jtis")} (iss, jti, expires_at) VALUES ($1, $2, now())`,
            [iss, jti],
          );
        await insert(ISS, "j1");
        await insert("https://other.example", "j1");
        await expect(insert(ISS, "j1")).rejects.toThrow(/duplicate key/);
        await fails(
          `INSERT INTO ${t("logout_jtis")} (iss, jti, expires_at) VALUES ($1, '', now())`,
          [ISS],
        );
        await fails(
          `INSERT INTO ${t("logout_jtis")} (iss, jti, expires_at) VALUES ($1, $2, now())`,
          [ISS, "x".repeat(256)],
        );
      });

      it("indexes sessions by user and revocation", async () => {
        const [row] = await sql.query<{ names: string[] }>(
          `SELECT array_agg(indexname::text ORDER BY indexname) AS "names" FROM pg_indexes
         WHERE schemaname = $1 AND tablename = 'sessions'`,
          [schema],
        );
        expect(row?.names).toEqual([
          "sessions_expires_at_idx",
          "sessions_pkey",
          "sessions_provider_sid_idx",
          "sessions_user_id_revoked_at_idx",
        ]);
      });
    });

    describe("sessions", () => {
      it("stores a hashed id with the provider's details", async () => {
        const userId = await createUser();
        const idHash = await createSession(userId, { sid: "provider-sid-1" });
        const [row] = await sql.query(
          `SELECT user_id AS "userId", amr, provider_sid AS "sid", revoked_at AS "revokedAt"
         FROM ${t("sessions")} WHERE id_hash = $1`,
          [idHash],
        );
        expect(row).toEqual({
          userId,
          amr: ["mfa"],
          sid: "provider-sid-1",
          revokedAt: null,
        });
      });

      it("accepts only 64-character lowercase hex ids", async () => {
        const userId = await createUser();
        for (const id of ["abc", "A".repeat(64), generateToken()])
          await fails(
            `INSERT INTO ${t("sessions")} (id_hash, user_id, authenticated_at, expires_at, idle_expires_at)
           VALUES ($1, $2, now(), now() + interval '1 hour', now() + interval '1 hour')`,
            [id, userId],
          );
      });

      it("refuses a session for an inactive, deleted or missing user", async () => {
        const inactive = await createUser({
          active: false,
          deactivated_at: new Date(),
        });
        await expect(createSession(inactive)).rejects.toThrow(/not active/);
        const deleted = await createUser({
          active: false,
          deactivated_at: new Date(),
          deleted_at: new Date(),
        });
        await expect(createSession(deleted)).rejects.toThrow(/not active/);
        await expect(
          createSession("00000000-0000-4000-8000-000000000000"),
        ).rejects.toThrow(/not active/);
      });

      it("enforces the time ordering", async () => {
        const userId = await createUser();
        const insert = (authenticated: string, expires: string, idle: string) =>
          fails(
            `INSERT INTO ${t("sessions")} (id_hash, user_id, authenticated_at, expires_at, idle_expires_at)
           VALUES ($1, $2, now() + $3::interval, now() + $4::interval, now() + $5::interval)`,
            [
              hashToken(sessionKey, generateToken()),
              userId,
              authenticated,
              expires,
              idle,
            ],
          );
        await insert("0", "0", "0"); // expires at creation
        await insert("0", "1 hour", "2 hours"); // idle beyond expiry
        await insert("0", "1 hour", "0"); // idle at creation
      });

      it("lets activity and step-up move forward, but fixes identity, expiry and revocation", async () => {
        const userId = await createUser();
        const idHash = await createSession(userId);
        await sql.query(
          `UPDATE ${t("sessions")} SET idle_expires_at = expires_at, authenticated_at = now(), amr = '{pwd,mfa}'
         WHERE id_hash = $1`,
          [idHash],
        );
        await fails(
          `UPDATE ${t("sessions")} SET authenticated_at = authenticated_at - interval '1 second' WHERE id_hash = $1`,
          [idHash],
          /never moves back/,
        );
        await fails(
          `UPDATE ${t("sessions")} SET expires_at = expires_at + interval '1 day' WHERE id_hash = $1`,
          [idHash],
        );
        await fails(
          `UPDATE ${t("sessions")} SET user_id = $2 WHERE id_hash = $1`,
          [idHash, await createUser()],
        );
        await fails(
          `UPDATE ${t("sessions")} SET id_hash = $2 WHERE id_hash = $1`,
          [idHash, "0".repeat(64)],
        );
        await sql.query(
          `UPDATE ${t("sessions")} SET revoked_at = now() WHERE id_hash = $1`,
          [idHash],
        );
        await fails(
          `UPDATE ${t("sessions")} SET revoked_at = NULL WHERE id_hash = $1`,
          [idHash],
        );
      });

      it("revokes every live session when the user is deactivated", async () => {
        const userId = await createUser();
        const other = await createUser();
        const live = [await createSession(userId), await createSession(userId)];
        const earlier = await createSession(userId);
        await sql.query(
          `UPDATE ${t("sessions")} SET revoked_at = created_at WHERE id_hash = $1`,
          [earlier],
        );
        const [before] = await sql.query<{ at: Date }>(
          `SELECT revoked_at AS "at" FROM ${t("sessions")} WHERE id_hash = $1`,
          [earlier],
        );
        const untouched = await createSession(other);
        await sql.query(
          `UPDATE ${t("users")} SET active = false, deactivated_at = now() WHERE id = $1`,
          [userId],
        );
        const rows = await sql.query<{
          idHash: string;
          revoked: boolean;
          at: Date | null;
        }>(
          `SELECT id_hash AS "idHash", revoked_at IS NOT NULL AS "revoked", revoked_at AS "at"
         FROM ${t("sessions")} WHERE id_hash = ANY($1::text[])`,
          [`{${[...live, earlier, untouched].join(",")}}`],
        );
        const byId = new Map(rows.map((r) => [r.idHash, r]));
        for (const id of live) expect(byId.get(id)?.revoked).toBe(true);
        expect(byId.get(earlier)?.at).toEqual(before?.at);
        expect(byId.get(untouched)?.revoked).toBe(false);
      });

      it("deletes a user's sessions with the user", async () => {
        const userId = await createUser();
        const idHash = await createSession(userId);
        await sql.query(`DELETE FROM ${t("users")} WHERE id = $1`, [userId]);
        expect(
          await sql.query(`SELECT 1 FROM ${t("sessions")} WHERE id_hash = $1`, [
            idHash,
          ]),
        ).toEqual([]);
      });
    });
  },
);
