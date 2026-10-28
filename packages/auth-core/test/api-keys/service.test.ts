import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createApiKeys, type ApiKeys } from "../../src/api-keys/index.js";
import {
  AuthRequestError,
  formatApiKey,
  generateApiKey,
  loadAuthConfig,
  type AuthConfig,
} from "../../src/index.js";
import { migrate, quoteIdent, type Sql } from "../../src/postgres/index.js";
import * as tokens from "../../src/tokens.js";
import {
  adapters,
  databaseUrl,
  dropSchemas,
  uniqueSchema,
} from "../postgres/support.js";

vi.mock("../../src/tokens.js", async (original) => {
  const actual = await original<typeof tokens>();
  return { ...actual, constantTimeEqual: vi.fn(actual.constantTimeEqual) };
});

const ISS = "https://auth.example.com/application/o/posted/";
const DAY = 86400;

/** The AuthRequestError a promise rejects with. */
async function refusal(promise: Promise<unknown>): Promise<AuthRequestError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AuthRequestError);
    return error as AuthRequestError;
  }
  throw new Error("expected a refusal");
}

describe.skipIf(!databaseUrl).each(adapters)(
  "API keys with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    const schema = uniqueSchema("apikeys");
    const t = (table: string) => `${quoteIdent(schema)}.${table}`;
    const configFor = (env: Record<string, string> = {}): AuthConfig =>
      loadAuthConfig("posted", {
        POSTED_SECRET: "s".repeat(32),
        POSTED_OIDC_ISSUER: ISS,
        POSTED_OIDC_CLIENT_ID: "posted",
        POSTED_OIDC_CLIENT_SECRET: "x",
        POSTED_WEB_ORIGIN: "https://posted.example.com",
        POSTED_API_ORIGIN: "https://api.posted.example.com",
        POSTED_API_KEY_MAX_TTL_DAYS: "90",
        POSTED_AUTH_SCHEMA: schema,
        ...env,
      });
    const config = configFor();
    // A clock the tests move; it starts at the present.
    let now = new Date();
    const advance = (seconds: number) => {
      now = new Date(now.getTime() + seconds * 1000);
    };
    let keys: ApiKeys<{ tier: string }>;
    let reads = 0;

    beforeAll(async () => {
      ({ sql, close } = adapter.open());
      await migrate(sql, { schema });
      const counted: Sql = {
        query: (text, params) => {
          reads++;
          return sql.query(text, params);
        },
        transaction: (fn) => sql.transaction(fn),
      };
      keys = createApiKeys({
        sql: counted,
        config,
        now: () => now,
        extendActor: (user) => ({ tier: user.role ?? "none" }),
      });
    });
    afterAll(async () => {
      await dropSchemas(sql, [schema]);
      await close();
    });

    let counter = 0;
    async function user(
      role: string | null = "member",
      source: string | null = "oidc",
    ): Promise<string> {
      const [row] = await sql.query<{ id: string }>(
        `INSERT INTO ${t("users")} (iss, sub, role, role_source, email)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [ISS, `k-${++counter}`, role, source, `k${counter}@example.com`],
      );
      return row?.id ?? "";
    }
    const setRole = (id: string, role: string | null) =>
      sql.query(`UPDATE ${t("users")} SET role = $2 WHERE id = $1`, [id, role]);
    const create = (
      userId: string,
      ceiling: "viewer" | "member" | "admin" = "viewer",
      extra: { workspace?: string; expiresInSeconds?: number | null } = {},
    ) => keys.create({ userId, name: "CI", ceiling, ...extra });
    const stored = async (id: string) =>
      (
        await sql.query<{
          secretHash: string;
          revoked: boolean;
          lastUsedAt: Date | null;
        }>(
          `SELECT secret_hash AS "secretHash", revoked_at IS NOT NULL AS "revoked",
             last_used_at AS "lastUsedAt" FROM ${t("api_keys")} WHERE id = $1`,
          [id],
        )
      )[0];

    it("issues a key once and verifies it with the lower of ceiling and role", async () => {
      now = new Date();
      const owner = await user("member");
      const { key, record } = await create(owner, "viewer", {
        workspace: "w-1",
      });
      expect(key).toMatch(
        /^posted_[0-7][0-9A-Z]{25}_[0-9A-Za-z]{43}_[0-9A-Za-z]{6}$/,
      );
      expect(key.split("_")[1]).toBe(record.id);
      expect(record).toMatchObject({
        userId: owner,
        name: "CI",
        ceiling: "viewer",
        workspace: "w-1",
        revokedAt: null,
        replacedBy: null,
      });
      expect(record.expiresAt?.getTime()).toBe(now.getTime() + 90 * DAY * 1000);
      expect(record).not.toHaveProperty("secretHash");
      const row = await stored(record.id);
      expect(row?.secretHash).toMatch(/^[0-9a-f]{64}$/);
      expect(row?.secretHash).not.toContain(key.split("_")[2]);

      const found = await keys.verify(key);
      expect(found?.actor).toEqual({
        user: {
          id: owner,
          role: "member",
          email: expect.any(String),
          displayName: null,
        },
        credential: {
          kind: "api_key",
          id: record.id,
          ceiling: "viewer",
          workspace: "w-1",
        },
        role: "viewer",
        ext: { tier: "member" },
      });

      advance(1);
      const wide = await create(owner, "member");
      expect((await keys.verify(wide.key))?.actor.role).toBe("member");
      expect((await keys.list(owner)).map((k) => k.id)).toEqual([
        wide.record.id,
        record.id,
      ]);
    });

    it("rejects malformed keys, bad checksums and other prefixes without reading the database", async () => {
      now = new Date();
      const { key } = await create(await user());
      const last = key.at(-1) === "A" ? "B" : "A";
      const other = generateApiKey("mill").key;
      reads = 0;
      for (const bad of [
        undefined,
        "",
        "nonsense",
        `${key.slice(0, -1)}${last}`,
        other,
        `${key} `,
      ])
        expect(await keys.verify(bad)).toBeNull();
      expect(reads).toBe(0);
    });

    it("refuses an unknown id or a wrong secret, comparing in constant time either way", async () => {
      now = new Date();
      const { key, record } = await create(await user());
      const [prefix = "", id = "", secret = ""] = key.split("_");
      const unknown = generateApiKey(prefix).key;
      const wrong = formatApiKey({
        prefix,
        id,
        secret: `${secret.slice(0, -1)}${secret.endsWith("A") ? "B" : "A"}`,
      });
      const compare = vi.mocked(tokens.constantTimeEqual);
      for (const bad of [unknown, wrong]) {
        compare.mockClear();
        expect(await keys.verify(bad)).toBeNull();
        expect(compare).toHaveBeenCalledTimes(1);
        expect(compare.mock.results[0]?.value).toBe(false);
      }
      expect(compare.mock.calls[0]?.[1]).toBe(
        (await stored(record.id))?.secretHash,
      );
      compare.mockClear();
      expect(await keys.verify(key)).not.toBeNull();
      expect(compare.mock.results[0]?.value).toBe(true);
    });

    it("stops working when it expires or is revoked, and revocation is final", async () => {
      now = new Date();
      const owner = await user();
      const short = await create(owner, "viewer", { expiresInSeconds: 3600 });
      const other = await create(owner);
      advance(3599);
      expect(await keys.verify(short.key)).not.toBeNull();
      advance(2);
      expect(await keys.verify(short.key)).toBeNull();
      expect((await keys.list(owner)).map((k) => k.id)).not.toContain(
        short.record.id,
      );

      expect(await keys.revoke(other.record.id, { userId: await user() })).toBe(
        false,
      );
      expect(await keys.revoke(other.record.id, { userId: owner })).toBe(true);
      expect(await keys.revoke(other.record.id)).toBe(false);
      expect(await keys.verify(other.key)).toBeNull();
      expect((await keys.get(other.record.id))?.revokedAt).toBeInstanceOf(Date);
      await expect(
        sql.query(
          `UPDATE ${t("api_keys")} SET revoked_at = NULL WHERE id = $1`,
          [other.record.id],
        ),
      ).rejects.toThrow(/stays revoked/);
    });

    it("rotates: the new key works, and the old one until its grace ends", async () => {
      now = new Date();
      const owner = await user("admin");
      const old = await create(owner, "member", {
        workspace: "w-9",
        expiresInSeconds: 30 * DAY,
      });
      const next = await keys.rotate(old.record.id, { graceSeconds: 300 });
      expect(next.key).not.toBe(old.key);
      expect(next.record).toMatchObject({
        userId: owner,
        name: "CI",
        ceiling: "member",
        workspace: "w-9",
        replacedBy: null,
      });
      expect(next.record.expiresAt?.getTime()).toBe(
        now.getTime() + 30 * DAY * 1000,
      );
      expect(await keys.get(old.record.id)).toMatchObject({
        replacedBy: next.record.id,
        graceUntil: new Date(now.getTime() + 300_000),
      });
      expect(await keys.verify(old.key)).not.toBeNull();
      expect((await keys.list(owner)).map((k) => k.id).sort()).toEqual(
        [old.record.id, next.record.id].sort(),
      );
      expect(
        (await refusal(keys.rotate(old.record.id, { graceSeconds: 0 }))).code,
      ).toBe("conflict");

      advance(301);
      expect(await keys.verify(old.key)).toBeNull();
      expect(await keys.verify(next.key)).not.toBeNull();
      expect((await keys.list(owner)).map((k) => k.id)).toEqual([
        next.record.id,
      ]);
      expect(
        (await refusal(keys.rotate(old.record.id, { graceSeconds: 0 }))).code,
      ).toBe("not_found");
      expect(
        (
          await refusal(
            keys.rotate(next.record.id, {
              graceSeconds: 0,
              userId: await user(),
            }),
          )
        ).code,
      ).toBe("not_found");
      for (const graceSeconds of [-1, 1.5, 8 * DAY])
        expect(
          (await refusal(keys.rotate(next.record.id, { graceSeconds }))).code,
        ).toBe("invalid_request");
    });

    it("lets exactly one of two concurrent rotations win", async () => {
      now = new Date();
      const { record } = await create(await user());
      const results = await Promise.allSettled([
        keys.rotate(record.id, { graceSeconds: 60 }),
        keys.rotate(record.id, { graceSeconds: 60 }),
      ]);
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      const [lost] = results.filter((r) => r.status === "rejected");
      expect((lost as PromiseRejectedResult).reason).toMatchObject({
        code: "conflict",
      });
      const [{ count } = { count: 0 }] = await sql.query<{ count: number }>(
        `SELECT count(*)::int AS "count" FROM ${t("api_keys")} WHERE user_id = (
           SELECT user_id FROM ${t("api_keys")} WHERE id = $1)`,
        [record.id],
      );
      expect(count).toBe(2);
    });

    it("revokes keys above a lowered role for good", async () => {
      now = new Date();
      const owner = await user("admin");
      const viewer = await create(owner, "viewer");
      const member = await create(owner, "member");
      const admin = await create(owner, "admin");
      expect((await keys.verify(admin.key))?.actor.role).toBe("admin");

      await setRole(owner, "member");
      expect(await keys.verify(admin.key)).toBeNull();
      expect((await stored(admin.record.id))?.revoked).toBe(true);
      expect((await keys.verify(member.key))?.actor.role).toBe("member");
      expect((await keys.list(owner)).map((k) => k.ceiling).sort()).toEqual([
        "member",
        "viewer",
      ]);
      // Raising the role back does not restore a revoked key.
      await setRole(owner, "admin");
      expect(await keys.verify(admin.key)).toBeNull();
      expect((await keys.verify(member.key))?.actor.role).toBe("member");
      expect((await keys.verify(viewer.key))?.actor.role).toBe("viewer");
    });

    it("suspends keys while the role is NULL and restores them with the role", async () => {
      now = new Date();
      const owner = await user("admin");
      const ks = {
        viewer: await create(owner, "viewer"),
        member: await create(owner, "member"),
        admin: await create(owner, "admin"),
      };
      await setRole(owner, null);
      for (const k of Object.values(ks)) {
        expect(await keys.verify(k.key)).toBeNull();
        expect((await stored(k.record.id))?.revoked).toBe(false);
      }
      expect((await refusal(create(owner))).reason).toBe("user");
      // The same role back: every key works again.
      await setRole(owner, "admin");
      for (const k of Object.values(ks))
        expect((await keys.verify(k.key))?.actor.role).toBe(k.record.ceiling);

      // Admin, then NULL, then member: the admin key is revoked, as if the
      // role had gone straight from admin to member.
      await setRole(owner, null);
      await setRole(owner, "member");
      expect(await keys.verify(ks.admin.key)).toBeNull();
      expect((await stored(ks.admin.record.id))?.revoked).toBe(true);
      expect((await keys.verify(ks.member.key))?.actor.role).toBe("member");
      expect((await keys.verify(ks.viewer.key))?.actor.role).toBe("viewer");
    });

    it("refuses and revokes the keys of a deactivated or deleted owner", async () => {
      now = new Date();
      const owner = await user();
      const k = await create(owner);
      await sql.query(
        `UPDATE ${t("users")} SET active = false, deactivated_at = now() WHERE id = $1`,
        [owner],
      );
      expect(await keys.verify(k.key)).toBeNull();
      expect((await stored(k.record.id))?.revoked).toBe(true);
      await sql.query(
        `UPDATE ${t("users")} SET active = true, deactivated_at = NULL WHERE id = $1`,
        [owner],
      );
      expect(await keys.verify(k.key)).toBeNull();

      const gone = await user();
      const g = await create(gone);
      await sql.query(
        `UPDATE ${t("users")} SET active = false, deactivated_at = now(), deleted_at = now()
         WHERE id = $1`,
        [gone],
      );
      expect((await stored(g.record.id))?.revoked).toBe(true);
      expect((await refusal(create(gone))).reason).toBe("user");
    });

    it("caps a key by the owner's role even if the row were left unrevoked", async () => {
      now = new Date();
      const owner = await user("admin");
      const k = await create(owner, "admin");
      // Lower the role behind the trigger's back, as a broken migration might.
      await sql.transaction(async (tx) => {
        await tx.query("SET LOCAL session_replication_role = replica");
        await tx.query(
          `UPDATE ${t("users")} SET role = 'viewer' WHERE id = $1`,
          [owner],
        );
      });
      expect((await stored(k.record.id))?.revoked).toBe(false);
      expect((await keys.verify(k.key))?.actor.role).toBe("viewer");
      await setRole(owner, null);
    });

    it("enforces the create rules", async () => {
      now = new Date();
      const member = await user("member");
      expect((await refusal(create(member, "admin"))).reason).toBe("ceiling");
      expect((await refusal(create(await user(null, null)))).reason).toBe(
        "user",
      );
      for (const name of ["", "   ", "x".repeat(101), "a\nb"])
        expect(
          (
            await refusal(
              keys.create({ userId: member, name, ceiling: "viewer" }),
            )
          ).reason,
        ).toBe("name");
      for (const workspace of ["", "x".repeat(256)])
        expect(
          (await refusal(create(member, "viewer", { workspace }))).reason,
        ).toBe("workspace");
      for (const expiresInSeconds of [null, 0, 59, 90 * DAY + 1, 1.5])
        expect(
          (await refusal(create(member, "viewer", { expiresInSeconds })))
            .reason,
        ).toBe("expiry");
      expect(
        (
          await refusal(
            keys.create({
              userId: member,
              name: "x",
              ceiling: "owner" as "admin",
            }),
          )
        ).reason,
      ).toBe("ceiling");

      const forever = createApiKeys({
        sql,
        config: configFor({ POSTED_API_KEY_ALLOW_NO_EXPIRY: "true" }),
      });
      const k = await forever.create({
        userId: member,
        name: "forever",
        ceiling: "viewer",
        expiresInSeconds: null,
      });
      expect(k.record.expiresAt).toBeNull();
      expect(await forever.verify(k.key)).not.toBeNull();
    });

    it("records last use at most once a minute", async () => {
      now = new Date();
      const { key, record } = await create(await user());
      expect((await keys.verify(key))?.key.lastUsedAt).toEqual(now);
      const first = now;
      advance(30);
      expect((await keys.verify(key))?.key.lastUsedAt).toEqual(first);
      expect((await stored(record.id))?.lastUsedAt).toEqual(first);
      advance(31);
      const second = now;
      expect((await keys.verify(key))?.key.lastUsedAt).toEqual(second);
      expect((await stored(record.id))?.lastUsedAt).toEqual(second);
    });

    it("in scim role mode, accepts only owners whose role SCIM set", async () => {
      now = new Date();
      const scim = createApiKeys({
        sql,
        config: configFor({ POSTED_ROLE_SOURCE: "scim" }),
      });
      const claimed = await user("admin", "oidc");
      expect(
        (
          await refusal(
            scim.create({ userId: claimed, name: "x", ceiling: "viewer" }),
          )
        ).reason,
      ).toBe("user");
      const fromClaims = await create(claimed);
      expect(await scim.verify(fromClaims.key)).toBeNull();
      const provisioned = await user("member", "scim");
      const k = await scim.create({
        userId: provisioned,
        name: "x",
        ceiling: "viewer",
      });
      expect((await scim.verify(k.key))?.actor.role).toBe("viewer");
    });
  },
);

describe("createApiKeys", () => {
  it("needs a key prefix", () => {
    const config = loadAuthConfig("x", {
      X_SECRET: "s".repeat(32),
      X_OIDC_ISSUER: ISS,
      X_OIDC_CLIENT_ID: "x",
      X_OIDC_CLIENT_SECRET: "x",
      X_WEB_ORIGIN: "https://x.example.com",
      X_API_ORIGIN: "https://api.x.example.com",
    });
    expect(() => createApiKeys({ sql: {} as Sql, config })).toThrow(
      /X_API_KEY_PREFIX/,
    );
  });
});
