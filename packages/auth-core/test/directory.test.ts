import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadAuthConfig, type AuthConfig } from "../src/index.js";
import {
  listDirectory,
  parseDirectoryQuery,
  type DirectoryQuery,
} from "../src/hono/directory.js";
import { migrate, quoteIdent, type Sql } from "../src/postgres/index.js";
import {
  adapters,
  databaseUrl,
  dropSchemas,
  uniqueSchema,
} from "./postgres/support.js";

const ISS = "https://auth.example.com/application/o/posted/";

const configFor = (schema: string, roleSource: "claims" | "scim"): AuthConfig =>
  loadAuthConfig("posted", {
    POSTED_SECRET: "s".repeat(32),
    POSTED_OIDC_ISSUER: ISS,
    POSTED_OIDC_CLIENT_ID: "posted",
    POSTED_OIDC_CLIENT_SECRET: "x",
    POSTED_WEB_ORIGIN: "https://posted.example.com",
    POSTED_API_ORIGIN: "https://api.posted.example.com",
    POSTED_AUTH_SCHEMA: schema,
    POSTED_ROLE_SOURCE: roleSource,
    ...(roleSource === "scim" ? { POSTED_SCIM_TOKENS: "t".repeat(32) } : {}),
  });

describe("parseDirectoryQuery", () => {
  it("fills defaults and treats empty parameters as absent", () => {
    expect(parseDirectoryQuery({})).toEqual({
      q: null,
      status: null,
      cursor: null,
      limit: 50,
    });
    expect(
      parseDirectoryQuery({ q: "  ", status: "", cursor: "", limit: "100" }),
    ).toEqual({ q: null, status: null, cursor: null, limit: 100 });
  });

  it("names the parameter it refuses", () => {
    const reason = (params: Parameters<typeof parseDirectoryQuery>[0]) => {
      try {
        parseDirectoryQuery(params);
      } catch (error) {
        return (error as { code: string; reason: string | null }).reason;
      }
      return null;
    };
    expect(reason({ q: "x".repeat(201) })).toBe("q");
    expect(reason({ status: "gone" })).toBe("status");
    expect(reason({ limit: "0" })).toBe("limit");
    expect(reason({ limit: "1000" })).toBe("limit");
    expect(reason({ limit: "-1" })).toBe("limit");
    expect(reason({ cursor: "!!" })).toBe("cursor");
    expect(reason({ cursor: "a".repeat(201) })).toBe("cursor");
  });
});

describe.skipIf(!databaseUrl).each(adapters)(
  "the people directory with $name",
  (adapter) => {
    let sql: Sql;
    let close: () => Promise<void>;
    const schema = uniqueSchema("directory");
    const t = (table: string) => `${quoteIdent(schema)}.${table}`;
    const claims = configFor(schema, "claims");
    const scim = configFor(schema, "scim");
    const query = (q: Partial<DirectoryQuery> = {}): DirectoryQuery => ({
      q: null,
      status: null,
      cursor: null,
      limit: 50,
      ...q,
    });

    let counter = 0;
    async function user(fields: Record<string, unknown>): Promise<string> {
      const values = { iss: ISS, sub: `u-${++counter}`, ...fields };
      const names = Object.keys(values);
      const [row] = await sql.query<{ id: string }>(
        `INSERT INTO ${t("users")} (${names.join(", ")})
         VALUES (${names.map((_, i) => `$${i + 1}`).join(", ")}) RETURNING id`,
        Object.values(values),
      );
      return row?.id ?? "";
    }

    beforeAll(async () => {
      ({ sql, close } = adapter.open());
      await migrate(sql, { schema });
      // Six people at the same microsecond, and four distinct states.
      for (let i = 0; i < 6; i++)
        await user({
          email: `tie-${i}@example.com`,
          role: "viewer",
          role_source: "scim",
          created_at: "2026-05-01T08:00:00.654321Z",
        });
      await user({
        display_name: "Sam",
        email: "sam@example.com",
        role: null,
        role_source: "oidc",
        created_at: "2026-04-01T00:00:00Z",
        last_sign_in_at: "2026-04-02T00:00:00.5Z",
      });
      await user({
        email: "dee@example.com",
        role: "member",
        role_source: "oidc",
        active: false,
        deactivated_at: "2026-04-03T00:00:00Z",
        created_at: "2026-03-01T00:00:00Z",
      });
      await user({
        email: "del@example.com",
        role: null,
        active: false,
        deactivated_at: "2026-04-03T00:00:00Z",
        deleted_at: "2026-04-04T00:00:00Z",
        created_at: "2026-02-01T00:00:00Z",
      });
      await user({
        display_name: "Admin Ann",
        email: "ann@example.com",
        role: "admin",
        role_source: "admin",
        created_at: "2026-01-01T00:00:00Z",
      });
    });
    afterAll(async () => {
      await dropSchemas(sql, [schema]);
      await close();
    });

    it("reads every field and status, newest first", async () => {
      const { users, nextCursor } = await listDirectory(sql, claims, query());
      expect(nextCursor).toBeNull();
      expect(users.map((u) => [u.email, u.status, u.roleSource])).toEqual([
        ...Array.from({ length: 6 }, () => [
          expect.stringMatching(/^tie-/),
          "active",
          "scim",
        ]),
        ["sam@example.com", "suspended", "claims"],
        ["dee@example.com", "deactivated", "claims"],
        ["del@example.com", "deleted", null],
        ["ann@example.com", "active", "app"],
      ]);
      expect(users.find((u) => u.email === "sam@example.com")).toEqual({
        id: expect.any(String),
        displayName: "Sam",
        email: "sam@example.com",
        role: null,
        roleSource: "claims",
        status: "suspended",
        createdAt: "2026-04-01T00:00:00.000Z",
        lastSignInAt: "2026-04-02T00:00:00.500Z",
        deactivatedAt: null,
        deletedAt: null,
      });
      expect(users.find((u) => u.email === "del@example.com")).toMatchObject({
        deactivatedAt: "2026-04-03T00:00:00.000Z",
        deletedAt: "2026-04-04T00:00:00.000Z",
      });
      // With roles from SCIM, a role from anywhere else is a suspension.
      const fromScim = await listDirectory(
        sql,
        scim,
        query({ status: "suspended" }),
      );
      expect(fromScim.users.map((u) => u.email)).toEqual([
        "sam@example.com",
        "ann@example.com",
      ]);
    });

    it("filters, searches and pages through ties at the microsecond", async () => {
      const emails = async (q: Partial<DirectoryQuery>) =>
        (await listDirectory(sql, claims, query(q))).users.map((u) => u.email);
      expect(await emails({ status: "deleted" })).toEqual(["del@example.com"]);
      expect(await emails({ q: "ANN" })).toEqual(["ann@example.com"]);
      expect(await emails({ q: "sam", status: "active" })).toEqual([]);

      const all = (await listDirectory(sql, claims, query())).users.map(
        (u) => u.id,
      );
      const seen: string[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < 10; page++) {
        const result = await listDirectory(
          sql,
          claims,
          parseDirectoryQuery({
            limit: "4",
            ...(cursor === null ? {} : { cursor }),
          }),
        );
        seen.push(...result.users.map((u) => u.id));
        cursor = result.nextCursor;
        if (cursor === null) break;
      }
      expect(seen).toEqual(all);
      const ties = await listDirectory(
        sql,
        claims,
        query({ q: "tie-", limit: 5 }),
      );
      const rest = await listDirectory(
        sql,
        claims,
        query({ q: "tie-", limit: 5, cursor: ties.nextCursor }),
      );
      expect(rest.users).toHaveLength(1);
      expect(rest.nextCursor).toBeNull();
      expect(
        new Set([...ties.users, ...rest.users].map((u) => u.id)).size,
      ).toBe(6);
    });
  },
);
