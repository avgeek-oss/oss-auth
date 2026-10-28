import { afterEach, describe, expect, it } from "vitest";
import { loadAuthConfig } from "../../src/index.js";
import { createApiKeys } from "../../src/api-keys/index.js";
import { createScim } from "../../src/scim/index.js";
import { createSessions } from "../../src/sessions/index.js";
import { AuthConfigError } from "../../src/errors.js";
import { constraintError } from "../../src/scim/errors.js";
import { databaseUrl } from "../postgres/support.js";
import {
  ISSUER,
  OLD_TOKEN,
  patchBody,
  startScim,
  TOKEN,
  userBody,
  type ScimStack,
} from "./support.js";

const stacks: ScimStack[] = [];
async function stack(
  ...args: Parameters<typeof startScim>
): Promise<ScimStack> {
  const s = await startScim(...args);
  stacks.push(s);
  return s;
}
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});

const ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";

async function create(
  s: ScimStack,
  userName: string,
  extra: Record<string, unknown> = {},
) {
  const { status, body } = await s.json(
    "POST",
    "/Users",
    userBody(userName, extra),
  );
  expect(status).toBe(201);
  return body.id as string;
}

async function group(
  s: ScimStack,
  displayName: string,
  members: string[] = [],
) {
  const { status, body } = await s.json("POST", "/Groups", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    displayName,
    members: members.map((value) => ({ value })),
  });
  expect(status).toBe(201);
  return body.id as string;
}

async function startSession(s: ScimStack, userId: string) {
  const sessions = createSessions({ sql: s.sql, config: s.config });
  const { token } = await sessions.create({
    userId,
    authenticatedAt: new Date(),
    amr: [],
    providerSid: null,
  });
  return { sessions, token };
}

async function userRow(s: ScimStack, id: string) {
  const [row] = await s.rows<{
    role: string | null;
    source: string | null;
    active: boolean;
    deleted: boolean;
  }>(
    `SELECT role, role_source AS "source", active, deleted_at IS NOT NULL AS "deleted"
     FROM {schema}.users WHERE id = $1`,
    [id],
  );
  return row;
}

describe("createScim", () => {
  it("needs SCIM tokens to be configured", () => {
    const config = loadAuthConfig("posted", {
      POSTED_SECRET: "s".repeat(32),
      POSTED_OIDC_ISSUER: ISSUER,
      POSTED_OIDC_CLIENT_ID: "posted",
      POSTED_OIDC_CLIENT_SECRET: "x",
      POSTED_WEB_ORIGIN: "https://posted.example.com",
      POSTED_API_ORIGIN: "https://api.posted.example.com",
    });
    const sql = {
      query: () => Promise.reject(new Error("unused")),
      transaction: () => Promise.reject(new Error("unused")),
    };
    expect(() => createScim({ config, sql })).toThrow(AuthConfigError);
    expect(() => createScim({ config, sql })).toThrow(/POSTED_SCIM_TOKENS/);
  });
});

describe.skipIf(!databaseUrl)("SCIM server", () => {
  describe("authentication", () => {
    it("refuses a missing, wrong or malformed token and accepts every configured one", async () => {
      const s = await stack();
      for (const token of [null, "wrong-token", `${TOKEN}x`, ""]) {
        const response = await s.request("GET", "/Users", undefined, token);
        expect(response.status).toBe(401);
        expect(response.headers.get("www-authenticate")).toBe(
          'Bearer realm="SCIM"',
        );
        expect(await response.json()).toEqual({
          schemas: [ERROR],
          status: "401",
          detail: "A valid bearer token is required.",
        });
      }
      const basic = await s.request("GET", "/Users", undefined, null);
      expect(basic.status).toBe(401);
      expect((await s.request("GET", "/Users", undefined, TOKEN)).status).toBe(
        200,
      );
      // Rotation: the old token keeps working until it is removed.
      expect(
        (await s.request("GET", "/Users", undefined, OLD_TOKEN)).status,
      ).toBe(200);
    });

    it("stops accepting a rotated-out token", async () => {
      const s = await stack({ POSTED_SCIM_TOKENS: TOKEN });
      expect(
        (await s.request("GET", "/Users", undefined, OLD_TOKEN)).status,
      ).toBe(401);
      expect((await s.request("GET", "/Users", undefined, TOKEN)).status).toBe(
        200,
      );
    });
  });

  describe("discovery", () => {
    it("serves the service provider config, resource types and schemas", async () => {
      const s = await stack();
      const config = await s.json("GET", "/ServiceProviderConfig");
      expect(config.body).toMatchObject({
        patch: { supported: true },
        filter: { supported: true, maxResults: 200 },
        bulk: { supported: false },
        sort: { supported: false },
        etag: { supported: false },
        changePassword: { supported: false },
        authenticationSchemes: [{ type: "oauthbearertoken" }],
      });
      const types = await s.json("GET", "/ResourceTypes");
      expect(
        (types.body.Resources as { id: string }[]).map((r) => r.id),
      ).toEqual(["User", "Group"]);
      expect((await s.json("GET", "/ResourceTypes/User")).body).toMatchObject({
        endpoint: "/Users",
      });
      const schemas = await s.json("GET", "/Schemas");
      expect(schemas.body.totalResults).toBe(2);
      expect(
        (
          await s.json(
            "GET",
            "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
          )
        ).body,
      ).toMatchObject({ name: "Group" });
      expect((await s.json("GET", "/Schemas/nope")).status).toBe(404);
      const response = await s.request("GET", "/ServiceProviderConfig");
      expect(response.headers.get("content-type")).toBe(
        "application/scim+json; charset=utf-8",
      );
    });

    it("answers unknown routes with a SCIM 404", async () => {
      const s = await stack();
      expect(await s.json("GET", "/Nope")).toEqual({
        status: 404,
        body: {
          schemas: [ERROR],
          status: "404",
          detail: "Resource not found.",
        },
      });
    });
  });

  describe("users", () => {
    it("creates, reads, replaces and lists a user", async () => {
      const s = await stack();
      const response = await s.request(
        "POST",
        "/Users",
        userBody("Ada@Example.com", {
          externalId: "ext-ada",
          name: { givenName: "Ada", familyName: "Lovelace" },
          emails: [{ value: "ada@example.com", type: "work", primary: true }],
        }),
      );
      expect(response.status).toBe(201);
      const created = (await response.json()) as Record<string, unknown>;
      const id = created.id as string;
      expect(response.headers.get("location")).toBe(
        `https://api.posted.example.com/scim/v2/Users/${id}`,
      );
      expect(created).toMatchObject({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "Ada@Example.com",
        externalId: "ext-ada",
        name: {
          givenName: "Ada",
          familyName: "Lovelace",
          formatted: "Ada Lovelace",
        },
        displayName: "Ada Lovelace",
        emails: [{ value: "ada@example.com", type: "work", primary: true }],
        active: true,
        meta: {
          resourceType: "User",
          location: `https://api.posted.example.com/scim/v2/Users/${id}`,
        },
      });
      expect((await s.json("GET", `/Users/${id}`)).body).toEqual(created);
      const [row] = await s.rows<{
        iss: string;
        sub: string | null;
        role: string | null;
        source: string | null;
      }>(
        `SELECT iss, sub, role, role_source AS "source" FROM {schema}.users WHERE id = $1`,
        [id],
      );
      expect(row).toEqual({ iss: ISSUER, sub: null, role: null, source: null });

      const replaced = await s.json(
        "PUT",
        `/Users/${id}`,
        userBody("ada@example.com", { displayName: "Countess", emails: [] }),
      );
      expect(replaced.body).toMatchObject({
        userName: "ada@example.com",
        externalId: "ext-ada",
        displayName: "Countess",
        emails: [],
      });
      expect(replaced.body).not.toHaveProperty("name");
    });

    it("makes an unchanged PUT a no-op", async () => {
      const s = await stack();
      const id = await create(s, "ada", {
        externalId: "e",
        displayName: "Ada",
      });
      const before = await s.json("GET", `/Users/${id}`);
      const again = await s.json(
        "PUT",
        `/Users/${id}`,
        userBody("ada", { externalId: "e", displayName: "Ada" }),
      );
      expect(again.status).toBe(200);
      expect((again.body.meta as { lastModified: string }).lastModified).toBe(
        (before.body.meta as { lastModified: string }).lastModified,
      );
    });

    it("refuses duplicate userNames, ignoring case, and duplicate externalIds", async () => {
      const s = await stack();
      const id = await create(s, "ada@example.com", { externalId: "e1" });
      await create(s, "grace@example.com", { externalId: "e2" });
      for (const [body, detail] of [
        [userBody("ADA@example.com"), "userName must be unique."],
        [
          userBody("someone", { externalId: "e1" }),
          "externalId must be unique.",
        ],
      ] as const) {
        const { status, body: error } = await s.json("POST", "/Users", body);
        expect(status).toBe(409);
        expect(error).toEqual({
          schemas: [ERROR],
          status: "409",
          scimType: "uniqueness",
          detail,
        });
      }
      const rename = await s.json(
        "PUT",
        `/Users/${id}`,
        userBody("grace@example.com"),
      );
      expect(rename.status).toBe(409);
      const patch = await s.json(
        "PATCH",
        `/Users/${id}`,
        patchBody({ op: "replace", path: "externalId", value: "e2" }),
      );
      expect(patch.status).toBe(409);
    });

    it("validates bodies and content types", async () => {
      const s = await stack();
      expect(
        (await s.json("POST", "/Users", { schemas: [] })).body,
      ).toMatchObject({
        status: "400",
        scimType: "invalidValue",
      });
      expect((await s.json("POST", "/Users", "{not json")).body).toMatchObject({
        scimType: "invalidSyntax",
      });
      expect((await s.request("POST", "/Users", undefined)).status).toBe(415);
      expect(
        (await s.request("POST", "/Users", userBody("x"), TOKEN, "text/plain"))
          .status,
      ).toBe(415);
      expect(
        (
          await s.request(
            "POST",
            "/Users",
            userBody("y"),
            TOKEN,
            "application/json; charset=utf-8",
          )
        ).status,
      ).toBe(201);
    });

    it("finds nothing for unknown, malformed and deleted ids", async () => {
      const s = await stack();
      for (const id of ["00000000-0000-4000-8000-000000000000", "not-a-uuid"]) {
        expect((await s.json("GET", `/Users/${id}`)).status).toBe(404);
        expect(
          (await s.json("PUT", `/Users/${id}`, userBody("x"))).status,
        ).toBe(404);
        expect((await s.json("DELETE", `/Users/${id}`)).status).toBe(404);
      }
    });
  });

  describe("filters, pagination and attributes", () => {
    it("filters users by userName (ignoring case), externalId, id and email", async () => {
      const s = await stack();
      const ada = await create(s, "Ada@Example.com", {
        externalId: "ext-ada",
        emails: [{ value: "ada@example.com", type: "work", primary: true }],
      });
      await create(s, "grace@example.com", { externalId: "ext-grace" });
      const ids = async (filter: string) => {
        const { status, body } = await s.json(
          "GET",
          `/Users?filter=${encodeURIComponent(filter)}`,
        );
        expect(status).toBe(200);
        return (body.Resources as { id: string }[]).map((r) => r.id);
      };
      expect(await ids('userName eq "ada@example.com"')).toEqual([ada]);
      expect(await ids('externalId eq "ext-ada"')).toEqual([ada]);
      expect(await ids('externalId eq "EXT-ADA"')).toEqual([]);
      expect(await ids(`id eq "${ada}"`)).toEqual([ada]);
      expect(await ids('id eq "not-a-uuid"')).toEqual([]);
      expect(await ids('emails.value eq "ADA@example.com"')).toEqual([ada]);
      expect(
        await ids('emails[type eq "work"].value eq "ada@example.com"'),
      ).toEqual([ada]);
      expect(
        await ids('userName eq "ada@example.com" and externalId eq "ext-ada"'),
      ).toEqual([ada]);
      expect(
        await ids(
          'userName eq "ada@example.com" and externalId eq "ext-grace"',
        ),
      ).toEqual([]);
    });

    it("answers invalidFilter for unsupported filters", async () => {
      const s = await stack();
      for (const filter of [
        'userName sw "a"',
        'title eq "x"',
        'userName eq "a" or userName eq "b"',
      ]) {
        const { status, body } = await s.json(
          "GET",
          `/Users?filter=${encodeURIComponent(filter)}`,
        );
        expect(status).toBe(400);
        expect(body).toMatchObject({
          scimType: "invalidFilter",
          status: "400",
        });
      }
      expect(
        (
          await s.json(
            "GET",
            `/Groups?filter=${encodeURIComponent('members eq "x"')}`,
          )
        ).body,
      ).toMatchObject({ scimType: "invalidFilter" });
    });

    it("pages with startIndex and count", async () => {
      const s = await stack();
      const ids: string[] = [];
      for (let i = 0; i < 5; i++)
        ids.push(await create(s, `user${i}@example.com`));
      const page = async (query: string) =>
        (await s.json("GET", `/Users?${query}`)).body;
      expect(await page("startIndex=2&count=2")).toMatchObject({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        totalResults: 5,
        startIndex: 2,
        itemsPerPage: 2,
      });
      expect(
        (
          (await page("startIndex=2&count=2")).Resources as { id: string }[]
        ).map((r) => r.id),
      ).toEqual(ids.slice(1, 3));
      expect(await page("count=0")).toMatchObject({
        totalResults: 5,
        itemsPerPage: 0,
        Resources: [],
      });
      expect(await page("startIndex=0&count=1000")).toMatchObject({
        startIndex: 1,
        itemsPerPage: 5,
      });
      expect(await page("startIndex=9")).toMatchObject({ itemsPerPage: 0 });
      expect(await page("count=-3")).toMatchObject({ itemsPerPage: 0 });
    });

    it("selects and excludes attributes", async () => {
      const s = await stack();
      const id = await create(s, "ada", {
        name: { givenName: "Ada", familyName: "L" },
        displayName: "Ada",
      });
      const only = await s.json(
        "GET",
        `/Users/${id}?attributes=userName,name.givenName`,
      );
      expect(only.body).toEqual({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        id,
        userName: "ada",
        name: { givenName: "Ada" },
      });
      const list = await s.json(
        "GET",
        "/Users?excludedAttributes=emails,meta,name",
      );
      expect(
        Object.keys((list.body.Resources as object[])[0] ?? {}).sort(),
      ).toEqual(["active", "displayName", "id", "schemas", "userName"]);
    });
  });

  describe("PATCH", () => {
    it("applies each path form, string booleans and path-less objects", async () => {
      const s = await stack();
      const id = await create(s, "ada", {
        emails: [{ value: "a@x", type: "work", primary: true }],
      });
      const { status, body } = await s.json(
        "PATCH",
        `/Users/${id}`,
        patchBody(
          { op: "Replace", path: "displayName", value: "Ada L" },
          { op: "add", path: "name.givenName", value: "Ada" },
          {
            op: "replace",
            path: 'emails[type eq "work"].value',
            value: "ada@x",
          },
          {
            op: "Add",
            value: { "name.familyName": "Lovelace", externalId: "ext" },
          },
          {
            op: "replace",
            path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
            value: "x",
          },
        ),
      );
      expect(status).toBe(200);
      expect(body).toMatchObject({
        displayName: "Ada L",
        externalId: "ext",
        name: { givenName: "Ada", familyName: "Lovelace" },
        emails: [{ value: "ada@x" }],
        active: true,
      });
      const off = await s.json(
        "PATCH",
        `/Users/${id}`,
        patchBody({ op: "Replace", path: "active", value: "False" }),
      );
      expect(off.body.active).toBe(false);
      const on = await s.json(
        "PATCH",
        `/Users/${id}`,
        patchBody({ op: "replace", value: { active: true } }),
      );
      expect(on.body.active).toBe(true);
    });

    it("rejects bad operations", async () => {
      const s = await stack();
      const id = await create(s, "ada");
      for (const [body, scimType] of [
        [patchBody({ op: "move", path: "active" }), "invalidSyntax"],
        [
          patchBody({ op: "replace", path: "active", value: "maybe" }),
          "invalidValue",
        ],
        [patchBody({ op: "remove", path: "userName" }), "mutability"],
        [
          patchBody({ op: "replace", path: "emails[type", value: "x" }),
          "invalidPath",
        ],
        [{ Operations: "x" }, "invalidSyntax"],
      ] as const) {
        const response = await s.json("PATCH", `/Users/${id}`, body);
        expect(response.status).toBe(400);
        expect(response.body.scimType).toBe(scimType);
      }
    });
  });

  describe("deactivation and deletion", () => {
    it("revokes sessions and calls the hook on deactivation, and reactivates", async () => {
      const s = await stack();
      const id = await create(s, "ada");
      const { sessions, token } = await startSession(s, id);
      await s.json("PUT", `/Users/${id}`, userBody("ada", { active: false }));
      expect(await sessions.lookup(token)).toBeNull();
      expect(await userRow(s, id)).toMatchObject({
        active: false,
        deleted: false,
      });
      expect(s.hooks).toEqual([{ hook: "deactivate", userId: id }]);
      // Deactivating again calls nothing new.
      await s.json("PUT", `/Users/${id}`, userBody("ada", { active: false }));
      expect(s.hooks).toHaveLength(1);

      const back = await s.json(
        "PATCH",
        `/Users/${id}`,
        patchBody({ op: "replace", path: "active", value: true }),
      );
      expect(back.body.active).toBe(true);
      expect(await userRow(s, id)).toMatchObject({ active: true });
      expect(await sessions.lookup(token)).toBeNull();
      expect((await startSession(s, id)).token).toEqual(expect.any(String));
    });

    it("tombstones on delete, revokes everything, and revives on a new POST of the externalId", async () => {
      const s = await stack();
      const id = await create(s, "ada", { externalId: "ext-ada" });
      const g = await group(s, "posted-members", [id]);
      const { sessions, token } = await startSession(s, id);
      const response = await s.request("DELETE", `/Users/${id}`);
      expect(response.status).toBe(204);
      expect(await sessions.lookup(token)).toBeNull();
      expect(await userRow(s, id)).toMatchObject({
        active: false,
        deleted: true,
      });
      expect(s.hooks).toEqual([{ hook: "deactivate", userId: id }]);
      expect(
        ((await s.json("GET", `/Groups/${g}`)).body.members as unknown[])
          .length,
      ).toBe(0);

      expect((await s.json("GET", `/Users/${id}`)).status).toBe(404);
      expect(
        (
          await s.json(
            "PATCH",
            `/Users/${id}`,
            patchBody({ op: "replace", path: "active", value: true }),
          )
        ).status,
      ).toBe(404);
      expect(
        (await s.json("PUT", `/Users/${id}`, userBody("ada", { active: true })))
          .status,
      ).toBe(404);
      expect((await s.json("DELETE", `/Users/${id}`)).status).toBe(404);
      expect(
        (await s.json("GET", '/Users?filter=userName eq "ada"')).body
          .totalResults,
      ).toBe(0);
      // A tombstone cannot join a group.
      expect(
        (
          await s.json(
            "PATCH",
            `/Groups/${g}`,
            patchBody({ op: "add", path: "members", value: [{ value: id }] }),
          )
        ).body,
      ).toMatchObject({ status: "400", scimType: "invalidValue" });

      // The userName is free for someone else, so reviving under it clashes.
      expect(await create(s, "ada", { externalId: "ext-new" })).not.toBe(id);
      expect(
        (
          await s.json(
            "POST",
            "/Users",
            userBody("ada", { externalId: "ext-ada" }),
          )
        ).body,
      ).toMatchObject({ status: "409", scimType: "uniqueness" });
      // Provisioned again, Ada comes back as the same row with no role, and
      // her old session stays revoked.
      const again = await s.json(
        "POST",
        "/Users",
        userBody("ada.lovelace", { externalId: "ext-ada" }),
      );
      expect(again.status).toBe(201);
      expect(again.body).toMatchObject({
        id,
        userName: "ada.lovelace",
        active: true,
      });
      expect(await userRow(s, id)).toMatchObject({
        role: null,
        source: null,
        active: true,
        deleted: false,
      });
      expect(await sessions.lookup(token)).toBeNull();
      expect(
        ((await s.json("GET", `/Groups/${g}`)).body.members as unknown[])
          .length,
      ).toBe(0);
    });

    it("revives by PUT only with the same externalId, and gives a role only through groups", async () => {
      const s = await stack({ POSTED_ROLE_SOURCE: "scim" });
      const id = await create(s, "ada", { externalId: "ext-ada" });
      const admins = await group(s, "posted-admins", [id]);
      expect(await userRow(s, id)).toMatchObject({ role: "admin" });
      await s.request("DELETE", `/Users/${id}`);

      for (const body of [
        userBody("ada"),
        userBody("ada", { externalId: "ext-other" }),
      ])
        expect((await s.json("PUT", `/Users/${id}`, body)).status).toBe(404);
      const revived = await s.json(
        "PUT",
        `/Users/${id}`,
        userBody("ada", { externalId: "ext-ada" }),
      );
      expect(revived.status).toBe(200);
      expect(revived.body.id).toBe(id);
      expect(await userRow(s, id)).toMatchObject({
        role: null,
        source: null,
        deleted: false,
      });

      await s.json(
        "PATCH",
        `/Groups/${admins}`,
        patchBody({ op: "add", path: "members", value: [{ value: id }] }),
      );
      expect(await userRow(s, id)).toMatchObject({
        role: "admin",
        source: "scim",
      });
      expect(s.hooks).toEqual([
        { hook: "role", userId: id, from: null, to: "admin" },
        { hook: "deactivate", userId: id },
        { hook: "role", userId: id, from: null, to: "admin" },
      ]);
    });

    it("revokes API keys on deactivation, deletion and a SCIM downgrade", async () => {
      const s = await stack({ POSTED_ROLE_SOURCE: "scim" });
      const keys = createApiKeys({ sql: s.sql, config: s.config });
      const issue = (userId: string, ceiling: "viewer" | "member" | "admin") =>
        keys.create({ userId, name: "CI", ceiling });
      const ada = await create(s, "ada");
      const grace = await create(s, "grace");
      const linus = await create(s, "linus");
      const admins = await group(s, "posted-admins", [grace, linus]);
      await group(s, "posted-viewers", [ada, linus]);
      const a = await issue(ada, "viewer");
      const g = await issue(grace, "admin");
      const l = await issue(linus, "admin");
      const lv = await issue(linus, "viewer");

      await s.json(
        "PATCH",
        `/Users/${ada}`,
        patchBody({ op: "replace", path: "active", value: false }),
      );
      expect(await keys.verify(a.key)).toBeNull();
      expect((await keys.get(a.record.id))?.revokedAt).toBeInstanceOf(Date);

      await s.request("DELETE", `/Users/${grace}`);
      expect(await keys.verify(g.key)).toBeNull();
      expect((await keys.get(g.record.id))?.revokedAt).toBeInstanceOf(Date);

      await s.json(
        "PATCH",
        `/Groups/${admins}`,
        patchBody({ op: "remove", path: `members[value eq "${linus}"]` }),
      );
      expect((await keys.get(l.record.id))?.revokedAt).toBeInstanceOf(Date);
      expect((await keys.verify(lv.key))?.actor.role).toBe("viewer");
    });

    it("rolls the change back when a hook fails", async () => {
      let fail = false;
      const s = await stack({}, { failHook: () => fail });
      const id = await create(s, "ada");
      fail = true;
      const response = await s.request(
        "PUT",
        `/Users/${id}`,
        userBody("ada", { active: false }),
      );
      expect(response.status).toBe(500);
      expect(await response.text()).not.toContain("hook failed");
      expect(await userRow(s, id)).toMatchObject({ active: true });
    });

    it("answers constraint violations with fixed messages and rethrows other database errors", async () => {
      const s = await stack();
      await create(s, "ada");
      const caught = async (query: string) => {
        try {
          await s.rows(query, [ISSUER]);
        } catch (error) {
          return error;
        }
        throw new Error("the query succeeded");
      };
      const duplicate = await caught(
        `INSERT INTO {schema}.users (iss, user_name) VALUES ($1, 'ADA')`,
      );
      expect(constraintError(duplicate)?.toJSON()).toEqual({
        schemas: [ERROR],
        status: "409",
        scimType: "uniqueness",
        detail: "userName must be unique.",
      });
      const empty = await caught(
        `INSERT INTO {schema}.users (iss, user_name) VALUES ($1, '')`,
      );
      expect(constraintError(empty)?.toJSON()).toEqual({
        schemas: [ERROR],
        status: "400",
        scimType: "invalidValue",
        detail: "userName is empty or too long.",
      });
      // A trigger's exception names no constraint: it is not ours to answer.
      const raised = await caught(
        `UPDATE {schema}.users SET id = gen_random_uuid() WHERE iss = $1`,
      );
      expect((raised as { code?: string }).code).toBe("23514");
      expect(constraintError(raised)).toBeNull();
      // Postgres.js reports the constraint as constraint_name.
      expect(
        constraintError({
          code: "23505",
          constraint_name: "scim_groups_display_name_key",
        })?.message,
      ).toBe("displayName must be unique.");
      expect(
        constraintError({ code: "23505", constraint: "something_else" }),
      ).toBeNull();

      // Concurrent creates race past the check; every loser gets the same
      // fixed answer whichever check caught it.
      const results = await Promise.all(
        Array.from({ length: 5 }, () =>
          s.json("POST", "/Users", userBody("grace")),
        ),
      );
      expect(results.filter((r) => r.status === 201)).toHaveLength(1);
      for (const r of results.filter((r) => r.status !== 201))
        expect(r).toEqual({
          status: 409,
          body: {
            schemas: [ERROR],
            status: "409",
            scimType: "uniqueness",
            detail: "userName must be unique.",
          },
        });
    });
  });

  describe("groups", () => {
    it("creates, renames, replaces members and deletes a group", async () => {
      const s = await stack();
      const ada = await create(s, "ada", { displayName: "Ada" });
      const grace = await create(s, "grace");
      const response = await s.request("POST", "/Groups", {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: "posted-members",
        externalId: "pk-1",
        members: [{ value: ada }],
      });
      expect(response.status).toBe(201);
      const created = (await response.json()) as Record<string, unknown>;
      const id = created.id as string;
      expect(response.headers.get("location")).toBe(
        `https://api.posted.example.com/scim/v2/Groups/${id}`,
      );
      expect(created).toMatchObject({
        displayName: "posted-members",
        externalId: "pk-1",
        members: [
          {
            value: ada,
            display: "Ada",
            type: "User",
            $ref: `https://api.posted.example.com/scim/v2/Users/${ada}`,
          },
        ],
      });
      const put = await s.json("PUT", `/Groups/${id}`, {
        displayName: "posted-members",
        members: [{ value: grace }],
      });
      expect(
        (put.body.members as { value: string }[]).map((m) => m.value),
      ).toEqual([grace]);
      const rename = await s.json("PUT", `/Groups/${id}`, {
        displayName: "Posted Members",
      });
      expect(rename.body).toMatchObject({
        displayName: "Posted Members",
        externalId: "pk-1",
      });
      expect((rename.body.members as unknown[]).length).toBe(1);
      expect((await s.request("DELETE", `/Groups/${id}`)).status).toBe(204);
      expect((await s.json("GET", `/Groups/${id}`)).status).toBe(404);
    });

    it("lists with a displayName filter and without members", async () => {
      const s = await stack();
      const ada = await create(s, "ada");
      await group(s, "posted-admins", [ada]);
      await group(s, "posted-members", [ada]);
      const { body } = await s.json(
        "GET",
        `/Groups?filter=${encodeURIComponent('displayName eq "POSTED-ADMINS"')}&excludedAttributes=members`,
      );
      expect(body.totalResults).toBe(1);
      const [found] = body.Resources as Record<string, unknown>[];
      expect(found?.displayName).toBe("posted-admins");
      expect(found).not.toHaveProperty("members");
    });

    it("refuses duplicate names, ignoring case, and unknown members", async () => {
      const s = await stack();
      await group(s, "posted-admins");
      expect(
        (await s.json("POST", "/Groups", { displayName: "Posted-Admins" }))
          .body,
      ).toMatchObject({
        status: "409",
        scimType: "uniqueness",
      });
      expect(
        (
          await s.json("POST", "/Groups", {
            displayName: "x",
            members: [{ value: "00000000-0000-4000-8000-000000000000" }],
          })
        ).body,
      ).toMatchObject({ status: "400", scimType: "invalidValue" });
      expect(
        (await s.json("POST", "/Groups", { displayName: "" })).body,
      ).toMatchObject({ scimType: "invalidValue" });
    });
  });

  describe("roles from SCIM groups", () => {
    const SCIM = { POSTED_ROLE_SOURCE: "scim" };

    it("gives the highest mapped role and downgrades immediately on removal", async () => {
      const s = await stack(SCIM);
      const id = await create(s, "ada");
      expect(await userRow(s, id)).toMatchObject({ role: null, source: null });
      const admins = await group(s, "posted-admins", [id]);
      const members = await group(s, "Posted-Members", [id]);
      await group(s, "unrelated", [id]);
      expect(await userRow(s, id)).toMatchObject({
        role: "admin",
        source: "scim",
      });
      const { sessions, token } = await startSession(s, id);

      const removed = await s.json(
        "PATCH",
        `/Groups/${admins}`,
        patchBody({ op: "remove", path: `members[value eq "${id}"]` }),
      );
      expect(removed.status).toBe(200);
      expect(await userRow(s, id)).toMatchObject({
        role: "member",
        source: "scim",
      });
      expect((await sessions.lookup(token))?.actor.role).toBe("member");

      await s.json(
        "PATCH",
        `/Groups/${members}`,
        patchBody({ op: "remove", path: "members", value: [{ value: id }] }),
      );
      expect(await userRow(s, id)).toMatchObject({
        role: null,
        source: "scim",
      });
      expect(await sessions.lookup(token)).toBeNull();
      expect(s.hooks).toEqual([
        { hook: "role", userId: id, from: null, to: "admin" },
        { hook: "role", userId: id, from: "admin", to: "member" },
        { hook: "role", userId: id, from: "member", to: null },
      ]);
    });

    it("recomputes when a group is renamed or deleted", async () => {
      const s = await stack(SCIM);
      const id = await create(s, "ada");
      const g = await group(s, "posted-viewers", [id]);
      expect(await userRow(s, id)).toMatchObject({ role: "viewer" });
      await s.json(
        "PATCH",
        `/Groups/${g}`,
        patchBody({ op: "replace", value: { displayName: "posted-admins" } }),
      );
      expect(await userRow(s, id)).toMatchObject({ role: "admin" });
      await s.request("DELETE", `/Groups/${g}`);
      expect(await userRow(s, id)).toMatchObject({
        role: null,
        source: "scim",
      });
    });

    it("leaves roles alone in claims mode", async () => {
      const s = await stack();
      const id = await create(s, "ada");
      await group(s, "posted-admins", [id]);
      expect(await userRow(s, id)).toMatchObject({ role: null, source: null });
      expect(s.hooks).toEqual([]);
    });

    it("keeps the role consistent under concurrent membership changes", async () => {
      const s = await stack(SCIM);
      const ids = [await create(s, "ada"), await create(s, "grace")];
      const groups = [
        await group(s, "posted-viewers"),
        await group(s, "posted-members"),
        await group(s, "posted-admins"),
      ];
      for (let round = 0; round < 3; round++) {
        const results = await Promise.all(
          groups.map((g) =>
            s.json(
              "PATCH",
              `/Groups/${g}`,
              patchBody({
                op: "add",
                path: "members",
                value: ids.map((value) => ({ value })),
              }),
            ),
          ),
        );
        expect(results.map((r) => r.status)).toEqual([200, 200, 200]);
        for (const id of ids)
          expect(await userRow(s, id)).toMatchObject({
            role: "admin",
            source: "scim",
          });
        const removals = await Promise.all(
          [groups[2], groups[1]].map((g) =>
            s.json(
              "PATCH",
              `/Groups/${g}`,
              patchBody({
                op: "remove",
                path: "members",
                value: ids.map((value) => ({ value })),
              }),
            ),
          ),
        );
        expect(removals.map((r) => r.status)).toEqual([200, 200]);
        for (const id of ids)
          expect(await userRow(s, id)).toMatchObject({
            role: "viewer",
            source: "scim",
          });
        await s.json(
          "PATCH",
          `/Groups/${groups[0]}`,
          patchBody({ op: "remove", path: "members" }),
        );
        for (const id of ids)
          expect(await userRow(s, id)).toMatchObject({
            role: null,
            source: "scim",
          });
      }
    });
  });
});
