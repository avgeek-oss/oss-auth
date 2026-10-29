import { afterEach, describe, expect, it } from "vitest";
import { createBrowser } from "../../src/testing/index.js";
import { databaseUrl } from "../postgres/support.js";
import {
  rows,
  startStack,
  WEB,
  type Stack,
  type StackOptions,
} from "./support.js";

const stacks: Stack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});
async function stack(options: StackOptions = {}): Promise<Stack> {
  const s = await startStack(options);
  stacks.push(s);
  return s;
}

interface UserJson {
  id: string;
  displayName: string | null;
  email: string | null;
  role: string | null;
  roleSource: string | null;
  status: string;
  createdAt: string;
  lastSignInAt: string | null;
  deactivatedAt: string | null;
  deletedAt: string | null;
}
interface PageJson {
  users: UserJson[];
  nextCursor: string | null;
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Signs in as `sub` in a browser of its own; `get` reads the API. */
async function signedIn(s: Stack, sub: string) {
  const browser = createBrowser();
  s.mock.setLogin({ sub, amr: ["mfa"] });
  const landed = await browser.follow(`${s.api}/auth/sign-in`, {
    stopAt: (url) => url.origin === WEB,
  });
  const get = async (path: string) => {
    const response = await browser.fetch(`${s.api}${path}`, {
      headers: { origin: WEB },
    });
    return {
      status: response.status,
      headers: response.headers,
      body: (await response.json()) as Record<string, unknown>,
    };
  };
  const page = async (query = "") => {
    const r = await get(`/auth/admin/users${query}`);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    return r.body as unknown as PageJson;
  };
  return { landed: new URL(landed.url), browser, get, page };
}

/** Inserts a user row directly, as SCIM or an earlier sign-in would leave it. */
async function insertUser(
  s: Stack,
  fields: Record<string, unknown>,
): Promise<string> {
  const values = { iss: s.mock.issuer, ...fields };
  const names = Object.keys(values);
  const [row] = await rows<{ id: string }>(
    s,
    `INSERT INTO {schema}.users (${names.join(", ")})
     VALUES (${names.map((_, i) => `$${i + 1}`).join(", ")}) RETURNING id`,
    Object.values(values),
  );
  return row?.id ?? "";
}

describe.skipIf(!databaseUrl)("the people directory over HTTP", () => {
  it("lists everyone for an admin, with role, source, status and last sign-in", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    s.advance(2);
    const grace = await signedIn(s, "grace");
    const provisioned = await insertUser(s, {
      external_id: "ext-pat",
      email: "pat@example.com",
      display_name: "Pat",
      role: "viewer",
      role_source: "scim",
    });
    const suspended = await insertUser(s, {
      sub: "sam",
      email: "sam@example.com",
      display_name: "Sam",
      role: null,
      role_source: "scim",
    });
    const deactivated = await insertUser(s, {
      sub: "dee",
      email: "dee@example.com",
      display_name: "Dee",
      role: "member",
      role_source: "scim",
      active: false,
      deactivated_at: new Date("2026-10-01T00:00:00Z"),
    });
    const deleted = await insertUser(s, {
      sub: "del",
      email: "del@example.com",
      role: null,
      active: false,
      deactivated_at: new Date("2026-10-01T00:00:00Z"),
      deleted_at: new Date("2026-10-02T00:00:00Z"),
    });

    const r = await grace.get("/auth/admin/users");
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    const { users, nextCursor } = r.body as unknown as PageJson;
    expect(nextCursor).toBeNull();
    for (const user of users) {
      expect(Object.keys(user).sort()).toEqual(
        [
          "createdAt",
          "deactivatedAt",
          "deletedAt",
          "displayName",
          "email",
          "id",
          "lastSignInAt",
          "role",
          "roleSource",
          "status",
        ].sort(),
      );
      expect(user.createdAt).toMatch(ISO);
    }
    const bySub = new Map(users.map((u) => [u.email, u]));
    const sessions = await rows<{ sub: string; createdAt: Date }>(
      s,
      `SELECT u.sub, s.created_at AS "createdAt" FROM {schema}.sessions s
       JOIN {schema}.users u ON u.id = s.user_id`,
    );
    const signedInAt = (sub: string) =>
      sessions.find((x) => x.sub === sub)?.createdAt.toISOString();
    expect(bySub.get("ada@example.com")).toMatchObject({
      displayName: "Ada",
      role: "member",
      roleSource: "claims",
      status: "active",
      lastSignInAt: signedInAt("ada"),
      deactivatedAt: null,
      deletedAt: null,
    });
    expect(bySub.get("grace@example.com")).toMatchObject({
      role: "admin",
      roleSource: "claims",
      status: "active",
      lastSignInAt: signedInAt("grace"),
    });
    expect(bySub.get("pat@example.com")).toMatchObject({
      id: provisioned,
      role: "viewer",
      roleSource: "scim",
      status: "active",
      lastSignInAt: null,
    });
    expect(bySub.get("sam@example.com")).toMatchObject({
      id: suspended,
      role: null,
      status: "suspended",
    });
    expect(bySub.get("dee@example.com")).toMatchObject({
      id: deactivated,
      status: "deactivated",
      deactivatedAt: "2026-10-01T00:00:00.000Z",
      deletedAt: null,
    });
    expect(bySub.get("del@example.com")).toMatchObject({
      id: deleted,
      status: "deleted",
      roleSource: null,
      deletedAt: "2026-10-02T00:00:00.000Z",
    });
    expect(users).toHaveLength(6);
    // Newest first.
    expect(users.map((u) => u.createdAt)).toEqual(
      users
        .map((u) => u.createdAt)
        .sort()
        .reverse(),
    );
    expect(ada.landed.origin).toBe(WEB);
  });

  it("filters by status and searches names and emails, matching % and _ literally", async () => {
    const s = await stack();
    const grace = await signedIn(s, "grace");
    await insertUser(s, { sub: "sam", display_name: "Sam O'Neil", role: null });
    await insertUser(s, {
      sub: "dee",
      email: "dee_100%@Example.com",
      role: "member",
      active: false,
      deactivated_at: new Date(),
    });
    await insertUser(s, {
      sub: "x1",
      email: "dee1100x@example.com",
      role: "viewer",
    });

    const emails = async (query: string) =>
      (await grace.page(query)).users.map((u) => u.email ?? u.displayName);
    expect(await emails("?status=suspended")).toEqual(["Sam O'Neil"]);
    expect(await emails("?status=deactivated")).toEqual([
      "dee_100%@Example.com",
    ]);
    expect(await emails("?status=deleted")).toEqual([]);
    expect(await emails("?status=active")).toEqual([
      "dee1100x@example.com",
      "grace@example.com",
    ]);
    expect(await emails("?q=o%27neil")).toEqual(["Sam O'Neil"]);
    expect(await emails("?q=%20GRACE%40%20")).toEqual(["grace@example.com"]);
    expect(await emails(`?q=${encodeURIComponent("_100%")}`)).toEqual([
      "dee_100%@Example.com",
    ]);
    expect(await emails("?q=dee&status=active")).toEqual([
      "dee1100x@example.com",
    ]);
    expect(await emails("?q=nobody-at-all")).toEqual([]);
    // An empty search or filter is no search or filter.
    expect(await emails("?q=&status=")).toHaveLength(4);
  });

  it("pages with an opaque cursor, without gaps or repeats, even for equal creation times", async () => {
    const s = await stack();
    const grace = await signedIn(s, "grace");
    // Microseconds, which a JavaScript Date would lose: the cursor must not.
    const same = "2026-06-01T12:00:00.123456Z";
    for (let i = 0; i < 6; i++)
      await insertUser(s, {
        sub: `same-${i}`,
        email: `same-${i}@example.com`,
        role: "viewer",
        created_at: same,
      });
    for (let i = 0; i < 4; i++)
      await insertUser(s, {
        sub: `old-${i}`,
        email: `old-${i}@example.com`,
        role: "viewer",
        created_at: new Date(Date.UTC(2026, 0, 1 + i, 0, 0, 0)),
      });
    const everyone = (await grace.page()).users.map((u) => u.id);
    expect(everyone).toHaveLength(11);

    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const query: string = `?limit=3${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const page: PageJson = await grace.page(query);
      pages++;
      expect(page.users.length).toBeLessThanOrEqual(3);
      seen.push(...page.users.map((u) => u.id));
      cursor = page.nextCursor;
      if (cursor) expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
    } while (cursor && pages < 10);
    expect(pages).toBe(4);
    expect(seen).toEqual(everyone);

    // A search pages the same way.
    const first = await grace.page("?q=same-&limit=4");
    expect(first.users).toHaveLength(4);
    const second = await grace.page(
      `?q=same-&limit=4&cursor=${first.nextCursor ?? ""}`,
    );
    expect(second.users).toHaveLength(2);
    expect(second.nextCursor).toBeNull();
    expect(
      new Set([...first.users, ...second.users].map((u) => u.email)).size,
    ).toBe(6);
    // A full last page has no next cursor.
    expect((await grace.page("?q=old-&limit=4")).nextCursor).toBeNull();
    // At most 100 a page, 50 by default.
    for (let i = 0; i < 95; i++)
      await insertUser(s, { sub: `bulk-${i}`, role: "viewer" });
    expect((await grace.page()).users).toHaveLength(50);
    expect((await grace.page("?limit=100")).users).toHaveLength(100);
  });

  it("refuses bad parameters by name", async () => {
    const s = await stack();
    const grace = await signedIn(s, "grace");
    const page = await grace.page("?limit=1");
    expect(page.nextCursor).toBeNull();
    for (const query of [
      "?limit=0",
      "?limit=101",
      "?limit=abc",
      "?limit=1.5",
      "?status=suspended,deleted",
      "?status=ACTIVE",
      `?q=${"x".repeat(201)}`,
      "?cursor=garbage!",
      `?cursor=${Buffer.from("[1,2]").toString("base64url")}`,
      `?cursor=${Buffer.from('["2026-01-01T00:00:00Z","x"]').toString("base64url")}`,
      `?cursor=${Buffer.from("not json").toString("base64url")}`,
    ]) {
      const r = await grace.get(`/auth/admin/users${query}`);
      expect(r.status, query).toBe(400);
      expect(r.body, query).toMatchObject({
        error: { code: "invalid_request" },
      });
    }
  });

  it("is for admins only: 401 without a session, 403 below admin, and read-only", async () => {
    const s = await stack();
    const anonymous = await fetch(`${s.api}/auth/admin/users`);
    expect(anonymous.status).toBe(401);
    const ada = await signedIn(s, "ada");
    const member = await ada.get("/auth/admin/users");
    expect(member.status).toBe(403);
    expect(member.body).toMatchObject({ error: { code: "forbidden" } });
    // An admin's key below admin is refused; one at admin may read.
    const grace = await signedIn(s, "grace");
    const keys: Record<string, string> = {};
    for (const ceiling of ["member", "admin"]) {
      const response = await grace.browser.fetch(`${s.api}/auth/api-keys`, {
        method: "POST",
        headers: {
          origin: WEB,
          "x-requested-with": "fetch",
          "content-type": "application/json",
        },
        body: JSON.stringify({ name: ceiling, ceiling }),
      });
      expect(response.status).toBe(201);
      keys[ceiling] = ((await response.json()) as { key: string }).key;
    }
    const withKey = (key: string | undefined) =>
      fetch(`${s.api}/auth/admin/users`, {
        headers: { authorization: `Bearer ${key}` },
      });
    expect((await withKey(keys.member)).status).toBe(403);
    expect((await withKey(keys.admin)).status).toBe(200);
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const response = await grace.browser.fetch(`${s.api}/auth/admin/users`, {
        method,
        headers: { origin: WEB, "x-requested-with": "fetch" },
      });
      expect(response.status, method).toBe(404);
    }
  });

  it("locks out a suspended admin and shows them as suspended", async () => {
    const s = await stack();
    const grace = await signedIn(s, "grace");
    const ada = await signedIn(s, "ada");
    await rows(s, `UPDATE {schema}.users SET role = NULL WHERE sub = 'grace'`);
    expect((await grace.get("/auth/admin/users")).status).toBe(401);
    // Once a role comes back, here admin by hand, the session works again.
    await rows(s, `UPDATE {schema}.users SET role = 'admin' WHERE sub = 'ada'`);
    const page = await ada.page("?status=suspended");
    expect(page.users.map((u) => [u.email, u.role, u.status])).toEqual([
      ["grace@example.com", null, "suspended"],
    ]);
  });

  it("follows <APP>_ROLE_SOURCE=scim: a role from elsewhere is not honoured", async () => {
    const s = await stack({ env: { POSTED_ROLE_SOURCE: "scim" } });
    await insertUser(s, {
      sub: "grace",
      email: "grace@example.com",
      role: "admin",
      role_source: "scim",
    });
    await insertUser(s, {
      sub: "old",
      email: "old@example.com",
      role: "member",
      role_source: "oidc",
    });
    const grace = await signedIn(s, "grace");
    const { users } = await grace.page();
    expect(users.map((u) => [u.email, u.role, u.roleSource, u.status])).toEqual(
      [
        ["old@example.com", "member", "claims", "suspended"],
        ["grace@example.com", "admin", "scim", "active"],
      ],
    );
    expect(users[1]?.lastSignInAt).toMatch(ISO);
  });

  it("records a sign-in without changing what SCIM reports as last modified", async () => {
    const s = await stack();
    await signedIn(s, "ada");
    const [before] = await rows<{ updatedAt: Date; lastSignInAt: Date }>(
      s,
      `SELECT updated_at AS "updatedAt", last_sign_in_at AS "lastSignInAt"
       FROM {schema}.users WHERE sub = 'ada'`,
    );
    s.advance(120);
    await signedIn(s, "ada");
    const [after] = await rows<{ updatedAt: Date; lastSignInAt: Date }>(
      s,
      `SELECT updated_at AS "updatedAt", last_sign_in_at AS "lastSignInAt"
       FROM {schema}.users WHERE sub = 'ada'`,
    );
    expect(after?.lastSignInAt.getTime()).toBeGreaterThanOrEqual(
      (before?.lastSignInAt.getTime() ?? 0) + 120_000,
    );
    expect(after?.updatedAt.getTime()).toBe(before?.updatedAt.getTime());
  });
});
