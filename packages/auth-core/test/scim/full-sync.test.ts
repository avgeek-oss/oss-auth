import { afterEach, describe, expect, it } from "vitest";
import { createApiKeys, type ApiKeys } from "../../src/api-keys/index.js";
import type { Role } from "../../src/index.js";
import { createSessions } from "../../src/sessions/index.js";
import { adapters, databaseUrl, type Adapter } from "../postgres/support.js";
import { startScim, userBody, type ScimStack } from "./support.js";

// authentik's full sync, every 10 minutes, rewrites every user with PUT and
// every group with PUT and its full member list, whether or not anything
// changed. Keys are revoked when a role drops, so a sync that lowered a
// role even for a moment would kill every key within 10 minutes.

const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";

const stacks: ScimStack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});

async function setUp(adapter: Adapter) {
  const s = await startScim({ POSTED_ROLE_SOURCE: "scim" }, { adapter });
  stacks.push(s);
  const keys: ApiKeys<object> = createApiKeys({ sql: s.sql, config: s.config });
  const sessions = createSessions({ sql: s.sql, config: s.config });

  const user = async (name: string) => {
    const r = await s.json(
      "POST",
      "/Users",
      userBody(`${name}@example.com`, {
        externalId: `ak-${name}`,
        displayName: name,
        name: { givenName: name, familyName: "Example" },
        emails: [
          { value: `${name}@example.com`, type: "other", primary: true },
        ],
      }),
    );
    expect(r.status).toBe(201);
    return r.body.id as string;
  };
  const group = async (displayName: string, members: string[]) => {
    const r = await s.json("POST", "/Groups", {
      schemas: [GROUP],
      displayName,
      externalId: `ak-${displayName}`,
      members: members.map((value) => ({ value })),
    });
    expect(r.status).toBe(201);
    return r.body.id as string;
  };
  /** A group's PUT body as authentik builds it: name, pk and every member. */
  const groupPut = (displayName: string, members: string[], upper = false) => ({
    schemas: [GROUP],
    displayName,
    externalId: `ak-${displayName}`,
    members: members.map((value) => ({
      value: upper ? value.toUpperCase() : value,
    })),
  });
  const snapshot = () =>
    s.rows<{
      id: string;
      role: Role | null;
      source: string | null;
      updatedAt: Date;
    }>(
      `SELECT id, role, role_source AS "source", updated_at AS "updatedAt"
       FROM {schema}.users ORDER BY id`,
    );
  const issue = async (userId: string, ceiling: Role) =>
    (await keys.create({ userId, name: `${ceiling} key`, ceiling })).key;
  const signIn = async (userId: string) =>
    (
      await sessions.create({
        userId,
        authenticatedAt: new Date(),
        amr: ["mfa"],
        providerSid: null,
      })
    ).token;
  return { s, keys, sessions, user, group, groupPut, snapshot, issue, signIn };
}

describe.skipIf(!databaseUrl).each(adapters)(
  "authentik full sync with $name",
  (adapter) => {
    it("replays PUT on every user and group without touching roles, keys or sessions", async () => {
      const t = await setUp(adapter);
      const ada = await t.user("ada");
      const grace = await t.user("grace");
      const linus = await t.user("linus");
      const groups = {
        "posted-admins": [grace, ada],
        "posted-members": [ada, linus],
        "posted-viewers": [linus],
      };
      const ids: Record<string, string> = {};
      for (const [name, members] of Object.entries(groups))
        ids[name] = await t.group(name, members);

      const before = await t.snapshot();
      expect(Object.fromEntries(before.map((u) => [u.id, u.role]))).toEqual({
        [ada]: "admin",
        [grace]: "admin",
        [linus]: "member",
      });
      const keys = [
        await t.issue(ada, "admin"),
        await t.issue(ada, "member"),
        await t.issue(grace, "admin"),
        await t.issue(linus, "member"),
        await t.issue(linus, "viewer"),
      ];
      const tokens = [
        await t.signIn(ada),
        await t.signIn(grace),
        await t.signIn(linus),
      ];
      const hooks = t.s.hooks.length;
      const userBodies = await Promise.all(
        [ada, grace, linus].map(async (id) => {
          const { body } = await t.s.json("GET", `/Users/${id}`);
          return { id, body };
        }),
      );

      const sync = async (upper: boolean) => {
        for (const { id, body } of userBodies)
          expect((await t.s.json("PUT", `/Users/${id}`, body)).status).toBe(
            200,
          );
        for (const [name, members] of Object.entries(groups))
          expect(
            (
              await t.s.json(
                "PUT",
                `/Groups/${ids[name]}`,
                t.groupPut(name, [...members].reverse(), upper),
              )
            ).status,
          ).toBe(200);
      };
      // Three syncs in a row, one with upper-case member ids, then one
      // with every request at once, as overlapping sync tasks would.
      await sync(false);
      await sync(true);
      await sync(false);
      const parallel = await Promise.all([
        ...userBodies.map(({ id, body }) =>
          t.s.json("PUT", `/Users/${id}`, body),
        ),
        ...Object.entries(groups).map(([name, members]) =>
          t.s.json("PUT", `/Groups/${ids[name]}`, t.groupPut(name, members)),
        ),
      ]);
      expect(parallel.map((r) => r.status)).toEqual(parallel.map(() => 200));

      // Nothing was written: not even updated_at moved.
      expect(await t.snapshot()).toEqual(before);
      expect(t.s.hooks).toHaveLength(hooks);
      for (const key of keys) expect(await t.keys.verify(key)).not.toBeNull();
      for (const token of tokens)
        expect(await t.sessions.lookup(token)).not.toBeNull();
      const [{ revoked } = { revoked: -1 }] = await t.s.rows<{
        revoked: number;
      }>(
        `SELECT count(*)::int AS "revoked" FROM {schema}.api_keys WHERE revoked_at IS NOT NULL`,
      );
      expect(revoked).toBe(0);
    });

    it("moves a user from posted-admins to posted-members in one PUT, revoking only keys above member", async () => {
      const t = await setUp(adapter);
      const ada = await t.user("ada");
      const grace = await t.user("grace");
      const admins = await t.group("posted-admins", [ada, grace]);
      await t.group("posted-members", [ada]);
      const admin = await t.issue(ada, "admin");
      const member = await t.issue(ada, "member");
      const viewer = await t.issue(ada, "viewer");
      const graceKey = await t.issue(grace, "admin");
      const token = await t.signIn(ada);
      const hooks = t.s.hooks.length;

      // The full member list of posted-admins, now without Ada.
      const put = await t.s.json(
        "PUT",
        `/Groups/${admins}`,
        t.groupPut("posted-admins", [grace]),
      );
      expect(put.status).toBe(200);
      expect(t.s.hooks.slice(hooks)).toEqual([
        { hook: "role", userId: ada, from: "admin", to: "member" },
      ]);
      expect(await t.keys.verify(admin)).toBeNull();
      expect((await t.keys.verify(member))?.actor.role).toBe("member");
      expect((await t.keys.verify(viewer))?.actor.role).toBe("viewer");
      expect((await t.keys.verify(graceKey))?.actor.role).toBe("admin");
      expect((await t.sessions.lookup(token))?.actor.role).toBe("member");
      expect((await t.keys.list(ada)).map((k) => k.ceiling).sort()).toEqual([
        "member",
        "viewer",
      ]);
    });

    it("renames posted-admins to posted-members in one PUT, revoking only keys above member", async () => {
      const t = await setUp(adapter);
      const ada = await t.user("ada");
      const g = await t.group("posted-admins", [ada]);
      const admin = await t.issue(ada, "admin");
      const member = await t.issue(ada, "member");
      const token = await t.signIn(ada);
      const hooks = t.s.hooks.length;

      const put = await t.s.json(
        "PUT",
        `/Groups/${g}`,
        t.groupPut("posted-members", [ada]),
      );
      expect(put.status).toBe(200);
      expect(t.s.hooks.slice(hooks)).toEqual([
        { hook: "role", userId: ada, from: "admin", to: "member" },
      ]);
      expect(await t.keys.verify(admin)).toBeNull();
      expect((await t.keys.verify(member))?.actor.role).toBe("member");
      expect((await t.sessions.lookup(token))?.actor.role).toBe("member");
    });
  },
);
