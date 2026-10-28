import { Hono } from "hono";
import { afterEach, describe, expect, it } from "vitest";
import { createScim } from "../../src/scim/index.js";
import { databaseUrl } from "../postgres/support.js";
import { rows, startStack, WEB, type Stack } from "./support.js";

const TOKEN = "scim-test-token-".repeat(3);
const stacks: Stack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});

/** A sign-in stack with a SCIM server on the same database. */
async function stack(env: Record<string, string>) {
  const s = await startStack({ env: { POSTED_SCIM_TOKENS: TOKEN, ...env } });
  stacks.push(s);
  const app = new Hono();
  app.route(
    "/scim/v2",
    createScim({ config: s.config, sql: s.sql, sessions: s.auth.sessions }),
  );
  const scim = async (method: string, path: string, body?: unknown) => {
    const response = await app.request(`/scim/v2${path}`, {
      method,
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/scim+json",
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return {
      status: response.status,
      body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
    };
  };
  const provision = async (
    externalId: string,
    userName = `${externalId}@example.com`,
  ) => {
    const { status, body } = await scim("POST", "/Users", {
      userName,
      externalId,
      active: true,
    });
    expect(status).toBe(201);
    return body.id as string;
  };
  const addToGroup = async (displayName: string, userId: string) => {
    const { status } = await scim("POST", "/Groups", {
      displayName,
      members: [{ value: userId }],
    });
    expect(status).toBe(201);
  };
  const users = () =>
    rows<{ id: string; sub: string | null; role: string; source: string }>(
      s,
      `SELECT id, sub, role, role_source AS "source" FROM {schema}.users ORDER BY created_at`,
    );
  const role = async () => {
    const response = await s.call("/auth/session");
    return response.status === 200
      ? ((await response.json()) as { role: string }).role
      : null;
  };
  return { s, scim, provision, addToGroup, users, role };
}

function failure(url: URL) {
  expect(url.origin).toBe(WEB);
  return url.searchParams.get("auth_error_reason");
}

describe.skipIf(!databaseUrl)("SCIM users at sign-in", () => {
  it("links a provisioned user by externalId = sub when configured", async () => {
    const t = await stack({ POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "true" });
    const id = await t.provision("ada");
    t.s.mock.setLogin({ sub: "ada" });
    expect((await t.s.signIn()).href).toBe(`${WEB}/`);
    expect(await t.users()).toEqual([
      { id, sub: "ada", role: "member", source: "oidc" },
    ]);
    expect(await t.role()).toBe("member");
  });

  it("leaves a provisioned user unlinked without the setting", async () => {
    const t = await stack({});
    const id = await t.provision("ada");
    t.s.mock.setLogin({ sub: "ada" });
    await t.s.signIn();
    const all = await t.users();
    expect(all).toHaveLength(2);
    expect(all[0]).toMatchObject({ id, sub: null });
    expect(all[1]).toMatchObject({ sub: "ada", source: "oidc" });
  });

  it("never links by email", async () => {
    const t = await stack({ POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "true" });
    // Same email as the mock's Ada, but a different externalId.
    await t.provision("someone-else", "ada@example.com");
    t.s.mock.setLogin({ sub: "ada" });
    await t.s.signIn();
    const all = await t.users();
    expect(all.map((u) => u.sub)).toEqual([null, "ada"]);
  });

  it("refuses a deleted user, instead of recreating them, until SCIM provisions them again", async () => {
    const t = await stack({ POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "true" });
    const id = await t.provision("ada");
    expect((await t.scim("DELETE", `/Users/${id}`)).status).toBe(204);
    t.s.mock.setLogin({ sub: "ada" });
    expect(failure(await t.s.signIn())).toBe("user_deleted");
    expect(await t.users()).toHaveLength(1);
    // Revived by SCIM, the same row signs in and takes the claim's role.
    expect(await t.provision("ada")).toBe(id);
    expect((await t.s.signIn()).href).toBe(`${WEB}/`);
    expect(await t.users()).toEqual([
      { id, sub: "ada", role: "member", source: "oidc" },
    ]);
  });

  it("treats a provisioned user with no role claim as unassigned in claims mode", async () => {
    const t = await stack({ POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "true" });
    await t.provision("claimless");
    t.s.mock.setLogin({ sub: "claimless" });
    expect(failure(await t.s.signIn())).toBe("no_role");
  });

  describe("with roles from SCIM", () => {
    const SCIM = {
      POSTED_ROLE_SOURCE: "scim",
      POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "true",
    };

    it("signs in with the role SCIM groups give, ignoring the role claim", async () => {
      const t = await stack(SCIM);
      const id = await t.provision("ada");
      await t.addToGroup("posted-admins", id);
      t.s.mock.setLogin({ sub: "ada" });
      expect((await t.s.signIn()).href).toBe(`${WEB}/`);
      expect(await t.role()).toBe("admin");
      expect(await t.users()).toEqual([
        { id, sub: "ada", role: "admin", source: "scim" },
      ]);
    });

    it("ends the session and refuses sign-in once no mapped group remains", async () => {
      const t = await stack(SCIM);
      const id = await t.provision("ada");
      const { body } = await t.scim("POST", "/Groups", {
        displayName: "posted-admins",
        members: [{ value: id }],
      });
      t.s.mock.setLogin({ sub: "ada" });
      await t.s.signIn();
      expect(await t.role()).toBe("admin");
      await t.scim("PATCH", `/Groups/${String(body.id)}`, {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "remove", path: `members[value eq "${id}"]` }],
      });
      expect(await t.role()).toBeNull();
      expect(failure(await t.s.signIn())).toBe("unassigned");
    });

    it("signs a revived user in as the same person once a group gives a role", async () => {
      const t = await stack(SCIM);
      const id = await t.provision("ada");
      await t.addToGroup("posted-admins", id);
      t.s.mock.setLogin({ sub: "ada" });
      await t.s.signIn();
      expect(await t.role()).toBe("admin");
      await t.scim("DELETE", `/Users/${id}`);
      expect(await t.role()).toBeNull();
      expect(failure(await t.s.signIn())).toBe("user_deleted");

      expect(await t.provision("ada")).toBe(id);
      expect(failure(await t.s.signIn())).toBe("unassigned");
      await t.addToGroup("posted-members", id);
      expect((await t.s.signIn()).href).toBe(`${WEB}/`);
      expect(await t.role()).toBe("member");
      expect(await t.users()).toEqual([
        { id, sub: "ada", role: "member", source: "scim" },
      ]);
    });

    it("refuses a user with no mapped group", async () => {
      const t = await stack(SCIM);
      const id = await t.provision("ada");
      await t.addToGroup("unrelated", id);
      t.s.mock.setLogin({ sub: "ada" });
      expect(failure(await t.s.signIn())).toBe("unassigned");
    });

    it("refuses an unprovisioned person and creates no user", async () => {
      const t = await stack(SCIM);
      t.s.mock.setLogin({ sub: "grace" });
      expect(failure(await t.s.signIn())).toBe("unassigned");
      expect(await t.users()).toEqual([]);
    });

    it("refuses an unlinked provisioned user without creating a duplicate", async () => {
      const t = await stack({ POSTED_ROLE_SOURCE: "scim" });
      const id = await t.provision("ada");
      await t.addToGroup("posted-admins", id);
      t.s.mock.setLogin({ sub: "ada" });
      expect(failure(await t.s.signIn())).toBe("unassigned");
      expect(await t.users()).toHaveLength(1);
    });

    it("still refuses when the role claim maps to nothing", async () => {
      const t = await stack(SCIM);
      const id = await t.provision("nobody");
      await t.addToGroup("posted-admins", id);
      t.s.mock.setLogin({ sub: "nobody" });
      expect(failure(await t.s.signIn())).toBe("no_role");
    });
  });
});
