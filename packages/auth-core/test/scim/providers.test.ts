import { afterEach, describe, expect, it } from "vitest";
import { createSessions } from "../../src/sessions/index.js";
import { databaseUrl } from "../postgres/support.js";
import { authentik, entra, okta } from "./fixtures.js";
import { startScim, type ScimStack } from "./support.js";

const stacks: ScimStack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});
async function stack(): Promise<ScimStack> {
  const s = await startScim({ POSTED_ROLE_SOURCE: "scim" });
  stacks.push(s);
  return s;
}

async function user(s: ScimStack, id: string) {
  const [row] = await s.rows<Record<string, unknown>>(
    `SELECT role, role_source AS "source", active, deleted_at IS NOT NULL AS "deleted",
       user_name AS "userName", email, display_name AS "displayName"
     FROM {schema}.users WHERE id = $1`,
    [id],
  );
  return row;
}

async function session(s: ScimStack, userId: string) {
  const sessions = createSessions({ sql: s.sql, config: s.config });
  const { token } = await sessions.create({
    userId,
    authenticatedAt: new Date(),
    amr: [],
    providerSid: null,
  });
  return { live: async () => (await sessions.lookup(token)) !== null };
}

describe.skipIf(!databaseUrl)("provider request fixtures", () => {
  it("authentik: create, replace, group membership, deactivate, delete", async () => {
    const s = await stack();
    const created = await s.json("POST", "/Users", authentik.user());
    expect(created.status).toBe(201);
    const id = created.body.id as string;
    // A full sync rewrites everyone with PUT; an unchanged one is a no-op.
    expect((await s.json("PUT", `/Users/${id}`, authentik.user())).status).toBe(
      200,
    );
    expect(
      (
        await s.json(
          "PUT",
          `/Users/${id}`,
          authentik.user({ name: "Ada King" }),
        )
      ).body,
    ).toMatchObject({
      displayName: "Ada King",
    });

    const g = await s.json("POST", "/Groups", authentik.group([]));
    expect(g.status).toBe(201);
    const groupId = g.body.id as string;
    expect(
      (await s.json("PATCH", `/Groups/${groupId}`, authentik.addMember(id)))
        .status,
    ).toBe(200);
    expect(await user(s, id)).toMatchObject({ role: "admin", source: "scim" });
    expect(
      (await s.json("PATCH", `/Groups/${groupId}`, authentik.replaceGroup()))
        .status,
    ).toBe(200);
    expect(await user(s, id)).toMatchObject({ role: "admin" });

    const signedIn = await session(s, id);
    expect(
      (await s.json("PATCH", `/Groups/${groupId}`, authentik.removeMember(id)))
        .status,
    ).toBe(200);
    expect(await user(s, id)).toMatchObject({ source: "none" });
    expect(await signedIn.live()).toBe(false);

    await s.json("PATCH", `/Groups/${groupId}`, authentik.addMember(id));
    const again = await session(s, id);
    // Deactivation arrives as a PUT with active: false.
    expect(
      (await s.json("PUT", `/Users/${id}`, authentik.user({ active: false })))
        .body.active,
    ).toBe(false);
    expect(await again.live()).toBe(false);
    // Leaving the app's scope is a DELETE.
    expect((await s.request("DELETE", `/Users/${id}`)).status).toBe(204);
    expect(await user(s, id)).toMatchObject({ deleted: true });
    // The next full sync tries to recreate the same person: refused.
    expect((await s.json("POST", "/Users", authentik.user())).status).toBe(409);
  });

  it("Okta: lookup by userName, create, PUT, group push, PATCH deactivation", async () => {
    const s = await stack();
    const lookup = await s.json(
      "GET",
      `/Users?filter=${encodeURIComponent('userName eq "grace@example.com"')}&startIndex=1&count=100`,
    );
    expect(lookup.body).toMatchObject({ totalResults: 0, Resources: [] });
    const created = await s.json("POST", "/Users", okta.user());
    expect(created.status).toBe(201);
    const id = created.body.id as string;
    expect(created.body).not.toHaveProperty("password");
    expect(
      (await s.json("PUT", `/Users/${id}`, okta.replace(id))).body,
    ).toMatchObject({
      name: { familyName: "Brewster Hopper" },
    });

    const g = await s.json("POST", "/Groups", okta.group());
    const groupId = g.body.id as string;
    await s.json("PATCH", `/Groups/${groupId}`, okta.addMember(id));
    expect(await user(s, id)).toMatchObject({ role: "member", source: "scim" });
    await s.json("PATCH", `/Groups/${groupId}`, okta.rename(groupId));
    expect(await user(s, id)).toMatchObject({ role: "admin" });
    await s.json("PATCH", `/Groups/${groupId}`, okta.removeMember(id));
    expect(await user(s, id)).toMatchObject({ source: "none" });

    const off = await s.json("PATCH", `/Users/${id}`, okta.deactivate());
    expect(off.body.active).toBe(false);
    expect(await user(s, id)).toMatchObject({ active: false });
    expect((await s.request("DELETE", `/Groups/${groupId}`)).status).toBe(204);
    expect((await s.request("DELETE", `/Users/${id}`)).status).toBe(204);
    expect(await user(s, id)).toMatchObject({ deleted: true });
  });

  it("Entra: probe, create with the enterprise extension, capitalised PATCH, string booleans, delete", async () => {
    const s = await stack();
    const probe = await s.json(
      "GET",
      `/Users?filter=${encodeURIComponent('userName eq "linus@example.com"')}`,
    );
    expect(probe.body.totalResults).toBe(0);
    const created = await s.json("POST", "/Users", entra.user());
    expect(created.status).toBe(201);
    const id = created.body.id as string;
    expect(created.body).not.toHaveProperty([
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    ]);
    // Entra checks for the user by its userName in a different case.
    expect(
      (
        await s.json(
          "GET",
          `/Users?filter=${encodeURIComponent('userName eq "linus@example.com"')}`,
        )
      ).body.totalResults,
    ).toBe(1);

    const updated = await s.json("PATCH", `/Users/${id}`, entra.update());
    expect(updated.status).toBe(200);
    expect(await user(s, id)).toMatchObject({
      displayName: "Linus B. Torvalds",
      email: "linus@kernel.example.com",
    });
    expect(updated.body).toMatchObject({
      name: { givenName: "Linus Benedict" },
    });

    const g = await s.json("POST", "/Groups", entra.group());
    const groupId = g.body.id as string;
    await s.json("PATCH", `/Groups/${groupId}`, entra.addMember(id));
    expect(await user(s, id)).toMatchObject({ role: "viewer", source: "scim" });
    const list = await s.json(
      "GET",
      `/Groups?filter=${encodeURIComponent('displayName eq "posted-viewers"')}&excludedAttributes=members`,
    );
    expect(list.body.totalResults).toBe(1);

    const signedIn = await session(s, id);
    expect(
      (await s.json("PATCH", `/Users/${id}`, entra.disable())).body.active,
    ).toBe(false);
    expect(await signedIn.live()).toBe(false);
    expect(
      (await s.json("PATCH", `/Users/${id}`, entra.enable())).body.active,
    ).toBe(true);
    await s.json("PATCH", `/Groups/${groupId}`, entra.removeMember(id));
    expect(await user(s, id)).toMatchObject({ source: "none" });
    expect((await s.request("DELETE", `/Users/${id}`)).status).toBe(204);
    expect((await s.json("GET", `/Users/${id}`)).status).toBe(404);
  });
});
