import { afterEach, describe, expect, it } from "vitest";
import { bearerChallenge } from "../../src/mcp/index.js";
import { createScim } from "../../src/scim/index.js";
import { databaseUrl } from "../postgres/support.js";
import {
  CONFIDENTIAL_CLIENT,
  CONFIDENTIAL_SECRET,
  PUBLIC_CLIENT,
  PUBLIC_REDIRECT,
  rows,
  startMcp,
  type McpStack,
} from "./support.js";

const stacks: McpStack[] = [];
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});
async function stack(...args: Parameters<typeof startMcp>) {
  const s = await startMcp(...args);
  stacks.push(s);
  return s;
}

const DAY = 86400;

async function userId(s: McpStack, sub: string): Promise<string> {
  const [row] = await rows<{ id: string }>(
    s,
    "SELECT id FROM {schema}.users WHERE sub = $1",
    [sub],
  );
  return row?.id ?? "";
}

const setRole = (s: McpStack, sub: string, role: string | null) =>
  rows(s, "UPDATE {schema}.users SET role = $2 WHERE sub = $1", [sub, role]);

describe("bearerChallenge", () => {
  it("formats RFC 6750 and RFC 9728 challenges with quoted values", () => {
    expect(
      bearerChallenge({
        resourceMetadata:
          "https://api.example.com/.well-known/oauth-protected-resource/mcp",
        scope: "viewer",
      }),
    ).toBe(
      'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp", scope="viewer"',
    );
    expect(
      bearerChallenge({
        error: "insufficient_scope",
        description: 'Needs "admin"',
        resourceMetadata: "https://x/m",
        scope: "admin",
      }),
    ).toBe(
      'Bearer error="insufficient_scope", error_description="Needs \\"admin\\"", resource_metadata="https://x/m", scope="admin"',
    );
  });
});

describe.skipIf(!databaseUrl)("MCP tokens", () => {
  it("issues audience-bound tokens and challenges requests without one", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const tokens = await ada.tokens();
    expect(tokens).toMatchObject({
      token_type: "Bearer",
      expires_in: 900,
      scope: "member",
      access_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      refresh_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    });
    const me = await s.bearer("/mcp", tokens.access_token);
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({
      role: "member",
      user: await userId(s, "ada"),
      credential: {
        kind: "oauth",
        id: expect.any(String),
        ceiling: "member",
        workspace: null,
        restrictions: null,
      },
    });
    // requireRole works for OAuth actors too.
    expect((await s.bearer("/mcp/members", tokens.access_token)).status).toBe(
      200,
    );

    const metadata = `${s.api}/.well-known/oauth-protected-resource/mcp`;
    const none = await fetch(`${s.api}/mcp`, { method: "POST" });
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${metadata}", scope="viewer"`,
    );
    const bad = await s.bearer("/mcp", "nonsense");
    expect(bad.status).toBe(401);
    expect(bad.headers.get("www-authenticate")).toMatch(
      new RegExp(
        `^Bearer error="invalid_token", error_description="[^"]+", resource_metadata="${metadata}", scope="viewer"$`,
      ),
    );
    // Issued for /mcp, refused on /v1.
    const v1 = await s.bearer("/v1/things", tokens.access_token);
    expect(v1.status).toBe(401);
    expect(v1.headers.get("www-authenticate")).toContain(
      `resource_metadata="${s.api}/.well-known/oauth-protected-resource/v1"`,
    );
    const v1Tokens = await ada.tokens({ resource: s.v1 });
    expect((await s.bearer("/v1/things", v1Tokens.access_token)).status).toBe(
      200,
    );
    expect((await s.bearer("/mcp", v1Tokens.access_token)).status).toBe(401);

    const low = await s.bearer("/mcp/admin", tokens.access_token);
    expect(low.status).toBe(403);
    expect(low.headers.get("www-authenticate")).toMatch(
      /^Bearer error="insufficient_scope", error_description="[^"]+", resource_metadata="[^"]+", scope="admin"$/,
    );
    s.advance(901);
    expect((await s.bearer("/mcp", tokens.access_token)).status).toBe(401);
  });

  it("uses each code once, and revokes the grant only for a replay that passes the client and PKCE checks", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const c = await ada.connect();
    const exchange = (fields: Record<string, string> = {}) =>
      s.form("/oauth/token", {
        grant_type: "authorization_code",
        client_id: PUBLIC_CLIENT,
        code: c.code,
        code_verifier: c.verifier,
        redirect_uri: c.redirectUri,
        resource: c.resource,
        ...fields,
      });
    // Wrong verifier, client, redirect or resource: refused, code still unused.
    expect(
      (await exchange({ code_verifier: "x".repeat(43) })).body,
    ).toMatchObject({
      error: "invalid_grant",
    });
    expect(
      (await exchange({ redirect_uri: "http://127.0.0.1:1/callback" })).body,
    ).toMatchObject({
      error: "invalid_grant",
    });
    expect((await exchange({ client_id: CONFIDENTIAL_CLIENT })).status).toBe(
      401,
    );
    const first = await exchange();
    expect(first.status).toBe(200);
    const access = first.body.access_token as string;
    expect((await s.bearer("/mcp", access)).status).toBe(200);

    // A replay without the verifier cannot revoke anything.
    expect(
      (await exchange({ code_verifier: "y".repeat(43) })).body,
    ).toMatchObject({
      error: "invalid_grant",
    });
    expect((await s.bearer("/mcp", access)).status).toBe(200);
    // A replay that passes PKCE means the code leaked with its verifier.
    expect((await exchange()).body).toMatchObject({ error: "invalid_grant" });
    expect((await s.bearer("/mcp", access)).status).toBe(401);
    expect(await s.mcp.listGrants(await userId(s, "ada"))).toEqual([]);

    // A code older than 60 seconds is refused, and so is a wrong resource.
    const late = await ada.connect();
    s.advance(61);
    expect(
      (
        await s.form("/oauth/token", {
          grant_type: "authorization_code",
          client_id: PUBLIC_CLIENT,
          code: late.code,
          code_verifier: late.verifier,
          redirect_uri: late.redirectUri,
        })
      ).body,
    ).toMatchObject({ error: "invalid_grant" });
    const wrong = await ada.connect();
    expect(
      (
        await s.form("/oauth/token", {
          grant_type: "authorization_code",
          client_id: PUBLIC_CLIENT,
          code: wrong.code,
          code_verifier: wrong.verifier,
          redirect_uri: wrong.redirectUri,
          resource: s.v1,
        })
      ).body,
    ).toMatchObject({ error: "invalid_target" });
  });

  it("rotates refresh tokens, and a reused one revokes the family and the grant", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const first = await ada.tokens();
    const refresh = (token: string, fields: Record<string, string> = {}) =>
      s.form("/oauth/token", {
        grant_type: "refresh_token",
        client_id: PUBLIC_CLIENT,
        refresh_token: token,
        resource: s.resource,
        ...fields,
      });
    const second = await refresh(first.refresh_token);
    expect(second.status).toBe(200);
    expect(second.body.refresh_token).not.toBe(first.refresh_token);
    const third = await refresh(second.body.refresh_token as string);
    expect(third.status).toBe(200);
    expect(
      (await refresh(third.body.refresh_token as string, { resource: s.v1 }))
        .body,
    ).toMatchObject({
      error: "invalid_target",
    });
    expect(
      (
        await refresh(third.body.refresh_token as string, {
          client_id: "other",
        })
      ).status,
    ).toBe(401);

    // The first token again: someone kept a copy.
    expect((await refresh(first.refresh_token)).body).toMatchObject({
      error: "invalid_grant",
    });
    expect(
      (await refresh(third.body.refresh_token as string)).body,
    ).toMatchObject({
      error: "invalid_grant",
    });
    expect(
      (await s.bearer("/mcp", third.body.access_token as string)).status,
    ).toBe(401);
    expect(await s.mcp.listGrants(await userId(s, "ada"))).toEqual([]);
  });

  it("ends a refresh family after 30 idle days or 90 days in all", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const refresh = (token: string) =>
      s.form("/oauth/token", {
        grant_type: "refresh_token",
        client_id: PUBLIC_CLIENT,
        refresh_token: token,
      });
    const idle = await ada.tokens();
    s.advance(30 * DAY + 1);
    expect((await refresh(idle.refresh_token)).body).toMatchObject({
      error: "invalid_grant",
    });

    // The session has expired meanwhile: sign in again.
    let token = (await (await s.person("ada")).tokens()).refresh_token;
    for (let day = 0; day < 80; day += 20) {
      s.advance(20 * DAY);
      const next = await refresh(token);
      expect(next.status, `day ${day + 20}`).toBe(200);
      token = next.body.refresh_token as string;
    }
    // Day 100 of a family that started on day 0: past the 90-day limit.
    s.advance(20 * DAY);
    expect((await refresh(token)).body).toMatchObject({
      error: "invalid_grant",
    });
  });

  it("purges what expired more than a day ago, keeping grants", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const tokens = await ada.tokens();
    await ada.connect();
    expect(await s.mcp.purgeExpired()).toEqual({
      requests: 0,
      codes: 0,
      tokens: 0,
    });
    s.advance(2 * 86400);
    // Two consent requests, two codes and the access token have expired.
    expect(await s.mcp.purgeExpired()).toEqual({
      requests: 2,
      codes: 2,
      tokens: 1,
    });
    expect(await s.mcp.listGrants(await userId(s, "ada"))).toHaveLength(2);
    expect(tokens.refresh_token).toBeDefined();
  });

  it("authenticates confidential clients with HTTP Basic", async () => {
    const s = await stack();
    const grace = await s.person("grace");
    const c = await grace.connect({ client: CONFIDENTIAL_CLIENT });
    const fields = {
      grant_type: "authorization_code",
      code: c.code,
      code_verifier: c.verifier,
      redirect_uri: c.redirectUri,
    };
    const without = await s.form("/oauth/token", {
      ...fields,
      client_id: CONFIDENTIAL_CLIENT,
    });
    expect(without.status).toBe(401);
    expect(without.headers.get("www-authenticate")).toMatch(/^Basic/);
    expect(
      (
        await s.form("/oauth/token", fields, {
          id: CONFIDENTIAL_CLIENT,
          secret: `${CONFIDENTIAL_SECRET}x`,
        })
      ).status,
    ).toBe(401);
    const ok = await s.form("/oauth/token", fields, {
      id: CONFIDENTIAL_CLIENT,
      secret: CONFIDENTIAL_SECRET,
    });
    expect(ok.status).toBe(200);
    expect(
      (
        await s.form("/oauth/token", {
          grant_type: "password",
          client_id: PUBLIC_CLIENT,
        })
      ).body,
    ).toMatchObject({
      error: "unsupported_grant_type",
    });
    const wrongType = await fetch(`${s.api}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(wrongType.status).toBe(400);
  });

  it("revokes a token family at the revocation endpoint", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const a = await ada.tokens();
    const b = await ada.tokens();
    // Another client's revocation does nothing; an unknown token is fine.
    expect(
      (
        await s.form(
          "/oauth/revoke",
          { token: a.access_token },
          {
            id: CONFIDENTIAL_CLIENT,
            secret: CONFIDENTIAL_SECRET,
          },
        )
      ).status,
    ).toBe(200);
    expect((await s.bearer("/mcp", a.access_token)).status).toBe(200);
    expect(
      (
        await s.form("/oauth/revoke", {
          token: "unknown",
          client_id: PUBLIC_CLIENT,
        })
      ).status,
    ).toBe(200);
    expect(
      (await s.form("/oauth/revoke", { token: a.access_token })).status,
    ).toBe(401);

    expect(
      (
        await s.form("/oauth/revoke", {
          token: a.access_token,
          client_id: PUBLIC_CLIENT,
        })
      ).status,
    ).toBe(200);
    expect((await s.bearer("/mcp", a.access_token)).status).toBe(401);
    expect(
      (
        await s.form("/oauth/token", {
          grant_type: "refresh_token",
          client_id: PUBLIC_CLIENT,
          refresh_token: a.refresh_token,
        })
      ).body,
    ).toMatchObject({ error: "invalid_grant" });
    // Revoking by refresh token ends that family too; the other grant lives.
    await s.form("/oauth/revoke", {
      token: b.refresh_token,
      token_type_hint: "refresh_token",
      client_id: PUBLIC_CLIENT,
    });
    expect((await s.bearer("/mcp", b.access_token)).status).toBe(401);
    const c = await ada.tokens();
    expect((await s.bearer("/mcp", c.access_token)).status).toBe(200);
  });

  it("follows the owner's role exactly as API keys do", async () => {
    const s = await stack();
    const grace = await s.person("grace");
    const admin = await grace.tokens({ ceiling: "admin" });
    const member = await grace.tokens({ ceiling: "member" });
    const viewer = await grace.tokens({ ceiling: "viewer" });
    const role = async (token: string) => {
      const r = await s.bearer("/mcp", token);
      return r.status === 200
        ? ((await r.json()) as { role: string }).role
        : r.status;
    };
    expect(await role(admin.access_token)).toBe("admin");
    expect(await role(member.access_token)).toBe("member");

    // NULL suspends: refused while it lasts, back with the same role.
    await setRole(s, "grace", null);
    for (const t of [admin, member, viewer])
      expect(await role(t.access_token)).toBe(401);
    expect(
      (
        await s.form("/oauth/token", {
          grant_type: "refresh_token",
          client_id: PUBLIC_CLIENT,
          refresh_token: member.refresh_token,
        })
      ).body,
    ).toMatchObject({ error: "invalid_grant" });
    await setRole(s, "grace", "admin");
    expect(await role(admin.access_token)).toBe("admin");
    expect(await role(member.access_token)).toBe("member");

    // A real downgrade revokes the grants above it for good.
    await setRole(s, "grace", "member");
    expect(await role(admin.access_token)).toBe(401);
    expect(await role(member.access_token)).toBe("member");
    await setRole(s, "grace", "admin");
    expect(await role(admin.access_token)).toBe(401);
    expect(
      (await s.mcp.listGrants(await userId(s, "grace")))
        .map((g) => g.ceiling)
        .sort(),
    ).toEqual(["member", "viewer"]);

    // Deactivation revokes everything for good.
    await rows(
      s,
      "UPDATE {schema}.users SET active = false, deactivated_at = now() WHERE sub = 'grace'",
    );
    await rows(
      s,
      "UPDATE {schema}.users SET active = true, deactivated_at = NULL WHERE sub = 'grace'",
    );
    for (const t of [member, viewer])
      expect(await role(t.access_token)).toBe(401);
    expect(await s.mcp.listGrants(await userId(s, "grace"))).toEqual([]);
  });

  it("survives an authentik full sync with every grant and token intact", async () => {
    const TOKEN = "scim-token-".repeat(4);
    const s = await stack({
      env: {
        POSTED_ROLE_SOURCE: "scim",
        POSTED_SCIM_TOKENS: TOKEN,
        POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "true",
      },
    });
    const scim = createScim({ config: s.config, sql: s.sql });
    const call = async (method: string, path: string, body?: unknown) => {
      const response = await scim.request(`${path}`, {
        method,
        headers: {
          authorization: `Bearer ${TOKEN}`,
          "content-type": "application/scim+json",
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const text = await response.text();
      return text ? (JSON.parse(text) as Record<string, unknown>) : {};
    };
    const user = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "grace@example.com",
      externalId: "grace",
      active: true,
    };
    const id = (await call("POST", "/Users", user)).id as string;
    const group = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
      displayName: "posted-admins",
      members: [{ value: id }],
    };
    const groupId = (await call("POST", "/Groups", group)).id as string;
    const grace = await s.person("grace");
    const tokens = [
      await grace.tokens({ ceiling: "admin" }),
      await grace.tokens({ ceiling: "viewer" }),
    ];
    for (let sync = 0; sync < 3; sync++) {
      await call("PUT", `/Users/${id}`, user);
      await call("PUT", `/Groups/${groupId}`, group);
    }
    for (const t of tokens)
      expect((await s.bearer("/mcp", t.access_token)).status).toBe(200);
    expect(await s.mcp.listGrants(id)).toHaveLength(2);
  });

  it("lists and revokes connected apps, and lets an admin manage other people's", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const tokens = await ada.tokens({ ceiling: "viewer" });
    await s.bearer("/mcp", tokens.access_token);
    const listed = await ada.call("/auth/connected-apps");
    expect(await listed.json()).toEqual({
      connectedApps: [
        {
          id: expect.any(String),
          clientId: PUBLIC_CLIENT,
          clientName: "Posted CLI",
          logoUri: null,
          ceiling: "viewer",
          resources: [s.resource],
          restrictions: null,
          createdAt: expect.any(String),
          lastUsedAt: expect.any(String),
        },
      ],
    });
    const [app] = (
      (await (await ada.call("/auth/connected-apps")).json()) as {
        connectedApps: { id: string }[];
      }
    ).connectedApps;

    const grace = await s.person("grace");
    const adaId = await userId(s, "ada");
    const theirs = await grace.call(`/auth/connected-apps?user=${adaId}`);
    expect(
      ((await theirs.json()) as { connectedApps: unknown[] }).connectedApps,
    ).toHaveLength(1);
    const graceTokens = await grace.tokens({ ceiling: "viewer" });
    const [graceApp] = (
      (await (await grace.call("/auth/connected-apps")).json()) as {
        connectedApps: { id: string }[];
      }
    ).connectedApps;
    expect(
      (await ada.call(`/auth/connected-apps?user=${await userId(s, "grace")}`))
        .status,
    ).toBe(403);
    expect(
      (
        await ada.call(`/auth/connected-apps/${graceApp?.id ?? ""}`, {
          method: "DELETE",
        })
      ).status,
    ).toBe(404);
    expect((await s.bearer("/mcp", graceTokens.access_token)).status).toBe(200);

    expect(
      (
        await grace.call(`/auth/connected-apps/${app?.id ?? ""}`, {
          method: "DELETE",
        })
      ).status,
    ).toBe(204);
    expect((await s.bearer("/mcp", tokens.access_token)).status).toBe(401);
    expect(
      (
        await ada.call(`/auth/connected-apps/${graceApp?.id ?? ""}`, {
          method: "DELETE",
          headers: { origin: "https://evil.example" },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await grace.call(`/auth/connected-apps/${graceApp?.id ?? ""}`, {
          method: "DELETE",
        })
      ).status,
    ).toBe(204);
    expect((await fetch(`${s.api}/auth/connected-apps`)).status).toBe(401);
    expect(PUBLIC_REDIRECT).toBeDefined();
  });
});
