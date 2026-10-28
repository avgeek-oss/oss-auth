import { afterEach, describe, expect, it } from "vitest";
import { AuthRequestError } from "../../src/index.js";
import { databaseUrl } from "../postgres/support.js";
import {
  CONFIDENTIAL_CLIENT,
  PUBLIC_CLIENT,
  PUBLIC_REDIRECT,
  pkce,
  rows,
  startMcp,
  type McpStack,
  type Person,
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

const ago = (seconds: number) => Math.floor(Date.now() / 1000) - seconds;

/** Starts an authorization and returns the consent request id. */
async function request(
  s: McpStack,
  person: Person,
  extra: Record<string, string> = {},
): Promise<string> {
  const response = await person.authorize({
    response_type: "code",
    client_id: PUBLIC_CLIENT,
    redirect_uri: PUBLIC_REDIRECT,
    code_challenge: pkce().challenge,
    code_challenge_method: "S256",
    resource: s.resource,
    state: "s-1",
    ...extra,
  });
  return (
    new URL(response.headers.get("location") ?? "").searchParams.get(
      "request",
    ) ?? ""
  );
}

const decide = (
  person: Person,
  id: string,
  body: unknown,
  headers: Record<string, string> = {},
) =>
  person.call(`/oauth/consent/${id}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

describe.skipIf(!databaseUrl)("MCP consent", () => {
  it("shows the client, its redirect host, the resource and the ceilings the person may choose", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const id = await request(s, ada, { scope: "viewer" });
    const response = await ada.call(`/oauth/consent/${id}`);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      client: {
        id: PUBLIC_CLIENT,
        name: "Posted CLI",
        logoUri: null,
        kind: "configured",
        redirectUri: PUBLIC_REDIRECT,
        redirectHost: "127.0.0.1",
        localhost: true,
      },
      resource: { uri: s.resource, name: "Posted MCP" },
      scope: "viewer",
      ceilings: ["viewer", "member"],
      defaultCeiling: "viewer",
      expiresAt: expect.any(String),
    });

    const grace = await s.person("grace");
    const confidential = await grace.authorize({
      response_type: "code",
      client_id: CONFIDENTIAL_CLIENT,
      redirect_uri: "https://ci.example.com/oauth/callback",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256",
      resource: s.v1,
    });
    const other = new URL(
      confidential.headers.get("location") ?? "",
    ).searchParams.get("request");
    expect(
      await (await grace.call(`/oauth/consent/${other ?? ""}`)).json(),
    ).toMatchObject({
      client: {
        name: "Posted CI",
        logoUri: "https://ci.example.com/logo.png",
        redirectHost: "ci.example.com",
        localhost: false,
      },
      resource: { uri: s.v1, name: "Posted API" },
      scope: null,
      ceilings: ["viewer", "member", "admin"],
    });
  });

  it("refuses a ceiling above the person's role", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const id = await request(s, ada);
    await ada.call(`/oauth/consent/${id}`);
    const refused = await decide(ada, id, {
      decision: "approve",
      ceiling: "admin",
    });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({
      error: { code: "forbidden" },
    });
    // The request is still open: a lower ceiling works.
    const ok = await decide(ada, id, {
      decision: "approve",
      ceiling: "member",
    });
    expect(ok.status).toBe(200);
  });

  it("needs a recent sign-in for an admin ceiling", async () => {
    const s = await stack();
    const grace = await s.person("grace", ago(3600));
    const id = await request(s, grace);
    const stale = await decide(grace, id, {
      decision: "approve",
      ceiling: "admin",
    });
    expect(stale.status).toBe(401);
    expect(await stale.json()).toEqual({
      error: {
        code: "step_up_required",
        message: expect.any(String),
        stepUpUrl: `${s.api}/auth/step-up`,
      },
    });
    await grace.stepUp();
    const ok = await decide(grace, id, {
      decision: "approve",
      ceiling: "admin",
    });
    expect(ok.status).toBe(200);
    const redirect = new URL(
      ((await ok.json()) as { redirectUri: string }).redirectUri,
    );
    expect(redirect.searchParams.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(redirect.searchParams.get("iss")).toBe(s.api);
    expect(redirect.searchParams.get("state")).toBe("s-1");
  });

  it("answers access_denied with state and iss when the person declines, once", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const id = await request(s, ada);
    const denied = await decide(ada, id, { decision: "deny" });
    const redirect = new URL(
      ((await denied.json()) as { redirectUri: string }).redirectUri,
    );
    expect(redirect.origin + redirect.pathname).toBe(PUBLIC_REDIRECT);
    expect(Object.fromEntries(redirect.searchParams)).toEqual({
      error: "access_denied",
      error_description: expect.any(String),
      state: "s-1",
      iss: s.api,
    });
    expect(
      (await decide(ada, id, { decision: "approve", ceiling: "viewer" }))
        .status,
    ).toBe(404);
    expect((await ada.call(`/oauth/consent/${id}`)).status).toBe(404);
  });

  it("is session-only, CSRF-checked, bound to one person and expires", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const id = await request(s, ada);
    // No session.
    expect((await fetch(`${s.api}/oauth/consent/${id}`)).status).toBe(401);
    // A forged cross-site POST.
    for (const headers of [
      { origin: "https://evil.example" },
      { "x-requested-with": "" },
    ] as Record<string, string>[]) {
      const forged = await decide(
        ada,
        id,
        { decision: "approve", ceiling: "viewer" },
        headers,
      );
      expect(forged.status).toBe(403);
    }
    // An API key is not a session.
    const key = await s.auth.apiKeys?.create({
      userId:
        (
          await rows<{ id: string }>(
            s,
            `SELECT id FROM {schema}.users WHERE sub = 'ada'`,
          )
        )[0]?.id ?? "",
      name: "k",
      ceiling: "viewer",
    });
    const keyed = await fetch(`${s.api}/oauth/consent/${id}`, {
      headers: { authorization: `Bearer ${key?.key ?? ""}` },
    });
    expect(keyed.status).toBe(403);
    expect(await keyed.json()).toMatchObject({ error: { code: "forbidden" } });

    // Ada opened it first, so it is hers alone.
    expect((await ada.call(`/oauth/consent/${id}`)).status).toBe(200);
    const grace = await s.person("grace");
    expect((await grace.call(`/oauth/consent/${id}`)).status).toBe(404);
    expect((await decide(grace, id, { decision: "deny" })).status).toBe(404);

    const later = await request(s, ada);
    s.advance(601);
    expect((await ada.call(`/oauth/consent/${later}`)).status).toBe(404);
    expect((await ada.call("/oauth/consent/unknown")).status).toBe(404);
    expect((await decide(ada, id, { decision: "maybe" })).status).toBe(400);
  });

  it("stores restrictions only through the app's hook, and puts them on the actor", async () => {
    const s = await stack();
    const ada = await s.person("ada");
    const id = await request(s, ada);
    const refused = await decide(ada, id, {
      decision: "approve",
      ceiling: "viewer",
      restrictions: { boards: ["b1"] },
    });
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({
      error: { code: "invalid_request" },
    });

    const seen: unknown[] = [];
    const t = await stack({
      hooks: {
        validateRestrictions: (actor, restrictions, context) => {
          seen.push({ user: actor.user.email, restrictions, context });
          const boards = (restrictions as { boards?: unknown }).boards;
          if (!Array.isArray(boards) || boards.some((b) => b !== "b1"))
            throw new AuthRequestError("invalid_request", "Unknown board.");
          return { boards };
        },
      },
    });
    const grace = await t.person("grace");
    expect(
      (
        await decide(grace, await request(t, grace), {
          decision: "approve",
          ceiling: "viewer",
          restrictions: { boards: ["b2"] },
        })
      ).status,
    ).toBe(400);
    const tokens = await grace.tokens({
      ceiling: "viewer",
      restrictions: { boards: ["b1"] },
    });
    expect(seen).toContainEqual({
      user: "grace@example.com",
      restrictions: { boards: ["b1"] },
      context: { clientId: PUBLIC_CLIENT, resource: t.resource },
    });
    const me = await t.bearer("/mcp", tokens.access_token);
    expect(await me.json()).toMatchObject({
      role: "viewer",
      credential: {
        kind: "oauth",
        ceiling: "viewer",
        workspace: null,
        restrictions: { boards: ["b1"] },
      },
    });
  });
});
