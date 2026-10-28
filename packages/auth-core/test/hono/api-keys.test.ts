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

const ago = (seconds: number) => Math.floor(Date.now() / 1000) - seconds;

interface KeyView {
  id: string;
  name: string;
  ceiling: string;
  workspace: string | null;
  replacedBy: string | null;
  graceUntil: string | null;
}

/**
 * Signs in as `sub` in a browser of their own and returns helpers for it.
 * `call` sends the web origin's headers, like the app's pages.
 */
async function signedIn(s: Stack, sub: string, authTime?: number) {
  const browser = createBrowser();
  const toWeb = (url: URL) => url.origin === WEB;
  const navigate = async (path: string) => {
    s.mock.setLogin({ sub, amr: ["mfa"] });
    return new URL(
      (await browser.follow(`${s.api}${path}`, { stopAt: toWeb })).url,
    );
  };
  const signIn = async () => {
    s.mock.setLogin({
      sub,
      ...(authTime === undefined ? {} : { authTime }),
    });
    return new URL(
      (await browser.follow(`${s.api}/auth/sign-in`, { stopAt: toWeb })).url,
    );
  };
  expect((await signIn()).origin).toBe(WEB);
  const call = (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    if (!headers.has("origin")) headers.set("origin", WEB);
    if (!headers.has("x-requested-with"))
      headers.set("x-requested-with", "fetch");
    return browser.fetch(`${s.api}${path}`, { ...init, headers });
  };
  const send = async (method: string, path: string, body?: unknown) => {
    const response = await call(`/auth${path}`, {
      method,
      ...(body === undefined
        ? {}
        : {
            body: JSON.stringify(body),
            headers: { "content-type": "application/json" },
          }),
    });
    const text = await response.text();
    return {
      status: response.status,
      body: (text === "" ? {} : JSON.parse(text)) as Record<string, unknown>,
    };
  };
  const create = async (ceiling: string, extra: object = {}) => {
    const r = await send("POST", "/api-keys", {
      name: "CI",
      ceiling,
      ...extra,
    });
    expect(r.status).toBe(201);
    return r.body as { key: string; apiKey: KeyView };
  };
  return {
    send,
    create,
    call,
    signIn,
    stepUp: () => navigate("/auth/step-up"),
  };
}

/** A request authenticated by an API key only: no cookies, no CSRF headers. */
function withKey(
  s: Stack,
  path: string,
  key: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${key}`);
  return fetch(`${s.api}${path}`, { ...init, headers });
}

async function userId(s: Stack, sub: string): Promise<string> {
  const [row] = await rows<{ id: string }>(
    s,
    `SELECT id FROM {schema}.users WHERE sub = $1`,
    [sub],
  );
  return row?.id ?? "";
}

describe.skipIf(!databaseUrl)("API keys over HTTP", () => {
  it("creates a key from a session, shows it once and authenticates with it", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const { key, apiKey } = await ada.create("viewer");
    expect(apiKey).toMatchObject({
      name: "CI",
      ceiling: "viewer",
      workspace: null,
    });
    expect(apiKey).not.toHaveProperty("secretHash");
    const listed = await ada.send("GET", "/api-keys");
    expect(listed.body).toEqual({
      apiKeys: [expect.objectContaining({ id: apiKey.id })],
    });
    expect(JSON.stringify(listed.body)).not.toContain(key);

    const me = await withKey(s, "/api/me", key);
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({ role: "viewer" });
    // A member key of a member is a member; requireRole uses the effective role.
    const member = await ada.create("member");
    expect(await (await withKey(s, "/api/me", member.key)).json()).toEqual({
      role: "member",
    });
    const members = await withKey(s, "/api/members", member.key, {
      method: "POST",
    });
    expect(members.status).toBe(403);
    expect(await members.json()).toMatchObject({
      error: { code: "forbidden" },
    });
  });

  it("refuses a ceiling above the role, and an admin key without a recent sign-in", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    expect(
      await ada.send("POST", "/api-keys", { name: "x", ceiling: "admin" }),
    ).toMatchObject({
      status: 403,
      body: { error: { code: "forbidden" } },
    });

    const t = await stack();
    const grace = await signedIn(t, "grace", ago(3600));
    expect(
      await grace.send("POST", "/api-keys", { name: "x", ceiling: "admin" }),
    ).toEqual({
      status: 401,
      body: {
        error: {
          code: "step_up_required",
          message: expect.any(String),
          stepUpUrl: `${t.api}/auth/step-up`,
        },
      },
    });
    // Lower ceilings need no step-up.
    await grace.create("member");
    expect((await grace.stepUp()).origin).toBe(WEB);
    const admin = await grace.create("admin");
    const ok = await withKey(t, "/api/members", admin.key, { method: "POST" });
    expect(ok.status).toBe(200);
  });

  it("never uses a key for step-up or to manage keys", async () => {
    const s = await stack();
    const grace = await signedIn(s, "grace");
    const { key, apiKey } = await grace.create("admin");
    const danger = await withKey(s, "/api/danger", key, { method: "POST" });
    expect(danger.status).toBe(403);
    expect(await danger.json()).toMatchObject({
      error: { code: "step_up_unavailable" },
    });
    for (const [method, path] of [
      ["GET", "/auth/api-keys"],
      ["POST", "/auth/api-keys"],
      ["POST", `/auth/api-keys/${apiKey.id}/rotate`],
      ["DELETE", `/auth/api-keys/${apiKey.id}`],
    ] as const) {
      const response = await withKey(s, path, key, {
        method,
        ...(method === "POST"
          ? { body: JSON.stringify({ name: "x", ceiling: "viewer" }) }
          : {}),
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({
        error: { code: "forbidden" },
      });
    }
    expect(await s.auth.apiKeys?.list(await userId(s, "grace"))).toHaveLength(
      1,
    );
  });

  it("reads a key only from the Authorization header", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const { key } = await ada.create("viewer");
    for (const query of ["api_key", "key", "access_token", "token"])
      expect(
        (await fetch(`${s.api}/api/me?${query}=${encodeURIComponent(key)}`))
          .status,
      ).toBe(401);
    expect(
      (
        await fetch(`${s.api}/api/me`, {
          headers: { cookie: `${s.auth.sessionCookie}=${key}` },
        })
      ).status,
    ).toBe(401);
    for (const header of [
      `Basic ${key}`,
      `Bearer`,
      `Bearer ${key} extra`,
      `Token ${key}`,
    ])
      expect(
        (await fetch(`${s.api}/api/me`, { headers: { authorization: header } }))
          .status,
      ).toBe(401);
    expect(
      (
        await fetch(`${s.api}/api/me`, {
          headers: { authorization: `bearer ${key}` },
        })
      ).status,
    ).toBe(200);
  });

  it("ignores the session cookie when a bearer key is sent, even a bad one", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    expect((await ada.call("/api/me")).status).toBe(200);
    expect(
      (
        await ada.call("/api/me", {
          headers: { authorization: "Bearer nonsense" },
        })
      ).status,
    ).toBe(401);
  });

  it("skips CSRF checks for bearer keys and keeps them for sessions", async () => {
    const s = await stack();
    const grace = await signedIn(s, "grace");
    const { key } = await grace.create("admin");
    const keyed = await withKey(s, "/api/members", key, {
      method: "POST",
      headers: { origin: "https://evil.example" },
    });
    expect(keyed.status).toBe(200);
    for (const headers of [
      { origin: "https://evil.example" },
      { "x-requested-with": "" },
    ] as Record<string, string>[]) {
      const response = await grace.call("/api/members", {
        method: "POST",
        headers,
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({
        error: {
          code: expect.stringMatching(/^(origin_invalid|csrf_header_missing)$/),
        },
      });
    }
    // The key routes are session routes, so CSRF applies to them too.
    const forged = await grace.call("/auth/api-keys", {
      method: "POST",
      headers: {
        origin: "https://evil.example",
        "content-type": "application/json",
      },
      body: JSON.stringify({ name: "x", ceiling: "viewer" }),
    });
    expect(forged.status).toBe(403);
  });

  it("rotates and revokes a user's own keys", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const { key, apiKey } = await ada.create("member");
    const rotated = await ada.send("POST", `/api-keys/${apiKey.id}/rotate`, {
      graceSeconds: 600,
    });
    expect(rotated.status).toBe(201);
    const next = rotated.body as { key: string; apiKey: KeyView };
    expect(next.apiKey).toMatchObject({ ceiling: "member", name: "CI" });
    expect((await withKey(s, "/api/me", key)).status).toBe(200);
    expect((await withKey(s, "/api/me", next.key)).status).toBe(200);
    expect(
      (await ada.send("POST", `/api-keys/${apiKey.id}/rotate`, {})).body,
    ).toMatchObject({ error: { code: "conflict" } });
    const listed = (await ada.send("GET", "/api-keys")).body
      .apiKeys as KeyView[];
    expect(listed.find((k) => k.id === apiKey.id)).toMatchObject({
      replacedBy: next.apiKey.id,
      graceUntil: expect.any(String),
    });
    s.advance(601);
    expect((await withKey(s, "/api/me", key)).status).toBe(401);

    expect(
      (await ada.send("DELETE", `/api-keys/${next.apiKey.id}`)).status,
    ).toBe(204);
    expect((await withKey(s, "/api/me", next.key)).status).toBe(401);
    expect(
      (await ada.send("DELETE", `/api-keys/${next.apiKey.id}`)).status,
    ).toBe(404);
    expect(
      (await ada.send("POST", "/api-keys/nonsense/rotate", {})).status,
    ).toBe(404);
    for (const body of [
      { ceiling: "owner", name: "x" },
      { ceiling: "viewer", name: "" },
      { ceiling: "viewer", name: "x", expiresInSeconds: "soon" },
    ])
      expect((await ada.send("POST", "/api-keys", body)).status).toBe(400);
    const raw = await ada.call("/auth/api-keys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    expect(raw.status).toBe(400);
  });

  it("lets an admin list and revoke someone else's keys, and nobody else", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const adaKey = await ada.create("viewer");
    const adaId = await userId(s, "ada");

    // The same browser signs in as Grace, which ends Ada's session.
    const grace = await signedIn(s, "grace");
    const graceKey = await grace.create("viewer");
    const listed = await grace.send("GET", `/api-keys?user=${adaId}`);
    expect(listed.status).toBe(200);
    expect((listed.body.apiKeys as KeyView[]).map((k) => k.id)).toEqual([
      adaKey.apiKey.id,
    ]);
    expect((await grace.send("GET", "/api-keys?user=nonsense")).status).toBe(
      400,
    );
    expect(
      (await grace.send("DELETE", `/api-keys/${adaKey.apiKey.id}`)).status,
    ).toBe(204);
    expect((await withKey(s, "/api/me", adaKey.key)).status).toBe(401);

    const ada2 = await signedIn(s, "ada");
    const graceId = await userId(s, "grace");
    expect((await ada2.send("GET", `/api-keys?user=${graceId}`)).status).toBe(
      403,
    );
    expect(
      (await ada2.send("DELETE", `/api-keys/${graceKey.apiKey.id}`)).status,
    ).toBe(404);
    expect(
      (await ada2.send("POST", `/api-keys/${graceKey.apiKey.id}/rotate`, {}))
        .status,
    ).toBe(404);
    expect((await withKey(s, "/api/me", graceKey.key)).status).toBe(200);
  });

  it("issues workspace keys only through the app's hook", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    expect(
      await ada.send("POST", "/api-keys", {
        name: "x",
        ceiling: "viewer",
        workspace: "w1",
      }),
    ).toMatchObject({
      status: 400,
      body: { error: { code: "invalid_request" } },
    });

    const seen: string[] = [];
    const t = await stack({
      auth: {
        hooks: {
          extendActor: () => ({ plan: "team" }),
          authorizeWorkspace: (actor, workspace) => {
            seen.push(`${actor.user.email}:${workspace}`);
            return workspace === "w1";
          },
        },
      },
    });
    const ada2 = await signedIn(t, "ada");
    const { key, apiKey } = await ada2.create("viewer", { workspace: "w1" });
    expect(apiKey.workspace).toBe("w1");
    expect(
      await ada2.send("POST", "/api-keys", {
        name: "x",
        ceiling: "viewer",
        workspace: "w2",
      }),
    ).toMatchObject({ status: 403, body: { error: { code: "forbidden" } } });
    expect(seen).toEqual(["ada@example.com:w1", "ada@example.com:w2"]);
    expect((await t.auth.apiKeys?.verify(key))?.actor.credential).toMatchObject(
      {
        kind: "api_key",
        workspace: "w1",
      },
    );
  });

  it("stops a key as soon as its owner is downgraded or loses access", async () => {
    const s = await stack();
    const grace = await signedIn(s, "grace");
    const admin = await grace.create("admin");
    const viewer = await grace.create("viewer");
    // Grace's groups change at the provider; the next sign-in applies it.
    s.mock.setUser({ sub: "grace", groups: ["posted-members"] });
    await grace.signIn();
    expect((await withKey(s, "/api/me", admin.key)).status).toBe(401);
    expect(await (await withKey(s, "/api/me", viewer.key)).json()).toEqual({
      role: "viewer",
    });
    s.mock.setUser({ sub: "grace", groups: ["unrelated"] });
    await grace.signIn();
    expect((await withKey(s, "/api/me", viewer.key)).status).toBe(401);
  });
});
