import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import type { FetchLike } from "../../src/oidc/index.js";
import { databaseUrl } from "../postgres/support.js";
import {
  rows,
  startStack,
  WEB,
  type Stack,
  type StackOptions,
} from "./support.js";

const stacks: Stack[] = [];
async function stack(options?: StackOptions): Promise<Stack> {
  const started = await startStack(options);
  stacks.push(started);
  return started;
}
afterEach(async () => {
  for (const s of stacks.splice(0)) await s.close();
});

const toWeb = (url: URL) => url.origin === WEB;
const toCallback = (url: URL) => url.pathname === "/auth/callback";

/** The `auth_error` and reason a failed callback redirected with. */
function failure(url: URL) {
  expect(url.origin).toBe(WEB);
  return {
    code: url.searchParams.get("auth_error"),
    reason: url.searchParams.get("auth_error_reason"),
  };
}

async function role(s: Stack): Promise<string | undefined> {
  const response = await s.call("/auth/session");
  if (response.status !== 200) return undefined;
  return ((await response.json()) as { role: string }).role;
}

/** The stack's sessions, oldest first, and whether each is revoked. */
async function sessionStates(s: Stack): Promise<boolean[]> {
  return (
    await rows<{ revoked: boolean }>(
      s,
      `SELECT revoked_at IS NOT NULL AS "revoked" FROM {schema}.sessions ORDER BY created_at`,
    )
  ).map((r) => r.revoked);
}

describe.skipIf(!databaseUrl)("sign-in", () => {
  it("signs in, reads the session and signs out", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada" });
    const landed = await s.signIn("/boards?tab=mine#top");
    expect(landed.href).toBe(`${WEB}/boards?tab=mine#top`);

    const session = await s.call("/auth/session");
    expect(session.status).toBe(200);
    expect(session.headers.get("cache-control")).toBe("no-store");
    expect(await session.json()).toMatchObject({
      user: { email: "ada@example.com", displayName: "Ada", role: "member" },
      role: "member",
      ext: { plan: "team" },
      session: { amr: ["mfa"] },
    });
    expect((await s.call("/api/me")).status).toBe(200);
    expect(await sessionStates(s)).toEqual([false]);

    const out = await s.call("/auth/sign-out", { method: "POST" });
    expect(out.status).toBe(200);
    const body = (await out.json()) as { endSessionUrl: string };
    const end = new URL(body.endSessionUrl);
    expect(end.origin).toBe(new URL(s.mock.issuer).origin);
    expect(end.searchParams.get("post_logout_redirect_uri")).toBe(`${WEB}/`);
    expect(end.searchParams.get("client_id")).toBe(s.mock.clientId);
    expect((await s.call("/auth/session")).status).toBe(401);
    expect(await s.call("/api/me").then((r) => r.json())).toEqual({
      error: { code: "unauthenticated", message: "Sign in to continue." },
    });
    expect(await sessionStates(s)).toEqual([true]);
  });

  it("stores only the token's hash, with the provider's sid and amr", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada", amr: ["pwd", "mfa"] });
    await s.signIn();
    const token = s.browser.cookie(s.api, s.auth.sessionCookie) ?? "";
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const [row] = await rows<{
      idHash: string;
      sid: string | null;
      amr: string[];
    }>(
      s,
      `SELECT id_hash AS "idHash", provider_sid AS "sid", amr FROM {schema}.sessions`,
    );
    expect(row?.idHash).toBe(s.auth.sessions.hash(token));
    expect(row?.idHash).not.toContain(token);
    expect(row?.sid).toEqual(expect.any(String));
    expect(row?.amr).toEqual(["pwd", "mfa"]);
  });

  it("refuses an unsafe returnTo before leaving the app", async () => {
    const s = await stack();
    for (const returnTo of [
      "https://evil.example",
      "//evil.example",
      "/\\evil.example",
    ]) {
      const response = await s.browser.fetch(
        `${s.api}/auth/sign-in?returnTo=${encodeURIComponent(returnTo)}`,
      );
      expect(response.status).toBe(400);
      expect(
        ((await response.json()) as { error: { code: string } }).error.code,
      ).toBe("return_to_invalid");
    }
  });

  it("sets the transaction cookie for ten minutes and clears it on callback", async () => {
    const s = await stack();
    const start = await s.browser.fetch(`${s.api}/auth/sign-in`);
    expect(start.status).toBe(302);
    const cookie = start.headers
      .getSetCookie()
      .find((c) => c.startsWith("posted-oidc="));
    expect(cookie).toMatch(/Max-Age=600/);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Lax/);
    expect(cookie).toMatch(/Path=\//);
    const url = new URL(start.headers.get("location") ?? "");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")).toMatch(/.{20,}/);
    expect(url.searchParams.get("nonce")).toMatch(/.{20,}/);
    expect(url.searchParams.get("prompt")).toBeNull();
    expect(url.searchParams.get("scope")).toBe(
      "openid email profile groups roles",
    );
    await s.browser.follow(url.href, { stopAt: toWeb });
    expect(s.browser.cookie(s.api, "posted-oidc")).toBeUndefined();
  });
});

describe.skipIf(!databaseUrl)("roles at sign-in", () => {
  it("refuses a new user whose role claim is missing", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "claimless" });
    expect(failure(await s.signIn())).toEqual({
      code: "sign_in_denied",
      reason: "no_role",
    });
    expect(await rows(s, "SELECT 1 FROM {schema}.users")).toEqual([]);
    expect(await sessionStates(s)).toEqual([]);
  });

  it("refuses a user whose groups map to no role", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "nobody" });
    expect(failure(await s.signIn())).toEqual({
      code: "sign_in_denied",
      reason: "no_role",
    });
  });

  it("gives the highest role when several groups match", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "grace" });
    await s.signIn();
    expect(await role(s)).toBe("admin");
  });

  it("reads authentik's roles claim", async () => {
    const s = await stack({ users: [{ sub: "eve", roles: ["member"] }] });
    s.mock.setLogin({ sub: "eve" });
    await s.signIn();
    expect(await role(s)).toBe("member");
  });

  it("keeps a returning user's role when the claim goes missing, and follows it when it changes", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada" });
    await s.signIn();
    expect(await role(s)).toBe("member");

    s.mock.setUser({ sub: "ada", email: "ada@example.org", name: "Ada L" });
    await s.signIn();
    expect(await role(s)).toBe("member");
    expect(
      await rows(
        s,
        `SELECT email, display_name AS "displayName" FROM {schema}.users WHERE sub = 'ada'`,
      ),
    ).toEqual([{ email: "ada@example.org", displayName: "Ada L" }]);

    s.mock.setUser({
      sub: "ada",
      email: "ada@example.org",
      groups: ["posted-admins"],
    });
    await s.signIn();
    expect(await role(s)).toBe("admin");

    // Groups that map to nothing take the role away and end the session.
    s.mock.setUser({ sub: "ada", groups: ["unrelated"] });
    expect(failure(await s.signIn()).reason).toBe("no_role");
    expect(
      await rows(
        s,
        `SELECT role, role_source AS "source" FROM {schema}.users WHERE sub = 'ada'`,
      ),
    ).toEqual([{ role: null, source: "oidc" }]);
    expect(await role(s)).toBeUndefined();

    // A missing claim cannot give it back.
    s.mock.setUser({ sub: "ada" });
    expect(failure(await s.signIn()).reason).toBe("no_role");
    s.mock.setUser({ sub: "ada", groups: ["posted-viewers"] });
    await s.signIn();
    expect(await role(s)).toBe("viewer");
  });

  it("refuses a deactivated or deleted user and ends their sessions", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada" });
    await s.signIn();
    await rows(
      s,
      `UPDATE {schema}.users SET active = false, deactivated_at = now() WHERE sub = 'ada'`,
    );
    expect((await s.call("/auth/session")).status).toBe(401);
    expect(failure(await s.signIn())).toEqual({
      code: "sign_in_denied",
      reason: "user_inactive",
    });
    await rows(
      s,
      `UPDATE {schema}.users SET deleted_at = now() WHERE sub = 'ada'`,
    );
    expect(failure(await s.signIn()).reason).toBe("user_deleted");
  });
});

describe.skipIf(!databaseUrl)("callback attacks", () => {
  it("rejects a changed state", async () => {
    const s = await stack();
    const landed = await s.browser.follow(`${s.api}/auth/sign-in`, {
      stopAt: toWeb,
      rewrite: (url) => {
        if (toCallback(url)) url.searchParams.set("state", "attacker-state");
        return url;
      },
    });
    expect(failure(new URL(landed.url))).toEqual({
      code: "oidc_callback_invalid",
      reason: "state",
    });
  });

  it("rejects an ID token whose nonce does not match", async () => {
    const s = await stack();
    const landed = await s.browser.follow(`${s.api}/auth/sign-in`, {
      stopAt: toWeb,
      rewrite: (url) => {
        if (url.pathname === "/auth" && url.searchParams.has("nonce"))
          url.searchParams.set("nonce", "attacker-nonce");
        return url;
      },
    });
    expect(failure(new URL(landed.url))).toEqual({
      code: "oidc_callback_invalid",
      reason: "nonce",
    });
  });

  it("rejects a changed or missing RFC 9207 iss when the provider advertises it", async () => {
    const s = await stack();
    for (const change of [
      (url: URL) => url.searchParams.set("iss", "https://evil.example"),
      (url: URL) => url.searchParams.delete("iss"),
    ]) {
      const landed = await s.browser.follow(`${s.api}/auth/sign-in`, {
        stopAt: toWeb,
        rewrite: (url) => {
          if (toCallback(url)) change(url);
          return url;
        },
      });
      expect(failure(new URL(landed.url))).toEqual({
        code: "oidc_callback_invalid",
        reason: "iss",
      });
    }
  });

  it("rejects ID tokens with the wrong iss or aud, signed with a trusted key", async () => {
    // A provider that publishes an extra key and re-signs the ID token.
    const { privateKey, publicKey } = await generateKeyPair("RS256", {
      extractable: true,
    });
    const jwk = {
      ...(await exportJWK(publicKey)),
      kid: "extra",
      alg: "RS256",
      use: "sig",
    };
    let change: (claims: Record<string, unknown>) => void = () => {};
    const tamper: FetchLike = async (url, init) => {
      const response = await fetch(url, init as RequestInit);
      if (new URL(url).pathname === "/jwks") {
        const body = (await response.json()) as { keys: unknown[] };
        return Response.json({ keys: [...body.keys, jwk] });
      }
      if (new URL(url).pathname === "/token" && response.ok) {
        const body = (await response.json()) as { id_token: string };
        const claims = decodeJwt(body.id_token) as Record<string, unknown>;
        change(claims);
        body.id_token = await new SignJWT(claims)
          .setProtectedHeader({ alg: "RS256", kid: "extra" })
          .sign(privateKey);
        return Response.json(body);
      }
      return response;
    };
    const s = await stack({ auth: { oidc: { fetch: tamper } } });

    // The harness alone does not break sign-in.
    await s.signIn();
    expect(await role(s)).toBe("member");

    change = (claims) => {
      claims.iss = "https://evil.example";
    };
    expect(failure(await s.signIn())).toEqual({
      code: "oidc_callback_invalid",
      reason: "id_token_iss",
    });
    change = (claims) => {
      claims.aud = "another-app";
    };
    expect(failure(await s.signIn())).toEqual({
      code: "oidc_callback_invalid",
      reason: "id_token_aud",
    });
    change = (claims) => {
      claims.exp = Math.floor(Date.now() / 1000) - 120;
    };
    expect(failure(await s.signIn()).code).toBe("oidc_callback_invalid");
  });

  it("rejects a missing, tampered or expired transaction cookie", async () => {
    const s = await stack();
    const capture = async () =>
      new URL(
        (
          await s.browser.follow(`${s.api}/auth/sign-in`, {
            stopAt: toCallback,
          })
        ).url,
      );

    let callback = await capture();
    s.browser.setCookie(s.api, "posted-oidc", "garbage");
    expect(
      failure(
        new URL((await s.browser.follow(callback.href, { stopAt: toWeb })).url),
      ).code,
    ).toBe("oidc_transaction_invalid");

    callback = await capture();
    const sealed = s.browser.cookie(s.api, "posted-oidc") ?? "";
    const flipped = `${sealed.slice(0, 30)}${sealed[30] === "A" ? "B" : "A"}${sealed.slice(31)}`;
    s.browser.setCookie(s.api, "posted-oidc", flipped);
    expect(
      failure(
        new URL((await s.browser.follow(callback.href, { stopAt: toWeb })).url),
      ).code,
    ).toBe("oidc_transaction_invalid");

    callback = await capture();
    s.advance(601);
    expect(
      failure(
        new URL((await s.browser.follow(callback.href, { stopAt: toWeb })).url),
      ).code,
    ).toBe("oidc_transaction_invalid");
  });

  it("refuses to redeem a callback twice", async () => {
    const s = await stack();
    const callback = (
      await s.browser.follow(`${s.api}/auth/sign-in`, { stopAt: toCallback })
    ).url;
    const sealed = s.browser.cookie(s.api, "posted-oidc") ?? "";
    expect((await s.browser.follow(callback, { stopAt: toWeb })).url).toBe(
      `${WEB}/`,
    );
    // The cookie is gone after the first use.
    expect(
      failure(
        new URL((await s.browser.follow(callback, { stopAt: toWeb })).url),
      ).code,
    ).toBe("oidc_transaction_invalid");
    // Even with the cookie replayed, the provider refuses the used code.
    s.browser.setCookie(s.api, "posted-oidc", sealed);
    expect(
      failure(
        new URL((await s.browser.follow(callback, { stopAt: toWeb })).url),
      ),
    ).toEqual({
      code: "oidc_callback_invalid",
      reason: "code",
    });
  });

  it("issues a new session id at sign-in, so a planted one never works", async () => {
    const s = await stack();
    const planted = "A".repeat(42) + "w";
    s.browser.setCookie(s.api, s.auth.sessionCookie, planted);
    await s.signIn();
    const first = s.browser.cookie(s.api, s.auth.sessionCookie);
    expect(first).not.toBe(planted);
    expect(await s.auth.sessions.lookup(planted)).toBeNull();

    // Signing in again replaces the browser's previous session.
    await s.signIn();
    const second = s.browser.cookie(s.api, s.auth.sessionCookie);
    expect(second).not.toBe(first);
    expect(await s.auth.sessions.lookup(first)).toBeNull();
    expect(await s.auth.sessions.lookup(second)).not.toBeNull();
    expect(await sessionStates(s)).toEqual([true, false]);
  });
});

describe.skipIf(!databaseUrl)("request checks", () => {
  it("requires the web origin and the CSRF header on state-changing requests", async () => {
    const s = await stack({
      users: [{ sub: "grace", groups: ["posted-admins"] }],
    });
    s.mock.setLogin({ sub: "grace" });
    await s.signIn();
    const post = (headers: Record<string, string>) =>
      s.browser.fetch(`${s.api}/api/members`, { method: "POST", headers });
    const code = async (response: Response) => [
      response.status,
      ((await response.json()) as { error: { code: string } }).error.code,
    ];

    expect(await code(await post({ "x-requested-with": "fetch" }))).toEqual([
      403,
      "origin_invalid",
    ]);
    expect(
      await code(
        await post({
          origin: "https://evil.example",
          "x-requested-with": "fetch",
        }),
      ),
    ).toEqual([403, "origin_invalid"]);
    expect(
      await code(await post({ origin: "null", "x-requested-with": "fetch" })),
    ).toEqual([403, "origin_invalid"]);
    expect(await code(await post({ origin: WEB }))).toEqual([
      403,
      "csrf_header_missing",
    ]);
    expect(
      (await post({ origin: WEB, "x-requested-with": "fetch" })).status,
    ).toBe(200);
    // Reads are not checked.
    expect((await s.browser.fetch(`${s.api}/api/me`)).status).toBe(200);
    // Sign-out is protected the same way.
    const out = await s.browser.fetch(`${s.api}/auth/sign-out`, {
      method: "POST",
    });
    expect(out.status).toBe(403);
    expect((await s.call("/auth/session")).status).toBe(200);
  });

  it("enforces the minimum role", async () => {
    const s = await stack();
    expect((await s.call("/api/members", { method: "POST" })).status).toBe(401);
    s.mock.setLogin({ sub: "ada" });
    await s.signIn();
    const response = await s.call("/api/members", { method: "POST" });
    expect(response.status).toBe(403);
    expect(
      ((await response.json()) as { error: { code: string } }).error.code,
    ).toBe("forbidden");
  });
});

describe.skipIf(!databaseUrl)("step-up", () => {
  const ago = (seconds: number) => Math.floor(Date.now() / 1000) - seconds;

  it("asks for step-up, re-authenticates with prompt=login and keeps the session", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada", authTime: ago(3600) });
    await s.signIn();
    const token = s.browser.cookie(s.api, s.auth.sessionCookie);

    const denied = await s.call("/api/danger", { method: "POST" });
    expect(denied.status).toBe(401);
    expect(await denied.json()).toEqual({
      error: {
        code: "step_up_required",
        message: expect.any(String),
        stepUpUrl: `${s.api}/auth/step-up`,
      },
    });

    s.mock.setLogin({ sub: "ada", amr: ["mfa"] });
    const hops: string[] = [];
    const landed = await s.browser.follow(
      `${s.api}/auth/step-up?returnTo=/danger`,
      {
        stopAt: toWeb,
        rewrite: (url) => {
          hops.push(url.href);
          return url;
        },
      },
    );
    expect(landed.url).toBe(`${WEB}/danger`);
    const authorize = new URL(
      hops.find((h) => new URL(h).pathname === "/auth") ?? "",
    );
    expect(authorize.searchParams.get("prompt")).toBe("login");
    expect(authorize.searchParams.get("max_age")).toBe("300");

    expect(s.browser.cookie(s.api, s.auth.sessionCookie)).toBe(token);
    expect((await s.call("/api/danger", { method: "POST" })).status).toBe(200);
    const [session] = await rows<{ fresh: boolean }>(
      s,
      `SELECT authenticated_at > now() - interval '1 minute' AS "fresh" FROM {schema}.sessions`,
    );
    expect(session?.fresh).toBe(true);
    expect(await sessionStates(s)).toEqual([false]);
  });

  it("rejects a provider that did not re-authenticate", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada", authTime: ago(3600) });
    await s.signIn();
    expect(failure(await s.stepUp())).toEqual({
      code: "step_up_failed",
      reason: "stale",
    });
    expect((await s.call("/api/danger", { method: "POST" })).status).toBe(401);
  });

  it("requires mfa in amr unless configured otherwise", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada", authTime: ago(3600), amr: ["pwd"] });
    await s.signIn();
    s.mock.setLogin({ sub: "ada", amr: ["pwd"] });
    expect(failure(await s.stepUp())).toEqual({
      code: "step_up_failed",
      reason: "mfa_missing",
    });

    const t = await stack({ auth: { stepUp: { requireMfa: false } } });
    t.mock.setLogin({ sub: "ada", authTime: ago(3600), amr: ["pwd"] });
    await t.signIn();
    t.mock.setLogin({ sub: "ada", amr: ["pwd"] });
    expect((await t.stepUp("/x")).href).toBe(`${WEB}/x`);
    expect((await t.call("/api/danger", { method: "POST" })).status).toBe(200);
  });

  it("refuses a step-up completed by another person or without a session", async () => {
    // Without back-channel logout, so the provider's account switch does not
    // also end the app session.
    const s = await stack({ backchannel: false });
    expect((await s.browser.fetch(`${s.api}/auth/step-up`)).status).toBe(401);
    s.mock.setLogin({ sub: "ada", authTime: ago(3600) });
    await s.signIn();
    s.mock.setLogin({ sub: "grace" });
    expect(failure(await s.stepUp())).toEqual({
      code: "step_up_failed",
      reason: "user",
    });
  });
});

describe.skipIf(!databaseUrl)("back-channel logout", () => {
  async function signedIn(s: Stack, sub = "ada") {
    s.mock.setLogin({ sub });
    await s.signIn();
    const [row] = await rows<{ sid: string }>(
      s,
      `SELECT provider_sid AS "sid" FROM {schema}.sessions s
       JOIN {schema}.users u ON u.id = s.user_id
       WHERE u.sub = $1 AND s.revoked_at IS NULL ORDER BY s.created_at DESC`,
      [sub],
    );
    return row?.sid ?? "";
  }
  const post = (s: Stack, token: string) => s.mock.sendBackchannelLogout(token);
  const reason = async (response: Response) => {
    expect(response.status).toBe(400);
    return ((await response.json()) as { error: { code: string } }).error.code;
  };

  it("ends the session when the person signs out at the provider", async () => {
    const s = await stack();
    await signedIn(s);
    const end = new URL(`${s.mock.issuer}/session/end`);
    end.searchParams.set("client_id", s.mock.clientId);
    end.searchParams.set("post_logout_redirect_uri", `${WEB}/`);
    // The person confirms on the provider's page; the provider then posts a
    // logout token it signed itself to the app.
    const confirm = await s.browser.follow(end.href, { stopAt: toWeb });
    const landed = await s.browser.submit(
      confirm,
      { logout: "yes" },
      { stopAt: toWeb },
    );
    expect(landed.url).toBe(`${WEB}/`);
    expect((await s.call("/auth/session")).status).toBe(401);
  });

  it("ends the session named by sid", async () => {
    const s = await stack();
    const sid = await signedIn(s);
    const response = await post(s, await s.mock.logoutToken({ sid }));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect((await s.call("/auth/session")).status).toBe(401);
    expect(await sessionStates(s)).toEqual([true]);
  });

  it("ends every session of the subject named by sub", async () => {
    const s = await stack();
    await signedIn(s);
    const other = s.browser.cookie(s.api, s.auth.sessionCookie);
    s.browser.clear(s.api);
    await signedIn(s);
    expect(
      (await post(s, await s.mock.logoutToken({ sub: "ada" }))).status,
    ).toBe(200);
    expect(await s.auth.sessions.lookup(other)).toBeNull();
    expect((await s.call("/auth/session")).status).toBe(401);
  });

  it("matches sub and sid together when both are given", async () => {
    const s = await stack();
    const sid = await signedIn(s);
    expect(
      (await post(s, await s.mock.logoutToken({ sub: "grace", sid }))).status,
    ).toBe(200);
    expect((await s.call("/auth/session")).status).toBe(200);
    expect(
      (await post(s, await s.mock.logoutToken({ sub: "ada", sid }))).status,
    ).toBe(200);
    expect((await s.call("/auth/session")).status).toBe(401);
  });

  it("rejects bad signatures, audiences, nonces, events and subjects", async () => {
    const s = await stack();
    const sid = await signedIn(s);
    for (const token of [
      await s.mock.logoutToken({ sid }, { foreignKey: true }),
      await s.mock.logoutToken({ sid }, { claims: { aud: "another-app" } }),
      await s.mock.logoutToken(
        { sid },
        { claims: { iss: "https://evil.example" } },
      ),
      await s.mock.logoutToken({ sid }, { claims: { nonce: "n" } }),
      await s.mock.logoutToken({ sid }, { claims: { events: {} } }),
      await s.mock.logoutToken({ sid }, { claims: { events: { other: {} } } }),
      await s.mock.logoutToken({}),
      await s.mock.logoutToken({ sid }, { omit: ["jti"] }),
      await s.mock.logoutToken({ sid }, { omit: ["iat"] }),
      await s.mock.logoutToken(
        { sid },
        { claims: { iat: Math.floor(Date.now() / 1000) - 3600 } },
      ),
      await s.mock.logoutToken({ sid }, { typ: "JWT+other" }),
      "not-a-jwt",
    ])
      expect(await reason(await post(s, token))).toBe("logout_token_invalid");
    expect(
      await reason(
        await fetch(`${s.api}/auth/backchannel-logout`, {
          method: "POST",
          body: new URLSearchParams(),
        }),
      ),
    ).toBe("logout_token_invalid");
    expect((await s.call("/auth/session")).status).toBe(200);
  });

  it("rejects a replayed jti", async () => {
    const s = await stack();
    const sid = await signedIn(s);
    const token = await s.mock.logoutToken({ sid });
    expect((await post(s, token)).status).toBe(200);
    const replay = await post(s, token);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({
      error: {
        code: "logout_token_invalid",
        message: "The logout token was already used.",
      },
    });
    const [row] = await rows<{ count: number }>(
      s,
      `SELECT count(*)::int AS "count" FROM {schema}.logout_jtis`,
    );
    expect(row?.count).toBe(1);
  });
});

describe.skipIf(!databaseUrl)("back-channel logout atomicity", () => {
  it("records nothing when revocation fails, so the provider's retry works", async () => {
    const s = await stack();
    s.mock.setLogin({ sub: "ada" });
    await s.signIn();
    const [session] = await rows<{ sid: string }>(
      s,
      `SELECT provider_sid AS "sid" FROM {schema}.sessions`,
    );
    const token = await s.mock.logoutToken({ sid: session?.sid ?? "" });
    const jtiCount = async () =>
      (
        await rows<{ count: number }>(
          s,
          `SELECT count(*)::int AS "count" FROM {schema}.logout_jtis`,
        )
      )[0]?.count;

    // The first revocation fails once, after the jti insert has run.
    const original = s.auth.sessions.revokeForProvider.bind(s.auth.sessions);
    let failures = 0;
    s.auth.sessions.revokeForProvider = async (input, db) => {
      if (failures++ === 0) {
        await db?.query("SELECT 1");
        throw new Error("revocation failed");
      }
      return original(input, db);
    };

    const failed = await s.mock.sendBackchannelLogout(token);
    expect(failed.status).toBe(500);
    expect(await jtiCount()).toBe(0);
    expect((await s.call("/auth/session")).status).toBe(200);

    // The provider retries the same token: it is accepted and revokes.
    const retried = await s.mock.sendBackchannelLogout(token);
    expect(retried.status).toBe(200);
    expect(await jtiCount()).toBe(1);
    expect((await s.call("/auth/session")).status).toBe(401);
    expect(await sessionStates(s)).toEqual([true]);

    // A true replay after success is still refused.
    const replay = await s.mock.sendBackchannelLogout(token);
    expect(replay.status).toBe(400);
    expect(
      ((await replay.json()) as { error: { message: string } }).error.message,
    ).toBe("The logout token was already used.");
    expect(failures).toBe(2);
  });
});

describe.skipIf(!databaseUrl)("authentik-like provider", () => {
  it("signs in and steps up without an iss in the authorization response", async () => {
    const s = await stack({ authentikLike: true });
    const discovery = (await (
      await fetch(`${s.mock.issuer}/.well-known/openid-configuration`)
    ).json()) as Record<string, unknown>;
    expect(discovery).not.toHaveProperty(
      "authorization_response_iss_parameter_supported",
    );

    s.mock.setLogin({
      sub: "ada",
      authTime: Math.floor(Date.now() / 1000) - 3600,
    });
    const callbacks: URL[] = [];
    await s.browser.follow(`${s.api}/auth/sign-in`, {
      stopAt: toWeb,
      rewrite: (url) => {
        if (toCallback(url)) callbacks.push(new URL(url));
        return url;
      },
    });
    expect(callbacks[0]?.searchParams.has("code")).toBe(true);
    expect(callbacks[0]?.searchParams.has("iss")).toBe(false);
    expect(await role(s)).toBe("member");

    s.mock.setLogin({ sub: "ada", amr: ["mfa"] });
    expect((await s.stepUp("/done")).href).toBe(`${WEB}/done`);
    expect((await s.call("/api/danger", { method: "POST" })).status).toBe(200);
  });

  it("still rejects an iss parameter that is present and wrong", async () => {
    const s = await stack({ authentikLike: true });
    const landed = await s.browser.follow(`${s.api}/auth/sign-in`, {
      stopAt: toWeb,
      rewrite: (url) => {
        if (toCallback(url))
          url.searchParams.set("iss", "https://evil.example");
        return url;
      },
    });
    expect(failure(new URL(landed.url)).reason).toBe("iss");
  });
});
