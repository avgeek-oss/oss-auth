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

const FIREFOX =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0";
const CHROME_ANDROID =
  "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36";
const COOKIE = "posted-session";
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ago = (seconds: number) => Math.floor(Date.now() / 1000) - seconds;

interface SessionJson {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  idleExpiresAt: string;
  expiresAt: string;
  authenticatedAt: string;
  browser: string | null;
  os: string | null;
  current: boolean;
}

/**
 * Signs in as `sub` in a browser of its own, sending `userAgent` to the
 * callback, and returns helpers that call the API as the app's pages do.
 */
async function signedIn(
  s: Stack,
  sub: string,
  options: { userAgent?: string; authTime?: number } = {},
) {
  const browser = createBrowser();
  s.mock.setLogin({
    sub,
    amr: ["mfa"],
    ...(options.authTime === undefined ? {} : { authTime: options.authTime }),
  });
  const callback = await browser.follow(`${s.api}/auth/sign-in`, {
    stopAt: (url) => url.pathname === "/auth/callback",
  });
  const landed = await browser.follow(callback.url, {
    init: options.userAgent
      ? { headers: { "user-agent": options.userAgent } }
      : {},
    stopAt: (url) => url.origin === WEB,
  });
  expect(new URL(landed.url).origin).toBe(WEB);
  const token = browser.cookie(s.api, COOKIE) ?? "";
  expect(token).not.toBe("");
  const call = (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    if (!headers.has("origin")) headers.set("origin", WEB);
    if (!headers.has("x-requested-with"))
      headers.set("x-requested-with", "fetch");
    return browser.fetch(`${s.api}${path}`, { ...init, headers });
  };
  const send = async (method: string, path: string) => {
    const response = await call(`/auth${path}`, { method });
    const text = await response.text();
    return {
      status: response.status,
      headers: response.headers,
      text,
      body: (text === "" ? {} : JSON.parse(text)) as Record<string, unknown>,
    };
  };
  const list = async () => {
    const r = await send("GET", "/sessions");
    expect(r.status).toBe(200);
    return (r.body as { sessions: SessionJson[] }).sessions;
  };
  const currentId = async () =>
    (await list()).find((session) => session.current)?.id ?? "";
  return { browser, token, call, send, list, currentId };
}

/** Whether `token` still authenticates, sent from a browser that never had it. */
async function works(s: Stack, token: string): Promise<boolean> {
  const response = await fetch(`${s.api}/auth/session`, {
    headers: { cookie: `${COOKIE}=${token}` },
  });
  return response.status === 200;
}

describe.skipIf(!databaseUrl)("sessions over HTTP", () => {
  it("lists the caller's live sessions newest first, marking the current one, with no token or hash", async () => {
    const s = await stack();
    const laptop = await signedIn(s, "ada", { userAgent: FIREFOX });
    s.advance(5);
    const phone = await signedIn(s, "ada", { userAgent: CHROME_ANDROID });
    s.advance(5);
    const bare = await signedIn(s, "ada");

    const r = await phone.send("GET", "/sessions");
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    const listed = (r.body as { sessions: SessionJson[] }).sessions;
    expect(listed).toHaveLength(3);
    for (const session of listed) {
      expect(Object.keys(session).sort()).toEqual(
        [
          "authenticatedAt",
          "browser",
          "createdAt",
          "current",
          "expiresAt",
          "id",
          "idleExpiresAt",
          "lastSeenAt",
          "os",
        ].sort(),
      );
      for (const field of [
        "createdAt",
        "lastSeenAt",
        "idleExpiresAt",
        "expiresAt",
        "authenticatedAt",
      ] as const)
        expect(session[field]).toMatch(ISO);
      expect(session.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
    }
    // Newest first, and only the caller's own is current.
    expect(listed.map((x) => [x.browser, x.os, x.current])).toEqual([
      [null, null, false],
      ["Chrome", "Android", true],
      ["Firefox", "macOS", false],
    ]);
    // Each browser sees its own as current.
    expect(
      (await laptop.list()).filter((x) => x.current).map((x) => x.browser),
    ).toEqual(["Firefox"]);
    expect((await bare.list()).find((x) => x.current)?.id).toBe(listed[0]?.id);
    // Neither a token nor a stored hash is in the answer.
    const hashes = await rows<{ idHash: string }>(
      s,
      `SELECT id_hash AS "idHash" FROM {schema}.sessions`,
    );
    for (const secret of [
      laptop.token,
      phone.token,
      bare.token,
      ...hashes.map((h) => h.idHash),
    ])
      expect(r.text).not.toContain(secret);
    // The user agent itself is not stored.
    const stored = await rows<{ json: string }>(
      s,
      `SELECT row_to_json(x)::text AS "json" FROM {schema}.sessions x`,
    );
    for (const row of stored) expect(row.json).not.toMatch(/Mozilla|Gecko/);
  });

  it("shows only the caller's own sessions, and another person's cannot be revoked or even found", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const grace = await signedIn(s, "grace");
    const adaId = await ada.currentId();
    const graceSessions = await grace.list();
    expect(graceSessions).toHaveLength(1);
    expect(graceSessions.map((x) => x.id)).not.toContain(adaId);

    // Grace is an admin, and still cannot end Ada's session: it answers
    // exactly like an id that does not exist.
    const theirs = await grace.send("DELETE", `/sessions/${adaId}`);
    const unknown = await grace.send(
      "DELETE",
      "/sessions/00000000-0000-4000-8000-000000000000",
    );
    const malformed = await grace.send("DELETE", "/sessions/not-a-session");
    for (const answer of [theirs, unknown, malformed]) {
      expect(answer.status).toBe(404);
      expect(answer.body).toEqual({
        error: { code: "not_found", message: "No such session." },
      });
    }
    expect(await works(s, ada.token)).toBe(true);
    expect(await works(s, grace.token)).toBe(true);
    // A stored hash is not an id either.
    const [hash] = await rows<{ idHash: string }>(
      s,
      `SELECT s.id_hash AS "idHash" FROM {schema}.sessions s
       JOIN {schema}.users u ON u.id = s.user_id WHERE u.sub = 'ada'`,
    );
    expect((await ada.send("DELETE", `/sessions/${hash?.idHash}`)).status).toBe(
      404,
    );
    expect(await works(s, ada.token)).toBe(true);
  });

  it("signs out another of the caller's sessions, keeping this one", async () => {
    const s = await stack();
    const laptop = await signedIn(s, "ada");
    const phone = await signedIn(s, "ada");
    const phoneId = await phone.currentId();

    const r = await laptop.send("DELETE", `/sessions/${phoneId}`);
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.body).toEqual({ current: false, endSessionUrl: null });
    expect(r.headers.getSetCookie()).toEqual([]);
    expect(await works(s, phone.token)).toBe(false);
    expect(await works(s, laptop.token)).toBe(true);
    expect((await laptop.list()).map((x) => x.id)).not.toContain(phoneId);
    // Once.
    expect((await laptop.send("DELETE", `/sessions/${phoneId}`)).status).toBe(
      404,
    );
  });

  it("signs out the current session like sign-out", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const id = await ada.currentId();
    const r = await ada.send("DELETE", `/sessions/${id.toUpperCase()}`);
    expect(r.status).toBe(200);
    expect(r.body.current).toBe(true);
    expect(String(r.body.endSessionUrl).startsWith(s.mock.issuer)).toBe(true);
    // The cookie is cleared, and the old token no longer works anywhere.
    expect(
      r.headers.getSetCookie().some((c) => c.startsWith(`${COOKIE}=;`)),
    ).toBe(true);
    expect(ada.browser.cookie(s.api, COOKIE)).toBeUndefined();
    expect((await ada.send("GET", "/session")).status).toBe(401);
    expect(await works(s, ada.token)).toBe(false);
    expect((await ada.send("GET", "/sessions")).status).toBe(401);
  });

  it("signs out everywhere, this session included, without a recent sign-in", async () => {
    const s = await stack();
    // Signed in at the provider long ago: sign-out-everywhere still works,
    // since it only ever takes access away.
    const laptop = await signedIn(s, "ada", { authTime: ago(3600) });
    const phone = await signedIn(s, "ada");
    const tablet = await signedIn(s, "ada");
    const grace = await signedIn(s, "grace");

    const r = await laptop.send("POST", "/sessions/sign-out-everywhere");
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.body.revoked).toBe(3);
    expect(String(r.body.endSessionUrl).startsWith(s.mock.issuer)).toBe(true);
    expect(Object.keys(r.body).sort()).toEqual(["endSessionUrl", "revoked"]);
    expect(laptop.browser.cookie(s.api, COOKIE)).toBeUndefined();
    for (const old of [laptop, phone, tablet]) {
      expect(await works(s, old.token)).toBe(false);
      expect((await old.send("GET", "/sessions")).status).toBe(401);
    }
    // Other people are not affected.
    expect(await works(s, grace.token)).toBe(true);
    expect(await grace.list()).toHaveLength(1);
    const revoked = await rows<{ sub: string; revoked: boolean }>(
      s,
      `SELECT u.sub, s.revoked_at IS NOT NULL AS "revoked" FROM {schema}.sessions s
       JOIN {schema}.users u ON u.id = s.user_id ORDER BY u.sub`,
    );
    expect(revoked.map((x) => [x.sub, x.revoked])).toEqual([
      ["ada", true],
      ["ada", true],
      ["ada", true],
      ["grace", false],
    ]);
    // Signing in again works as usual.
    const again = await signedIn(s, "ada");
    expect(await again.list()).toHaveLength(1);
  });

  it("needs a signed-in session: no session is 401 and an API key is 403", async () => {
    const s = await stack();
    const anonymous = createBrowser();
    for (const [method, path] of [
      ["GET", "/auth/sessions"],
      ["DELETE", "/auth/sessions/00000000-0000-4000-8000-000000000000"],
      ["POST", "/auth/sessions/sign-out-everywhere"],
    ] as const) {
      const response = await anonymous.fetch(`${s.api}${path}`, {
        method,
        headers: { origin: WEB, "x-requested-with": "fetch" },
      });
      expect(response.status, `${method} ${path}`).toBe(401);
    }
    const ada = await signedIn(s, "ada");
    const created = await ada.call("/auth/api-keys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "CI", ceiling: "member" }),
    });
    const { key } = (await created.json()) as { key: string };
    for (const [method, path] of [
      ["GET", "/auth/sessions"],
      ["POST", "/auth/sessions/sign-out-everywhere"],
    ] as const) {
      const response = await fetch(`${s.api}${path}`, {
        method,
        headers: { authorization: `Bearer ${key}` },
      });
      expect(response.status, `${method} ${path}`).toBe(403);
      expect(await response.json()).toMatchObject({
        error: { code: "forbidden" },
      });
    }
    expect(await works(s, ada.token)).toBe(true);
  });

  it("requires the web origin and the CSRF header to sign out", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const id = await ada.currentId();
    const noHeader = await ada.browser.fetch(`${s.api}/auth/sessions/${id}`, {
      method: "DELETE",
      headers: { origin: WEB },
    });
    expect(noHeader.status).toBe(403);
    expect(await noHeader.json()).toMatchObject({
      error: { code: "csrf_header_missing" },
    });
    const elsewhere = await ada.call("/auth/sessions/sign-out-everywhere", {
      method: "POST",
      headers: { origin: "https://evil.example" },
    });
    expect(elsewhere.status).toBe(403);
    expect(await elsewhere.json()).toMatchObject({
      error: { code: "origin_invalid" },
    });
    expect(await works(s, ada.token)).toBe(true);
  });

  it("rate limits signing out per user", async () => {
    const s = await stack({
      env: {
        POSTED_RATE_LIMITS: JSON.stringify({
          "sessions.write": { limit: 2, periodSeconds: 60 },
        }),
      },
    });
    const ada = await signedIn(s, "ada");
    const others = [await signedIn(s, "ada"), await signedIn(s, "ada")];
    const ids = await Promise.all(others.map((o) => o.currentId()));
    for (const id of ids)
      expect((await ada.send("DELETE", `/sessions/${id}`)).status).toBe(200);
    const limited = await ada.send("POST", "/sessions/sign-out-everywhere");
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThanOrEqual(
      1,
    );
    expect(limited.body).toMatchObject({ error: { code: "rate_limited" } });
    expect(await works(s, ada.token)).toBe(true);
    // Another person has their own allowance, and listing is not limited.
    const grace = await signedIn(s, "grace");
    expect(
      (await grace.send("POST", "/sessions/sign-out-everywhere")).status,
    ).toBe(200);
    expect((await ada.send("GET", "/sessions")).status).toBe(200);
  });

  it("records the last sighting as the session is used", async () => {
    const s = await stack();
    const ada = await signedIn(s, "ada");
    const [first] = await ada.list();
    s.advance(120);
    await ada.call("/api/me");
    const [later] = await ada.list();
    expect(Date.parse(later?.lastSeenAt ?? "")).toBeGreaterThanOrEqual(
      Date.parse(first?.lastSeenAt ?? "") + 120_000,
    );
    expect(later?.createdAt).toBe(first?.createdAt);
  });
});
