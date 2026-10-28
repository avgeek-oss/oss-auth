import { createHash, randomBytes } from "node:crypto";
import { expect } from "vitest";
import {
  createMcpAuth,
  type McpAuth,
  type McpHooks,
  type MetadataFetchOptions,
} from "../../src/mcp/index.js";
import { createBrowser, type Browser } from "../../src/testing/index.js";
import {
  rows,
  startStack,
  WEB,
  type Stack,
  type StackOptions,
} from "../hono/support.js";

export const PUBLIC_CLIENT = "posted-cli";
export const PUBLIC_REDIRECT = "http://127.0.0.1/callback";
export const CONFIDENTIAL_CLIENT = "posted-ci";
export const CONFIDENTIAL_REDIRECT = "https://ci.example.com/oauth/callback";
export const CONFIDENTIAL_SECRET = "ci-secret-".repeat(4);

export const CLIENTS = [
  {
    client_id: PUBLIC_CLIENT,
    client_name: "Posted CLI",
    redirect_uris: [PUBLIC_REDIRECT, "http://localhost:7777/callback"],
  },
  {
    client_id: CONFIDENTIAL_CLIENT,
    client_name: "Posted CI",
    redirect_uris: [CONFIDENTIAL_REDIRECT],
    logo_uri: "https://ci.example.com/logo.png",
    client_secret: CONFIDENTIAL_SECRET,
  },
];

/** A PKCE pair. */
export function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export interface McpStack extends Stack {
  readonly mcp: McpAuth<{ plan: string }>;
  readonly resource: string;
  readonly v1: string;
  /** Signs a person in with a fresh browser and returns their helpers. */
  person(sub: string, authTime?: number): Promise<Person>;
  /** POSTs a form to an OAuth endpoint. */
  form(
    path: string,
    fields: Record<string, string>,
    basic?: { id: string; secret: string },
  ): Promise<{
    status: number;
    body: Record<string, unknown>;
    headers: Headers;
  }>;
  /** Calls a protected route with a bearer token. */
  bearer(path: string, token: string): Promise<Response>;
}

export interface Person {
  readonly browser: Browser;
  /** A request from the web origin's pages. */
  call(path: string, init?: RequestInit): Promise<Response>;
  /** GETs /oauth/authorize and returns where it redirects (or the error). */
  authorize(params: Record<string, string>): Promise<Response>;
  /** Runs authorize and consent, returning the redirect with the code. */
  connect(options?: {
    readonly ceiling?: string;
    readonly scope?: string;
    readonly resource?: string;
    readonly client?: string;
    readonly redirectUri?: string;
    readonly state?: string;
    readonly restrictions?: unknown;
  }): Promise<{
    code: string;
    verifier: string;
    redirect: URL;
    clientId: string;
    redirectUri: string;
    resource: string;
  }>;
  /** connect, then the code exchange; returns the token response. */
  tokens(options?: Parameters<Person["connect"]>[0]): Promise<{
    access_token: string;
    refresh_token: string;
    scope: string;
    clientId: string;
    resource: string;
  }>;
  stepUp(): Promise<void>;
}

export async function startMcp(
  options: StackOptions & {
    readonly hooks?: McpHooks<{ plan: string }>;
    readonly metadataFetch?: MetadataFetchOptions;
  } = {},
): Promise<McpStack> {
  let mcp: McpAuth<{ plan: string }> | undefined;
  const s = await startStack({
    ...options,
    env: { POSTED_OAUTH_CLIENTS: JSON.stringify(CLIENTS), ...options.env },
    mount: (app, context) => {
      mcp = createMcpAuth({
        config: context.config,
        sql: context.sql,
        auth: context.auth,
        resources: [
          { path: "/mcp", name: "Posted MCP" },
          { path: "/v1", name: "Posted API", scope: "viewer" },
        ],
        now: context.now,
        ...(options.hooks ? { hooks: options.hooks } : {}),
        ...(options.metadataFetch
          ? { metadataFetch: options.metadataFetch }
          : {}),
      });
      app.route("/", mcp.routes);
      const me = (c: {
        get: (key: "actor") => unknown;
        json: (v: unknown) => Response;
      }) => {
        const actor = c.get("actor") as {
          role: string;
          user: { id: string };
          credential: unknown;
        };
        return c.json({
          role: actor.role,
          user: actor.user.id,
          credential: actor.credential,
        });
      };
      app.post("/mcp", mcp.requireMcpToken({ resource: "/mcp" }), (c) =>
        me(c as never),
      );
      app.post(
        "/mcp/admin",
        mcp.requireMcpToken({ resource: "/mcp", role: "admin" }),
        (c) => me(c as never),
      );
      app.post(
        "/mcp/members",
        mcp.requireMcpToken({ resource: "/mcp" }),
        context.auth.middleware.requireRole("member"),
        (c) => me(c as never),
      );
      app.get("/v1/things", mcp.requireMcpToken({ resource: "/v1" }), (c) =>
        me(c as never),
      );
    },
  });
  if (!mcp) throw new Error("mcp not mounted");
  const created = mcp;
  const resource = `${s.api}/mcp`;

  const form: McpStack["form"] = async (path, fields, basic) => {
    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
    };
    if (basic)
      headers.authorization = `Basic ${Buffer.from(
        `${encodeURIComponent(basic.id)}:${encodeURIComponent(basic.secret)}`,
      ).toString("base64")}`;
    const response = await fetch(`${s.api}${path}`, {
      method: "POST",
      headers,
      body: new URLSearchParams(fields).toString(),
    });
    const text = await response.text();
    return {
      status: response.status,
      body: (response.headers.get("content-type") ?? "").includes("json")
        ? (JSON.parse(text) as Record<string, unknown>)
        : {},
      headers: response.headers,
    };
  };

  const person = async (sub: string, authTime?: number): Promise<Person> => {
    const browser = createBrowser();
    const toWeb = (url: URL) => url.origin === WEB;
    s.mock.setLogin({
      sub,
      amr: ["mfa"],
      ...(authTime === undefined ? {} : { authTime }),
    });
    const landed = await browser.follow(`${s.api}/auth/sign-in`, {
      stopAt: toWeb,
    });
    expect(new URL(landed.url).origin).toBe(WEB);
    const call = (path: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers);
      if (!headers.has("origin")) headers.set("origin", WEB);
      if (!headers.has("x-requested-with"))
        headers.set("x-requested-with", "fetch");
      return browser.fetch(`${s.api}${path}`, { ...init, headers });
    };
    const authorize = (params: Record<string, string>) =>
      browser.fetch(
        `${s.api}/oauth/authorize?${new URLSearchParams(params).toString()}`,
      );
    const connect: Person["connect"] = async (o = {}) => {
      const { verifier, challenge } = pkce();
      const clientId = o.client ?? PUBLIC_CLIENT;
      const redirectUri =
        o.redirectUri ??
        (clientId === CONFIDENTIAL_CLIENT
          ? CONFIDENTIAL_REDIRECT
          : PUBLIC_REDIRECT);
      const target = o.resource ?? resource;
      const response = await authorize({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: target,
        state: o.state ?? "state-1",
        ...(o.scope ? { scope: o.scope } : {}),
      });
      expect(response.status).toBe(302);
      const consentUrl = new URL(response.headers.get("location") ?? "");
      expect(consentUrl.origin + consentUrl.pathname).toBe(
        `${WEB}/oauth/consent`,
      );
      const id = consentUrl.searchParams.get("request") ?? "";
      expect(
        (await call(`/oauth/consent/${encodeURIComponent(id)}`)).status,
      ).toBe(200);
      const decided = await call(`/oauth/consent/${encodeURIComponent(id)}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          decision: "approve",
          ceiling: o.ceiling ?? "member",
          ...(o.restrictions === undefined
            ? {}
            : { restrictions: o.restrictions }),
        }),
      });
      const body = (await decided.json()) as { redirectUri: string };
      expect(decided.status).toBe(200);
      const redirect = new URL(body.redirectUri);
      return {
        code: redirect.searchParams.get("code") ?? "",
        verifier,
        redirect,
        clientId,
        redirectUri,
        resource: target,
      };
    };
    const tokens: Person["tokens"] = async (o = {}) => {
      const c = await connect(o);
      const exchanged = await form(
        "/oauth/token",
        {
          grant_type: "authorization_code",
          code: c.code,
          code_verifier: c.verifier,
          redirect_uri: c.redirectUri,
          resource: c.resource,
          ...(c.clientId === CONFIDENTIAL_CLIENT
            ? {}
            : { client_id: c.clientId }),
        },
        c.clientId === CONFIDENTIAL_CLIENT
          ? { id: CONFIDENTIAL_CLIENT, secret: CONFIDENTIAL_SECRET }
          : undefined,
      );
      expect(exchanged.status).toBe(200);
      return {
        ...(exchanged.body as {
          access_token: string;
          refresh_token: string;
          scope: string;
        }),
        clientId: c.clientId,
        resource: c.resource,
      };
    };
    return {
      browser,
      call,
      authorize,
      connect,
      tokens,
      async stepUp() {
        s.mock.setLogin({ sub, amr: ["mfa"] });
        await browser.follow(`${s.api}/auth/step-up`, { stopAt: toWeb });
      },
    };
  };

  return Object.assign(s, {
    mcp: created,
    resource,
    v1: `${s.api}/v1`,
    person,
    form,
    bearer: (path: string, token: string) =>
      fetch(`${s.api}${path}`, {
        method: path.startsWith("/v1") ? "GET" : "POST",
        headers: { authorization: `Bearer ${token}` },
      }),
  });
}

export { rows };
