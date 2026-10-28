import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
import { Hono } from "hono";
import { loadAuthConfig, type AuthConfig } from "../../src/index.js";
import {
  createAuth,
  type Auth,
  type CreateAuthOptions,
} from "../../src/hono/index.js";
import { migrate, quoteIdent, type Sql } from "../../src/postgres/index.js";
import {
  createBrowser,
  startMockProvider,
  type Browser,
  type MockProvider,
  type MockUser,
} from "../../src/testing/index.js";
import { adapters, dropSchemas, uniqueSchema } from "../postgres/support.js";

export const WEB = "http://localhost:5173";

export const ROLE_MAP = {
  "posted-viewers": "viewer",
  "posted-members": "member",
  "posted-admins": "admin",
  viewer: "viewer",
  member: "member",
  admin: "admin",
};

export const USERS: readonly MockUser[] = [
  {
    sub: "ada",
    email: "ada@example.com",
    name: "Ada",
    groups: ["posted-members"],
  },
  {
    sub: "grace",
    email: "grace@example.com",
    name: "Grace",
    groups: ["posted-viewers", "posted-admins"],
  },
  {
    sub: "nobody",
    email: "nobody@example.com",
    name: "Nobody",
    groups: ["mill-admins"],
  },
  { sub: "claimless", email: "claimless@example.com", name: "Claimless" },
  { sub: "boss", email: "boss@example.com", name: "Boss" },
];

/** A running API, provider, database schema and browser. */
export interface Stack {
  readonly api: string;
  readonly config: AuthConfig;
  readonly auth: Auth<{ plan: string }>;
  readonly mock: MockProvider;
  readonly browser: Browser;
  readonly sql: Sql;
  readonly schema: string;
  /** Starts sign-in in the browser and follows it to the web origin. */
  signIn(returnTo?: string): Promise<URL>;
  /** Starts step-up and follows it to the web origin. */
  stepUp(returnTo?: string): Promise<URL>;
  /** A request from the web origin's pages, with cookies. */
  call(path: string, init?: RequestInit): Promise<Response>;
  /** Moves the API's clock by `seconds`. */
  advance(seconds: number): void;
  close(): Promise<void>;
}

export interface StackOptions {
  readonly authentikLike?: boolean;
  /** Register the back-channel logout URI with the provider. Default true. */
  readonly backchannel?: boolean;
  readonly env?: Readonly<Record<string, string>>;
  readonly users?: readonly MockUser[];
  readonly auth?: Partial<CreateAuthOptions<{ plan: string }>>;
}

/** Starts a full stack on the `pg` adapter. */
export async function startStack(options: StackOptions = {}): Promise<Stack> {
  const { sql, close: closeSql } = (adapters[0] ?? raise()).open();
  const schema = uniqueSchema("flow");
  await migrate(sql, { schema });

  let handler: (request: Request) => Response | Promise<Response> = () =>
    new Response("starting", { status: 503 });
  const server = createServer(
    getRequestListener((request) => handler(request)),
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const api = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const mock = await startMockProvider({
    users: options.users ?? USERS,
    redirectUris: [`${api}/auth/callback`],
    postLogoutRedirectUris: [`${WEB}/`],
    ...(options.backchannel === false
      ? {}
      : { backchannelLogoutUri: `${api}/auth/backchannel-logout` }),
    authentikLike: options.authentikLike ?? false,
  });

  const config = loadAuthConfig("posted", {
    POSTED_SECRET: "test-secret-".repeat(4),
    POSTED_OIDC_ISSUER: mock.issuer,
    POSTED_OIDC_CLIENT_ID: mock.clientId,
    POSTED_OIDC_CLIENT_SECRET: mock.clientSecret,
    POSTED_OIDC_ROLE_CLAIMS: "groups,roles",
    POSTED_OIDC_ROLE_MAP: JSON.stringify(ROLE_MAP),
    POSTED_OIDC_SCOPES: "openid email profile groups roles",
    POSTED_WEB_ORIGIN: WEB,
    POSTED_API_ORIGIN: api,
    POSTED_AUTH_SCHEMA: schema,
    ...options.env,
  });

  let offset = 0;
  const auth = createAuth<{ plan: string }>({
    config,
    sql,
    hooks: { extendActor: () => ({ plan: "team" }) },
    now: () => new Date(Date.now() + offset * 1000),
    ...options.auth,
  });

  const app = new Hono();
  app.route("/auth", auth.routes);
  app.use("/api/*", auth.middleware.actor, auth.middleware.trustedOrigin);
  app.get("/api/me", auth.middleware.requireActor, (c) =>
    c.json({ role: c.get("actor")?.role }),
  );
  app.post("/api/members", auth.middleware.requireRole("admin"), (c) =>
    c.json({ ok: true }),
  );
  app.post("/api/danger", auth.middleware.requireRecentAuth(300), (c) =>
    c.json({ ok: true }),
  );
  handler = (request) => app.fetch(request);

  const browser = createBrowser();
  const toWeb = (url: URL) => url.origin === WEB;
  const navigate = async (path: string) => {
    const result = await browser.follow(`${api}${path}`, { stopAt: toWeb });
    return new URL(result.url);
  };

  return {
    api,
    config,
    auth,
    mock,
    browser,
    sql,
    schema,
    signIn: (returnTo) =>
      navigate(
        `/auth/sign-in${returnTo === undefined ? "" : `?returnTo=${encodeURIComponent(returnTo)}`}`,
      ),
    stepUp: (returnTo) =>
      navigate(
        `/auth/step-up${returnTo === undefined ? "" : `?returnTo=${encodeURIComponent(returnTo)}`}`,
      ),
    call: (path, init = {}) => {
      const headers = new Headers(init.headers);
      if (!headers.has("origin")) headers.set("origin", WEB);
      if (!headers.has("x-requested-with"))
        headers.set("x-requested-with", "fetch");
      return browser.fetch(`${api}${path}`, { ...init, headers });
    },
    advance(seconds) {
      offset += seconds;
    },
    async close() {
      await mock.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await dropSchemas(sql, [schema]);
      await closeSql();
    },
  };
}

function raise(): never {
  throw new Error("no adapter");
}

/** Reads rows of a table in the stack's schema. */
export async function rows<T extends object>(
  stack: Stack,
  query: string,
  params: unknown[] = [],
): Promise<T[]> {
  return stack.sql.query<T>(
    query.replaceAll("{schema}", quoteIdent(stack.schema)),
    params,
  );
}
