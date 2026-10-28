import { Hono } from "hono";
import type { AuthConfig } from "@avgeek-oss/auth-core";
import {
  createAuth,
  type AuthEnv,
  type CreateAuthOptions,
} from "@avgeek-oss/auth-core/hono";
import {
  createMcpAuth,
  type CreateMcpAuthOptions,
} from "@avgeek-oss/auth-core/mcp";
import type { Sql } from "@avgeek-oss/auth-core/postgres";
import { handleMcp } from "./mcp.ts";

/** Seconds a sensitive action accepts since the last sign-in at the provider. */
export const SENSITIVE_MAX_AGE = 60;

/**
 * The reference API: auth routes under `/auth`, two app routes that show the
 * middleware, and an MCP endpoint protected by the OAuth authorization
 * server. Everything an app needs is the `createAuth` and `createMcpAuth`
 * calls and the route lines below them.
 */
export function createExampleApp(options: {
  config: AuthConfig;
  sql: Sql;
  oidc?: CreateAuthOptions<Record<never, never>>["oidc"];
  metadataFetch?: CreateMcpAuthOptions<Record<never, never>>["metadataFetch"];
}) {
  const auth = createAuth({
    config: options.config,
    sql: options.sql,
    ...(options.oidc ? { oidc: options.oidc } : {}),
  });
  const { cors, actor, requireActor, requireRecentAuth, trustedOrigin } =
    auth.middleware;

  const mcp = createMcpAuth({
    config: options.config,
    sql: options.sql,
    auth,
    resources: [{ path: "/mcp", name: "Reference app MCP" }],
    ...(options.metadataFetch ? { metadataFetch: options.metadataFetch } : {}),
  });

  const app = new Hono<AuthEnv<Record<never, never>>>();
  app.route("/auth", auth.routes);
  app.route("/", mcp.routes);
  // cors matters when the page is on another host; behind the dev proxy
  // the page and API share an origin and it adds nothing.
  app.use("/api/*", cors, actor, trustedOrigin, requireActor);

  app.get("/api/me", (c) => {
    const me = c.get("actor");
    return c.json({
      name: me?.user.displayName ?? me?.user.email,
      role: me?.role,
    });
  });

  app.post("/api/sensitive", requireRecentAuth(SENSITIVE_MAX_AGE), (c) =>
    c.json({ done: true, at: new Date().toISOString() }),
  );

  // The MCP endpoint: POST with a bearer token from /oauth/token. There is
  // no server-sent event stream, so GET answers 405.
  app.post("/mcp", mcp.requireMcpToken({ resource: "/mcp" }), (c) => {
    const me = c.get("actor");
    if (!me) throw new Error("requireMcpToken sets the actor");
    return handleMcp(c, me);
  });
  app.on(["GET", "DELETE"], "/mcp", (c) => {
    c.header("Allow", "POST");
    return c.body(null, 405);
  });

  return { app, auth, mcp };
}
