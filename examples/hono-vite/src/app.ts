import { Hono } from "hono";
import type { AuthConfig } from "@avgeek-oss/auth-core";
import {
  createAuth,
  type AuthEnv,
  type CreateAuthOptions,
} from "@avgeek-oss/auth-core/hono";
import type { Sql } from "@avgeek-oss/auth-core/postgres";

/** Seconds a sensitive action accepts since the last sign-in at the provider. */
export const SENSITIVE_MAX_AGE = 60;

/**
 * The reference API: auth routes under `/auth`, and two app routes that show
 * the middleware. Everything an app needs is the `createAuth` call and the
 * three `app.use`/route lines.
 */
export function createExampleApp(options: {
  config: AuthConfig;
  sql: Sql;
  oidc?: CreateAuthOptions<Record<never, never>>["oidc"];
}) {
  const auth = createAuth({
    config: options.config,
    sql: options.sql,
    ...(options.oidc ? { oidc: options.oidc } : {}),
  });
  const { actor, requireActor, requireRecentAuth, trustedOrigin } =
    auth.middleware;

  const app = new Hono<AuthEnv<Record<never, never>>>();
  app.route("/auth", auth.routes);
  app.use("/api/*", actor, trustedOrigin, requireActor);

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

  return { app, auth };
}
