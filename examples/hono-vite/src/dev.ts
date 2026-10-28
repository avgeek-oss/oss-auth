// Runs the reference app locally: a mock identity provider, the Hono API and
// the Vite page, in one process. Needs DATABASE_URL (any disposable
// Postgres) and a build of @avgeek-oss/auth-core (`pnpm dev:example` does
// both from the repository root).
import { createServer as createHttpServer } from "node:http";
import { fileURLToPath } from "node:url";
import { getRequestListener } from "@hono/node-server";
import pg from "pg";
import { createServer as createViteServer } from "vite";
import { loadAuthConfig } from "@avgeek-oss/auth-core";
import { runAuthWorker } from "@avgeek-oss/auth-core/jobs";
import { fromPg, migrate } from "@avgeek-oss/auth-core/postgres";
import { startMockProvider } from "@avgeek-oss/auth-core/testing";
import { createExampleApp } from "./app.ts";

const WEB = "http://localhost:5173";
const API_PORT = 8787;
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  process.stderr.write(
    "Set DATABASE_URL to a disposable Postgres database, for example\n" +
      "  docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine\n" +
      "  DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres pnpm dev:example\n",
  );
  process.exit(1);
}

// The page proxies the API's paths, so both share the web origin, which is
// then also the OAuth issuer.
const mock = await startMockProvider({
  users: [
    {
      sub: "ada",
      email: "ada@example.com",
      name: "Ada Lovelace",
      groups: ["example-admins"],
    },
    {
      sub: "grace",
      email: "grace@example.com",
      name: "Grace Hopper",
      groups: ["example-members"],
    },
  ],
  redirectUris: [`${WEB}/auth/callback`],
  postLogoutRedirectUris: [`${WEB}/`],
  backchannelLogoutUri: `http://127.0.0.1:${API_PORT}/auth/backchannel-logout`,
});
mock.setLogin({ sub: "ada", amr: ["mfa"] });

const config = loadAuthConfig("example", {
  EXAMPLE_SECRET: "local-development-secret-only-for-the-example",
  EXAMPLE_OIDC_ISSUER: mock.issuer,
  EXAMPLE_OIDC_CLIENT_ID: mock.clientId,
  EXAMPLE_OIDC_CLIENT_SECRET: mock.clientSecret,
  EXAMPLE_OIDC_ROLE_CLAIMS: "groups",
  EXAMPLE_OIDC_ROLE_MAP: JSON.stringify({
    "example-admins": "admin",
    "example-members": "member",
  }),
  EXAMPLE_OIDC_SCOPES: "openid email profile groups",
  EXAMPLE_WEB_ORIGIN: WEB,
  EXAMPLE_API_ORIGIN: WEB,
  EXAMPLE_AUTH_SCHEMA: "example_auth",
  // An MCP client registered by the operator: a local CLI on any loopback
  // port. Clients with a metadata document need no registration.
  EXAMPLE_OAUTH_CLIENTS: JSON.stringify([
    {
      client_id: "example-cli",
      client_name: "Example CLI",
      redirect_uris: ["http://127.0.0.1/callback"],
    },
  ]),
});

const sql = fromPg(new pg.Pool({ connectionString: databaseUrl }));
await migrate(sql, { schema: config.schema });
const { app } = createExampleApp({ config, sql });
// Sweeps expired sessions, tokens and the rest every five minutes. An app
// with a job runner calls runAuthJobs from it instead.
void runAuthWorker({ sql, config, signal: new AbortController().signal });
createHttpServer(getRequestListener(app.fetch)).listen(API_PORT, "127.0.0.1");

const vite = await createViteServer({
  root: fileURLToPath(new URL("..", import.meta.url)),
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/auth": `http://127.0.0.1:${API_PORT}`,
      "/api": `http://127.0.0.1:${API_PORT}`,
      "/mcp": `http://127.0.0.1:${API_PORT}`,
      "/.well-known": `http://127.0.0.1:${API_PORT}`,
      // The consent page itself is the Vite page; only its API is proxied.
      "^/oauth/(?!consent(?:\\?|$))": `http://127.0.0.1:${API_PORT}`,
    },
  },
});
await vite.listen();
process.stdout.write(
  `Reference app on ${WEB}. Mock provider ${mock.issuer} signs in as Ada (admin).\n`,
);
