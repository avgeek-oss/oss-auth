# Reference app: Hono and Vite

A Hono API using `createAuth` from `@avgeek-oss/auth-core/hono`, and a one-page Vite front end with **Sign in**, the current user and role, **Sign out** and a **Sensitive action** that needs a sign-in within the last minute, so it triggers step-up. It is not published.

```sh
docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres pnpm dev:example
```

Then open http://localhost:5173. The mock provider from `@avgeek-oss/auth-core/testing` signs you in as Ada, an admin, with `amr: ["mfa"]`. The page proxies the API's paths to port 8787, so both share one origin. The API's code is all in [`src/app.ts`](src/app.ts); [`test/flow.test.ts`](test/flow.test.ts) drives the same flow without a browser.

The API is also an OAuth authorization server for MCP clients, with an MCP endpoint at `/mcp` ([`src/mcp.ts`](src/mcp.ts), an `echo` and a `whoami` tool) protected by `requireMcpToken`. `example-cli` is a pre-registered public client with the redirect URI `http://127.0.0.1/callback`, on any port, and the page at `/oauth/consent` is the consent screen. [`test/mcp.test.ts`](test/mcp.test.ts) connects the official MCP TypeScript SDK client: discovery, PKCE, consent, a tool call, refresh and revocation.
