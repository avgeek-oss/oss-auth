# Reference app: Hono and Vite

A Hono API using `createAuth` from `@avgeek-oss/auth-core/hono`, and a one-page Vite front end with **Sign in**, the current user and role, **Sign out** and a **Sensitive action** that needs a sign-in within the last minute, so it triggers step-up. It is not published.

```sh
docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres pnpm dev:example
```

Then open http://localhost:5173. The mock provider from `@avgeek-oss/auth-core/testing` signs you in as Ada, an admin, with `amr: ["mfa"]`. The page proxies `/auth` and `/api` to the API on port 8787, so both share one origin. The API's code is all in [`src/app.ts`](src/app.ts); [`test/flow.test.ts`](test/flow.test.ts) drives the same flow without a browser.
