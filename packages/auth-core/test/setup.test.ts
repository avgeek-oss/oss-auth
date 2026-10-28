import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  AuthSetupError,
  checkAuthSetup,
  loadAuthConfig,
  type AuthConfig,
  type AuthSetupReport,
} from "../src/index.js";
import type { FetchLike } from "../src/oidc/client.js";
import {
  loadMigrations,
  migrate,
  quoteIdent,
  type Sql,
} from "../src/postgres/index.js";
import {
  adapters,
  databaseUrl,
  dropSchemas,
  uniqueSchema,
} from "./postgres/support.js";
import { startStack, type Stack } from "./hono/support.js";

const ISSUER = "https://auth.example.com/application/o/posted/";

/** A provider that answers discovery and the token probe, as told. */
function provider(
  overrides: {
    metadata?: Record<string, unknown>;
    token?: () => Response;
    discovery?: () => Response;
  } = {},
): FetchLike {
  return async (url) => {
    if (url.endsWith("/.well-known/openid-configuration"))
      return (
        overrides.discovery?.() ??
        Response.json({
          issuer: ISSUER,
          response_types_supported: ["code"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint: "https://auth.example.com/application/o/token/",
          ...overrides.metadata,
        })
      );
    return (
      overrides.token?.() ??
      Response.json({ error: "invalid_grant" }, { status: 400 })
    );
  };
}

const codes = (report: AuthSetupReport) =>
  report.problems.map((p) => `${p.level}:${p.code}`).sort();

describe.skipIf(!databaseUrl)("checkAuthSetup", () => {
  let sql: Sql;
  let close: () => Promise<void>;
  const schema = uniqueSchema("setup");
  const env = {
    POSTED_SECRET: "s".repeat(32),
    POSTED_OIDC_ISSUER: ISSUER,
    POSTED_OIDC_CLIENT_ID: "posted",
    POSTED_OIDC_CLIENT_SECRET: "x",
    POSTED_OIDC_ROLE_CLAIMS: "roles",
    POSTED_OIDC_SCOPES: "openid email profile entitlements",
    POSTED_WEB_ORIGIN: "https://posted.example.com",
    POSTED_API_ORIGIN: "https://api.posted.example.com",
    POSTED_AUTH_SCHEMA: schema,
  };
  const configWith = (extra: Record<string, string> = {}) =>
    loadAuthConfig("posted", { ...env, ...extra });
  const check = (config: AuthConfig, fetch: FetchLike = provider()) =>
    checkAuthSetup({ config, sql, fetch });

  beforeAll(async () => {
    ({ sql, close } = (adapters[0] as (typeof adapters)[number]).open());
    await migrate(sql, { schema });
  });
  afterAll(async () => {
    await dropSchemas(sql, [schema]);
    await close();
  });

  it("finds nothing wrong with a correct setup, and logs a one-line summary", async () => {
    const lines: string[] = [];
    const report = await checkAuthSetup({
      config: configWith(),
      sql,
      fetch: provider(),
      log: (line) => lines.push(line),
    });
    expect(report).toEqual({ ok: true, problems: [] });
    expect(lines).toEqual(["auth setup for posted: ok, 0 errors, 0 warnings"]);
  });

  it("checks the provider's discovery document", async () => {
    expect(
      codes(
        await check(
          configWith(),
          provider({ metadata: { issuer: ISSUER.slice(0, -1) } }),
        ),
      ),
    ).toEqual(["error:oidc_issuer_mismatch"]);
    expect(
      codes(
        await check(
          configWith(),
          provider({ metadata: { response_types_supported: ["id_token"] } }),
        ),
      ),
    ).toEqual(["error:oidc_code_flow_unsupported"]);
    expect(
      codes(
        await check(
          configWith(),
          provider({
            metadata: { code_challenge_methods_supported: ["plain"] },
          }),
        ),
      ),
    ).toEqual(["error:oidc_pkce_unsupported"]);
    expect(
      codes(
        await check(
          configWith(),
          provider({
            metadata: { code_challenge_methods_supported: undefined },
          }),
        ),
      ),
    ).toEqual(["warning:oidc_pkce_unadvertised"]);
    expect(
      codes(
        await check(
          configWith(),
          provider({ metadata: { token_endpoint: undefined } }),
        ),
      ),
    ).toEqual(["error:oidc_token_endpoint_missing"]);
    for (const discovery of [
      () => new Response("down", { status: 502 }),
      () => {
        throw new TypeError("fetch failed");
      },
    ]) {
      const report = await check(configWith(), provider({ discovery }));
      expect(codes(report)).toEqual(["error:oidc_discovery_unreachable"]);
      expect(report.ok).toBe(false);
      expect(report.problems[0]?.hint).toMatch(/POSTED_OIDC_ISSUER/);
    }
  });

  it("checks the client credentials with a made-up code, and says when it cannot", async () => {
    expect(
      codes(
        await check(
          configWith(),
          provider({
            token: () =>
              Response.json({ error: "invalid_client" }, { status: 401 }),
          }),
        ),
      ),
    ).toEqual(["error:oidc_client_rejected"]);
    for (const token of [
      () => Response.json({ error: "unsupported_grant_type" }, { status: 400 }),
      () => new Response("oops", { status: 500 }),
    ])
      expect(codes(await check(configWith(), provider({ token })))).toEqual([
        "warning:oidc_client_unverified",
      ]);
    // What the probe sends.
    let sent: { url: string; body: string; auth: string } | undefined;
    await check(configWith(), async (url, init) => {
      if (url.endsWith("openid-configuration")) return provider()(url, init);
      sent = {
        url,
        body: typeof init.body === "string" ? init.body : "",
        auth: init.headers.authorization ?? "",
      };
      return Response.json({ error: "invalid_grant" }, { status: 400 });
    });
    expect(sent?.url).toBe("https://auth.example.com/application/o/token/");
    const form = new URLSearchParams(sent?.body);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(form.get("redirect_uri")).toBe(
      "https://api.posted.example.com/auth/callback",
    );
    expect(sent?.auth).toBe(
      `Basic ${Buffer.from("posted:x").toString("base64")}`,
    );
  });

  it("checks roles, scopes and SCIM", async () => {
    const empty = {
      ...configWith(),
      oidc: {
        ...configWith().oidc,
        roleMap: { claims: ["roles"], values: {} },
      },
    };
    expect(codes(await check(empty))).toEqual(["error:role_map_empty"]);
    const invalid = {
      ...configWith(),
      oidc: {
        ...configWith().oidc,
        roleMap: { claims: ["roles"], values: { x: "owner" as never } },
      },
    };
    expect(codes(await check(invalid))).toEqual(["error:role_map_invalid"]);
    expect(
      codes(
        await check(configWith({ POSTED_OIDC_SCOPES: "openid email profile" })),
      ),
    ).toEqual(["warning:scopes_role_claim"]);
    expect(
      codes(
        await check(
          configWith({
            POSTED_OIDC_ROLE_CLAIMS: "groups",
            POSTED_OIDC_SCOPES: "openid email",
          }),
        ),
      ),
    ).toEqual(["warning:scopes_role_claim"]);
    // A claim we know nothing about is not second-guessed.
    expect(
      codes(
        await check(
          configWith({
            POSTED_OIDC_ROLE_CLAIMS: "app_roles",
            POSTED_OIDC_SCOPES: "openid",
          }),
        ),
      ),
    ).toEqual([]);
    expect(
      codes(await check(configWith({ POSTED_ROLE_SOURCE: "scim" }))),
    ).toEqual(["error:scim_tokens_missing"]);
    expect(
      codes(
        await check(
          configWith({
            POSTED_ROLE_SOURCE: "scim",
            POSTED_SCIM_TOKENS: "t".repeat(32),
          }),
        ),
      ),
    ).toEqual([]);
  });

  it("checks origins, proxies and rotation", async () => {
    expect(
      codes(
        await check(
          configWith({
            POSTED_WEB_ORIGIN: "https://posted.example.com",
            POSTED_API_ORIGIN: "https://api.posted.example.net",
          }),
        ),
      ),
    ).toEqual(["error:origins_cross_site"]);
    expect(
      codes(
        await check(
          configWith({
            POSTED_WEB_ORIGIN: "https://posted.example.co.uk",
            POSTED_API_ORIGIN: "https://api.example.co.uk",
          }),
        ),
      ),
    ).toEqual(["warning:origins_site_unverified"]);
    expect(
      codes(
        await check(
          configWith({
            POSTED_WEB_ORIGIN: "http://localhost:5173",
            POSTED_API_ORIGIN: "http://localhost:8787",
          }),
        ),
      ),
    ).toEqual(["warning:origin_insecure", "warning:origin_insecure"]);
    // Loopback names are different sites from each other.
    expect(
      codes(
        await check(
          configWith({
            POSTED_WEB_ORIGIN: "http://localhost:5173",
            POSTED_API_ORIGIN: "http://127.0.0.1:8787",
          }),
        ),
      ),
    ).toContain("error:origins_cross_site");
    expect(
      codes(
        await check(
          configWith({ POSTED_TRUSTED_PROXIES: "10.0.0.0/8,0.0.0.0/0" }),
        ),
      ),
    ).toEqual(["warning:trusted_proxies_everyone"]);
    const unparsable = {
      ...configWith(),
      rateLimits: { ...configWith().rateLimits, trustedProxies: ["nope"] },
    };
    expect(codes(await check(unparsable))).toEqual([
      "error:trusted_proxies_invalid",
    ]);
    const rotating = await check(
      configWith({ POSTED_PREVIOUS_SECRETS: "p".repeat(32) }),
    );
    expect(codes(rotating)).toEqual(["warning:secret_rotation_in_progress"]);
    expect(rotating.ok).toBe(true);
    expect(JSON.stringify(rotating)).not.toContain("p".repeat(32));
  });

  it("checks that every migration is applied, unchanged and known", async () => {
    const fresh = uniqueSchema("setup_fresh");
    const partial = uniqueSchema("setup_partial");
    try {
      expect(
        codes(await check(configWith({ POSTED_AUTH_SCHEMA: fresh }))),
      ).toEqual(["error:migrations_pending"]);
      const shipped = await loadMigrations();
      await migrate(sql, { schema: partial, migrations: shipped.slice(0, 5) });
      const report = await check(configWith({ POSTED_AUTH_SCHEMA: partial }));
      expect(codes(report)).toEqual(["error:migrations_pending"]);
      expect(report.problems[0]?.message).toContain(
        shipped
          .slice(5)
          .map((m) => m.name)
          .join(", "),
      );
      const ledger = `${quoteIdent(partial)}.schema_migrations`;
      await sql.query(`UPDATE ${ledger} SET checksum = $1 WHERE name = $2`, [
        "0".repeat(64),
        shipped[0]?.name,
      ]);
      await sql.query(
        `INSERT INTO ${ledger} (name, checksum) VALUES ('9999_future.sql', $1)`,
        ["0".repeat(64)],
      );
      expect(
        codes(await check(configWith({ POSTED_AUTH_SCHEMA: partial }))),
      ).toEqual([
        "error:migrations_modified",
        "error:migrations_pending",
        "error:migrations_unknown",
      ]);
      const broken: Sql = {
        query: () => Promise.reject(new Error("connection refused")),
        transaction: () => Promise.reject(new Error("connection refused")),
      };
      expect(
        codes(
          await checkAuthSetup({
            config: configWith(),
            sql: broken,
            fetch: provider(),
          }),
        ),
      ).toEqual(["error:database_unreachable"]);
    } finally {
      await dropSchemas(sql, [fresh, partial]);
    }
  });

  it("throws with every error when asked to fail, and not for warnings", async () => {
    const config = configWith({ POSTED_ROLE_SOURCE: "scim" });
    const error = await checkAuthSetup({
      config,
      sql,
      fetch: provider({ metadata: { issuer: "https://other.example/" } }),
      failOnError: true,
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthSetupError);
    expect((error as AuthSetupError).code).toBe("setup_invalid");
    expect((error as Error).message).toMatch(/oidc_issuer_mismatch/);
    expect((error as Error).message).toMatch(/scim_tokens_missing/);
    expect((error as AuthSetupError).report.problems).toHaveLength(2);
    const lines: string[] = [];
    await expect(
      checkAuthSetup({
        config: configWith({ POSTED_OIDC_SCOPES: "openid" }),
        sql,
        fetch: provider(),
        failOnError: true,
        log: (line) => lines.push(line),
      }),
    ).resolves.toMatchObject({ ok: true });
    expect(lines[0]).toBe("auth setup for posted: ok, 0 errors, 1 warning");
    expect(lines[1]).toMatch(/^ {2}warning scopes_role_claim: /);
  });
});

describe.skipIf(!databaseUrl)("createAuth's self-check", () => {
  const stacks: Stack[] = [];
  afterEach(async () => {
    for (const s of stacks.splice(0)) await s.close();
  });

  it("runs in the background against the real provider, logging through log", async () => {
    const lines: string[] = [];
    const s = await startStack({
      env: { POSTED_SELF_CHECK: "true" },
      auth: { log: (line) => lines.push(line) },
    });
    stacks.push(s);
    const report = await s.auth.selfCheck;
    // The mock provider over loopback HTTP, and a page on localhost with the
    // API on 127.0.0.1: two sites, which the check reports.
    expect(codes(report as AuthSetupReport)).toEqual([
      "error:origins_cross_site",
      "warning:origin_insecure",
      "warning:origin_insecure",
    ]);
    expect(lines[0]).toBe("auth setup for posted: FAILED, 1 error, 2 warnings");
  });

  it("is off with SELF_CHECK=false", async () => {
    const s = await startStack();
    stacks.push(s);
    expect(s.auth.selfCheck).toBeNull();
  });
});
