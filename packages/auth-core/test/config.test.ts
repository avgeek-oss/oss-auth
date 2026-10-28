import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import {
  AuthConfigError,
  authEnvNames,
  DEFAULT_ROLE_MAP_VALUES,
  loadAuthConfig,
  parseDuration,
  type ConfigIssue,
} from "../src/index.js";

const SECRET = "s".repeat(32);
const SCIM_TOKEN = "t".repeat(32);

const base = {
  POSTED_SECRET: SECRET,
  POSTED_OIDC_ISSUER: "https://auth.example.com/application/o/posted/",
  POSTED_OIDC_CLIENT_ID: "posted",
  POSTED_OIDC_CLIENT_SECRET: "client-secret",
  POSTED_WEB_ORIGIN: "https://posted.example.com",
  POSTED_API_ORIGIN: "https://api.posted.example.com",
};

function issues(env: Record<string, string | undefined>): ConfigIssue[] {
  try {
    loadAuthConfig("posted", env);
  } catch (error) {
    expect(error).toBeInstanceOf(AuthConfigError);
    return [...(error as AuthConfigError).issues];
  }
  throw new Error("expected the configuration to be rejected");
}

const variables = (env: Record<string, string | undefined>) =>
  issues(env).map((issue) => issue.variable);

describe("loadAuthConfig", () => {
  it("reads a minimal configuration and fills the defaults", () => {
    const config = loadAuthConfig("posted", base);
    expect({ ...config }).toEqual({
      app: "posted",
      secret: SECRET,
      oidc: {
        issuer: "https://auth.example.com/application/o/posted/",
        clientId: "posted",
        clientSecret: "client-secret",
        roleMap: { claims: ["roles"], values: DEFAULT_ROLE_MAP_VALUES },
        scopes: ["openid", "email", "profile"],
      },
      scim: { tokens: [], externalIdIsSubject: false },
      oauth: { clients: [], legacyDcr: false },
      rateLimits: {
        trustedProxies: [],
        proxyHeader: "x-forwarded-for",
        policies: {},
      },
      apiKeys: {
        prefix: "posted",
        maxTtlSeconds: 365 * 86400,
        allowNoExpiry: false,
      },
      roleSource: "claims",
      origins: {
        web: "https://posted.example.com",
        api: "https://api.posted.example.com",
      },
      session: { maxAgeSeconds: 12 * 3600, idleTimeoutSeconds: 2 * 3600 },
      schema: "auth",
    });
    expect(DEFAULT_ROLE_MAP_VALUES).toEqual({
      viewer: "viewer",
      member: "member",
      admin: "admin",
    });
  });

  it("reads every optional variable", () => {
    const config = loadAuthConfig("posted", {
      ...base,
      POSTED_OIDC_ROLE_CLAIMS: " groups , roles ",
      POSTED_OIDC_ROLE_MAP: JSON.stringify({
        "posted-admins": "admin",
        "posted-members": "member",
      }),
      POSTED_SCIM_TOKENS: `${SCIM_TOKEN}, ${"u".repeat(40)}`,
      POSTED_SESSION_MAX_AGE: "7d",
      POSTED_SESSION_IDLE_TIMEOUT: "900",
      POSTED_AUTH_SCHEMA: "Posted Auth",
    });
    expect(config.oidc.roleMap).toEqual({
      claims: ["groups", "roles"],
      values: { "posted-admins": "admin", "posted-members": "member" },
    });
    expect(config.scim.tokens).toEqual([SCIM_TOKEN, "u".repeat(40)]);
    expect(config.session).toEqual({
      maxAgeSeconds: 7 * 86400,
      idleTimeoutSeconds: 900,
    });
    expect(config.schema).toBe("Posted Auth");
  });

  it("uses the app id as the variable prefix", () => {
    expect(authEnvNames("vitalog")).toMatchObject({
      SECRET: "VITALOG_SECRET",
      OIDC_ROLE_MAP: "VITALOG_OIDC_ROLE_MAP",
      AUTH_SCHEMA: "VITALOG_AUTH_SCHEMA",
    });
    const env = Object.fromEntries(
      Object.entries(base).map(([k, v]) => [
        k.replace("POSTED_", "VITALOG_"),
        v,
      ]),
    );
    expect(loadAuthConfig("vitalog", env).app).toBe("vitalog");
    expect(() => loadAuthConfig("vitalog", base)).toThrow(AuthConfigError);
  });

  it("rejects an invalid app id as a programming error", () => {
    expect(() => loadAuthConfig("Posted", base)).toThrow(TypeError);
    expect(() => authEnvNames("my-app")).toThrow(TypeError);
  });

  it("names every missing required variable at once", () => {
    expect(issues({})).toEqual([
      {
        variable: "POSTED_SECRET",
        message: expect.stringMatching(/^is required/),
      },
      {
        variable: "POSTED_OIDC_ISSUER",
        message: expect.stringMatching(/^is required/),
      },
      {
        variable: "POSTED_OIDC_CLIENT_ID",
        message: expect.stringMatching(/^is required/),
      },
      {
        variable: "POSTED_OIDC_CLIENT_SECRET",
        message: expect.stringMatching(/^is required/),
      },
      {
        variable: "POSTED_WEB_ORIGIN",
        message: expect.stringMatching(/^is required/),
      },
      {
        variable: "POSTED_API_ORIGIN",
        message: expect.stringMatching(/^is required/),
      },
    ]);
  });

  it("treats empty values as unset", () => {
    expect(variables({ ...base, POSTED_SECRET: "" })).toEqual([
      "POSTED_SECRET",
    ]);
    expect(
      loadAuthConfig("posted", { ...base, POSTED_AUTH_SCHEMA: "" }).schema,
    ).toBe("auth");
  });

  it("puts every variable name in the message, never a value", () => {
    const env = {
      ...base,
      POSTED_SECRET: "short-secret-value",
      POSTED_SCIM_TOKENS: "tiny-token-value",
    };
    let message = "";
    try {
      loadAuthConfig("posted", env);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/^Invalid auth configuration:\n- POSTED_SECRET: /);
    expect(message).toContain("- POSTED_SCIM_TOKENS: ");
    expect(message).not.toContain("short-secret-value");
    expect(message).not.toContain("tiny-token-value");
  });

  describe("secret", () => {
    it("needs at least 32 bytes", () => {
      expect(variables({ ...base, POSTED_SECRET: "s".repeat(31) })).toEqual([
        "POSTED_SECRET",
      ]);
      expect(
        loadAuthConfig("posted", { ...base, POSTED_SECRET: "s".repeat(32) })
          .secret,
      ).toHaveLength(32);
    });

    it("counts bytes, not characters", () => {
      // 16 characters, 32 bytes in UTF-8.
      expect(
        loadAuthConfig("posted", { ...base, POSTED_SECRET: "é".repeat(16) })
          .secret,
      ).toBe("é".repeat(16));
      expect(variables({ ...base, POSTED_SECRET: "é".repeat(15) })).toEqual([
        "POSTED_SECRET",
      ]);
    });
  });

  describe("OIDC", () => {
    it("keeps the issuer exactly as written", () => {
      for (const issuer of [
        "https://accounts.google.com",
        "https://auth.example.com/application/o/posted/",
        "https://login.microsoftonline.com/7f1d8c11-0000-4000-8000-000000000000/v2.0",
        "http://localhost:9000",
      ])
        expect(
          loadAuthConfig("posted", { ...base, POSTED_OIDC_ISSUER: issuer }).oidc
            .issuer,
        ).toBe(issuer);
    });

    it("rejects issuers that are not plain HTTPS URLs", () => {
      for (const issuer of [
        "auth.example.com",
        "http://auth.example.com",
        "https://auth.example.com/?tenant=1",
        "https://auth.example.com/#x",
        "https://user:pass@auth.example.com",
        "https://Auth.Example.com",
        "https://auth.example.com:443/o/",
        "ftp://auth.example.com",
      ])
        expect(variables({ ...base, POSTED_OIDC_ISSUER: issuer })).toEqual([
          "POSTED_OIDC_ISSUER",
        ]);
    });

    it("rejects a blank client id", () => {
      expect(variables({ ...base, POSTED_OIDC_CLIENT_ID: "   " })).toEqual([
        "POSTED_OIDC_CLIENT_ID",
      ]);
    });

    it("needs at least one role claim", () => {
      expect(variables({ ...base, POSTED_OIDC_ROLE_CLAIMS: " , " })).toEqual([
        "POSTED_OIDC_ROLE_CLAIMS",
      ]);
    });

    it("rejects role maps that are not objects of roles", () => {
      for (const map of [
        "not json",
        "[]",
        "null",
        '"admin"',
        "{}",
        '{"posted-admins":"owner"}',
        '{"posted-admins":"Admin"}',
        '{" ":"admin"}',
        '{"posted-admins":["admin"]}',
      ])
        expect(variables({ ...base, POSTED_OIDC_ROLE_MAP: map })).toEqual([
          "POSTED_OIDC_ROLE_MAP",
        ]);
    });
  });

  describe("scopes", () => {
    it("reads space- or comma-separated scopes without repeats", () => {
      expect(
        loadAuthConfig("posted", {
          ...base,
          POSTED_OIDC_SCOPES: "openid  email,profile entitlements openid",
        }).oidc.scopes,
      ).toEqual(["openid", "email", "profile", "entitlements"]);
    });

    it("requires openid and valid scope characters", () => {
      for (const scopes of [
        "email profile",
        'openid ema"il',
        "openid caf\u00e9",
      ])
        expect(variables({ ...base, POSTED_OIDC_SCOPES: scopes })).toEqual([
          "POSTED_OIDC_SCOPES",
        ]);
    });
  });

  describe("role source and SCIM linking", () => {
    it("reads claims or scim, and true or false, in any case", () => {
      const config = loadAuthConfig("posted", {
        ...base,
        POSTED_ROLE_SOURCE: " SCIM ",
        POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "True",
      });
      expect(config.roleSource).toBe("scim");
      expect(config.scim.externalIdIsSubject).toBe(true);
    });

    it("rejects other values", () => {
      expect(variables({ ...base, POSTED_ROLE_SOURCE: "groups" })).toEqual([
        "POSTED_ROLE_SOURCE",
      ]);
      expect(
        variables({ ...base, POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT: "yes" }),
      ).toEqual(["POSTED_SCIM_EXTERNAL_ID_IS_SUBJECT"]);
    });
  });

  describe("OAuth clients", () => {
    const client = {
      client_id: "posted-cli",
      client_name: " Posted CLI ",
      redirect_uris: [
        "http://127.0.0.1/callback",
        "https://cli.example.com/cb",
      ],
    };
    const secret = "c".repeat(40);

    it("reads pre-registered clients and the DCR switch, and redacts secrets", () => {
      const config = loadAuthConfig("posted", {
        ...base,
        POSTED_OAUTH_CLIENTS: JSON.stringify([
          client,
          {
            client_id: "posted-ci",
            client_name: "CI",
            redirect_uris: ["https://ci.example.com/cb"],
            logo_uri: "https://ci.example.com/logo.png",
            client_secret: secret,
          },
        ]),
        POSTED_OAUTH_LEGACY_DCR: "true",
      });
      expect(config.oauth).toEqual({
        legacyDcr: true,
        clients: [
          {
            clientId: "posted-cli",
            clientName: "Posted CLI",
            redirectUris: client.redirect_uris,
            logoUri: null,
            clientSecret: null,
          },
          {
            clientId: "posted-ci",
            clientName: "CI",
            redirectUris: ["https://ci.example.com/cb"],
            logoUri: "https://ci.example.com/logo.png",
            clientSecret: secret,
          },
        ],
      });
      expect(JSON.stringify(config)).not.toContain(secret);
      expect(inspect(config)).not.toContain(secret);
    });

    it("rejects malformed clients with a reason", () => {
      const bad: unknown[] = [
        "{}",
        [{ ...client, client_id: "https://cli.example.com/meta.json" }],
        [{ ...client, client_id: "dcr_1" }],
        [{ ...client, client_name: "" }],
        [{ ...client, redirect_uris: [] }],
        [{ ...client, redirect_uris: ["http://cli.example.com/cb"] }],
        [{ ...client, redirect_uris: ["https://cli.example.com/cb#x"] }],
        [{ ...client, logo_uri: "http://cli.example.com/logo.png" }],
        [{ ...client, client_secret: "short" }],
        [{ ...client, scope: "admin" }],
        [client, client],
      ];
      for (const value of bad)
        expect(
          issues({
            ...base,
            POSTED_OAUTH_CLIENTS:
              typeof value === "string" ? value : JSON.stringify(value),
          }).map((issue) => issue.variable),
        ).toEqual(["POSTED_OAUTH_CLIENTS"]);
      expect(variables({ ...base, POSTED_OAUTH_LEGACY_DCR: "maybe" })).toEqual([
        "POSTED_OAUTH_LEGACY_DCR",
      ]);
    });
  });

  describe("rate limits", () => {
    it("reads trusted proxies and policy overrides", () => {
      const config = loadAuthConfig("posted", {
        ...base,
        POSTED_TRUSTED_PROXIES: " 10.0.0.0/8, 192.0.2.1 ,fd00::/8 ",
        POSTED_TRUSTED_PROXY_HEADER: " Forwarded ",
        POSTED_RATE_LIMITS: JSON.stringify({
          "oauth.token.ip": { limit: 300, periodSeconds: 60 },
          "app.exports": { limit: 5, periodSeconds: 3600, burst: 2 },
        }),
      });
      expect(config.rateLimits).toEqual({
        trustedProxies: ["10.0.0.0/8", "192.0.2.1", "fd00::/8"],
        proxyHeader: "forwarded",
        policies: {
          "oauth.token.ip": { limit: 300, periodSeconds: 60 },
          "app.exports": { limit: 5, periodSeconds: 3600, burst: 2 },
        },
      });
    });

    it("keeps policy names off the prototype chain", () => {
      const { policies } = loadAuthConfig("posted", {
        ...base,
        POSTED_RATE_LIMITS: JSON.stringify({
          constructor: { limit: 2, periodSeconds: 60 },
        }),
      }).rateLimits;
      expect(Object.getPrototypeOf(policies)).toBeNull();
      expect(policies.constructor).toEqual({ limit: 2, periodSeconds: 60 });
      expect("toString" in policies).toBe(false);
      expect(
        variables({
          ...base,
          POSTED_RATE_LIMITS: '{"__proto__":{"limit":1,"periodSeconds":1}}',
        }),
      ).toEqual(["POSTED_RATE_LIMITS"]);
    });

    it("rejects bad proxies, proxy headers and policies", () => {
      for (const value of ["x-real-ip", "both", "x-forwarded-for,forwarded"])
        expect(
          variables({ ...base, POSTED_TRUSTED_PROXY_HEADER: value }),
        ).toEqual(["POSTED_TRUSTED_PROXY_HEADER"]);
      for (const value of [
        "10.0.0.0/33",
        "proxy.example.com",
        "10.0.0.0/8,nope",
      ])
        expect(variables({ ...base, POSTED_TRUSTED_PROXIES: value })).toEqual([
          "POSTED_TRUSTED_PROXIES",
        ]);
      for (const value of [
        "[]",
        "nope",
        JSON.stringify({ oidc: { limit: 0, periodSeconds: 60 } }),
        JSON.stringify({ oidc: { limit: 1.5, periodSeconds: 60 } }),
        JSON.stringify({ oidc: { limit: 10, periodSeconds: 86401 } }),
        JSON.stringify({ oidc: { limit: 10, periodSeconds: 60, burst: 0 } }),
        JSON.stringify({ oidc: { limit: 10, periodSeconds: 60, window: 5 } }),
        JSON.stringify({ "Bad Name": { limit: 10, periodSeconds: 60 } }),
      ])
        expect(variables({ ...base, POSTED_RATE_LIMITS: value })).toEqual([
          "POSTED_RATE_LIMITS",
        ]);
    });
  });

  describe("API keys", () => {
    it("reads the prefix, maximum lifetime and the no-expiry switch", () => {
      const config = loadAuthConfig("posted", {
        ...base,
        POSTED_API_KEY_PREFIX: "pst",
        POSTED_API_KEY_MAX_TTL_DAYS: "30",
        POSTED_API_KEY_ALLOW_NO_EXPIRY: "TRUE",
      });
      expect(config.apiKeys).toEqual({
        prefix: "pst",
        maxTtlSeconds: 30 * 86400,
        allowNoExpiry: true,
      });
    });

    it("defaults the prefix to the app id only when it fits", () => {
      const env = {
        ...base,
        X_SECRET: SECRET,
        X_OIDC_ISSUER: base.POSTED_OIDC_ISSUER,
        X_OIDC_CLIENT_ID: "x",
        X_OIDC_CLIENT_SECRET: "x",
        X_WEB_ORIGIN: base.POSTED_WEB_ORIGIN,
        X_API_ORIGIN: base.POSTED_API_ORIGIN,
      };
      expect(loadAuthConfig("x", env).apiKeys.prefix).toBeNull();
      expect(
        loadAuthConfig("x", { ...env, X_API_KEY_PREFIX: "xapp" }).apiKeys
          .prefix,
      ).toBe("xapp");
    });

    it("rejects bad prefixes, lifetimes and switches", () => {
      for (const prefix of ["P", "a", "1abc", "posted_x", "a".repeat(17)])
        expect(variables({ ...base, POSTED_API_KEY_PREFIX: prefix })).toEqual([
          "POSTED_API_KEY_PREFIX",
        ]);
      for (const days of ["0", "3651", "1.5", "-1", "year"])
        expect(
          variables({ ...base, POSTED_API_KEY_MAX_TTL_DAYS: days }),
        ).toEqual(["POSTED_API_KEY_MAX_TTL_DAYS"]);
      expect(
        variables({ ...base, POSTED_API_KEY_ALLOW_NO_EXPIRY: "yes" }),
      ).toEqual(["POSTED_API_KEY_ALLOW_NO_EXPIRY"]);
    });
  });

  describe("SCIM tokens", () => {
    it("rejects short, spaced or repeated tokens", () => {
      for (const tokens of [
        "t".repeat(31),
        `${SCIM_TOKEN},short`,
        `${"t".repeat(20)} ${"t".repeat(20)}`,
        `${SCIM_TOKEN},${SCIM_TOKEN}`,
      ])
        expect(variables({ ...base, POSTED_SCIM_TOKENS: tokens })).toEqual([
          "POSTED_SCIM_TOKENS",
        ]);
    });
  });

  describe("origins", () => {
    it("normalises origins", () => {
      const config = loadAuthConfig("posted", {
        ...base,
        POSTED_WEB_ORIGIN: "HTTPS://Posted.Example.com:443/",
        POSTED_API_ORIGIN: "http://localhost:3001",
      });
      expect(config.origins).toEqual({
        web: "https://posted.example.com",
        api: "http://localhost:3001",
      });
    });

    it("rejects anything but a bare HTTPS or loopback origin", () => {
      for (const value of [
        "posted.example.com",
        "http://posted.example.com",
        "https://posted.example.com/app",
        "https://posted.example.com/?x=1",
        "https://posted.example.com/#top",
        "https://user@posted.example.com",
        "ws://localhost:3000",
      ]) {
        expect(variables({ ...base, POSTED_WEB_ORIGIN: value })).toEqual([
          "POSTED_WEB_ORIGIN",
        ]);
        expect(variables({ ...base, POSTED_API_ORIGIN: value })).toEqual([
          "POSTED_API_ORIGIN",
        ]);
      }
    });

    it("accepts every loopback host for development", () => {
      for (const value of [
        "http://localhost:5173",
        "http://127.0.0.1:8080",
        "http://[::1]:3000",
      ])
        expect(
          loadAuthConfig("posted", { ...base, POSTED_WEB_ORIGIN: value })
            .origins.web,
        ).toBe(value);
    });
  });

  describe("session lengths", () => {
    it("enforces the bounds", () => {
      expect(variables({ ...base, POSTED_SESSION_MAX_AGE: "299" })).toEqual([
        "POSTED_SESSION_MAX_AGE",
      ]);
      expect(variables({ ...base, POSTED_SESSION_MAX_AGE: "31d" })).toEqual([
        "POSTED_SESSION_MAX_AGE",
      ]);
      expect(
        variables({
          ...base,
          POSTED_SESSION_MAX_AGE: "1h",
          POSTED_SESSION_IDLE_TIMEOUT: "59s",
        }),
      ).toEqual(["POSTED_SESSION_IDLE_TIMEOUT"]);
      expect(
        loadAuthConfig("posted", {
          ...base,
          POSTED_SESSION_MAX_AGE: "300",
          POSTED_SESSION_IDLE_TIMEOUT: "60",
        }).session,
      ).toEqual({ maxAgeSeconds: 300, idleTimeoutSeconds: 60 });
    });

    it("rejects an idle timeout longer than the max age", () => {
      expect(
        issues({
          ...base,
          POSTED_SESSION_MAX_AGE: "1h",
          POSTED_SESSION_IDLE_TIMEOUT: "2h",
        }),
      ).toEqual([
        {
          variable: "POSTED_SESSION_IDLE_TIMEOUT",
          message: "must not be longer than the session max age",
        },
      ]);
    });

    it("rejects malformed durations", () => {
      for (const value of ["12 hours", "1.5h", "-1", "1w", "h", "1hh"])
        expect(variables({ ...base, POSTED_SESSION_MAX_AGE: value })).toEqual([
          "POSTED_SESSION_MAX_AGE",
        ]);
    });
  });

  describe("schema", () => {
    it("accepts names that need quoting", () => {
      for (const schema of [
        "auth",
        "posted_auth",
        "Posted Auth",
        'odd"name',
        "ä".repeat(31),
      ])
        expect(
          loadAuthConfig("posted", { ...base, POSTED_AUTH_SCHEMA: schema })
            .schema,
        ).toBe(schema);
    });

    it("rejects reserved, padded, overlong and control-character names", () => {
      for (const schema of [
        "pg_auth",
        "PG_x",
        " auth",
        "auth ",
        "a".repeat(64),
        "ä".repeat(32),
        "au\nth",
        "au\u0000th",
      ])
        expect(variables({ ...base, POSTED_AUTH_SCHEMA: schema })).toEqual([
          "POSTED_AUTH_SCHEMA",
        ]);
    });
  });

  it("freezes the result and redacts secrets when logged", () => {
    const config = loadAuthConfig("posted", {
      ...base,
      POSTED_SCIM_TOKENS: SCIM_TOKEN,
    });
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.oidc)).toBe(true);
    expect(Object.isFrozen(config.oidc.roleMap.claims)).toBe(true);
    expect(Object.isFrozen(config.scim.tokens)).toBe(true);
    for (const text of [
      JSON.stringify(config),
      inspect(config, { depth: 5 }),
    ]) {
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain("client-secret");
      expect(text).not.toContain(SCIM_TOKEN);
      expect(text).toContain("[redacted]");
      expect(text).toContain("https://posted.example.com");
    }
    expect(config.secret).toBe(SECRET);
  });
});

describe("parseDuration", () => {
  it("reads seconds and unit suffixes", () => {
    expect(parseDuration("0")).toBe(0);
    expect(parseDuration("90")).toBe(90);
    expect(parseDuration("90s")).toBe(90);
    expect(parseDuration("15m")).toBe(900);
    expect(parseDuration(" 12h ")).toBe(43200);
    expect(parseDuration("30d")).toBe(2592000);
  });

  it("returns null for anything else", () => {
    for (const value of [
      "",
      "m",
      "1.5h",
      "-5",
      "5 m",
      "5M",
      "1y",
      "1234567890",
    ])
      expect(parseDuration(value)).toBeNull();
  });
});
