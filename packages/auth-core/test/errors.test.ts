import { describe, expect, it } from "vitest";
import {
  assertAppId,
  AUTH_ERROR_CODES,
  AuthConfigError,
  AuthError,
  InvalidApiKeyError,
  isAuthError,
  MigrationError,
  SecretTooShortError,
  UnknownKeyLabelError,
} from "../src/index.js";

describe("errors", () => {
  it("gives every error a stable code and its class name", () => {
    const cases: [AuthError, string, string][] = [
      [new AuthConfigError([]), "config_invalid", "AuthConfigError"],
      [new SecretTooShortError(3), "secret_too_short", "SecretTooShortError"],
      [
        new UnknownKeyLabelError("x"),
        "key_label_unknown",
        "UnknownKeyLabelError",
      ],
      [
        new InvalidApiKeyError("checksum"),
        "api_key_invalid",
        "InvalidApiKeyError",
      ],
      [
        new MigrationError("migration_modified", "0001_core.sql", "changed"),
        "migration_modified",
        "MigrationError",
      ],
    ];
    for (const [error, code, name] of cases) {
      expect(error).toBeInstanceOf(AuthError);
      expect(error).toBeInstanceOf(Error);
      expect(error.code).toBe(code);
      expect(error.name).toBe(name);
      expect(AUTH_ERROR_CODES).toContain(error.code);
    }
  });

  it("lists every config issue by variable", () => {
    const error = new AuthConfigError([
      { variable: "POSTED_SECRET", message: "is required" },
      { variable: "POSTED_WEB_ORIGIN", message: "must be an origin" },
    ]);
    expect(error.message).toBe(
      "Invalid auth configuration:\n- POSTED_SECRET: is required\n- POSTED_WEB_ORIGIN: must be an origin",
    );
    expect(error.issues).toHaveLength(2);
  });

  it("says how to fix a short secret", () => {
    expect(new SecretTooShortError(12).message).toMatch(
      /12 bytes; it must be at least 32.*openssl rand/,
    );
  });

  it("records why an API key was rejected", () => {
    const error = new InvalidApiKeyError("prefix");
    expect(error.reason).toBe("prefix");
  });

  it("names the migration at fault", () => {
    const error = new MigrationError("migration_unknown", "0009_x.sql", "m");
    expect(error.migration).toBe("0009_x.sql");
  });

  it("recognises auth errors by code, including from another copy", () => {
    const error = new SecretTooShortError(1);
    expect(isAuthError(error)).toBe(true);
    expect(isAuthError(error, "secret_too_short")).toBe(true);
    expect(isAuthError(error, "config_invalid")).toBe(false);
    const foreign = Object.assign(new Error("x"), { code: "api_key_invalid" });
    expect(isAuthError(foreign, "api_key_invalid")).toBe(true);
    expect(
      isAuthError(Object.assign(new Error("x"), { code: "ECONNRESET" })),
    ).toBe(false);
    expect(isAuthError({ code: "config_invalid" })).toBe(false);
    expect(isAuthError(null)).toBe(false);
    expect(isAuthError("config_invalid")).toBe(false);
  });
});

describe("assertAppId", () => {
  it("accepts lowercase ids and rejects everything else", () => {
    for (const app of ["mill", "posted", "rootset", "towbar", "vitalog", "a1"])
      expect(() => assertAppId(app)).not.toThrow();
    for (const app of [
      "",
      "Mill",
      "1app",
      "my-app",
      "my_app",
      "a".repeat(33),
      "pösted",
    ])
      expect(() => assertAppId(app)).toThrow(TypeError);
  });
});
