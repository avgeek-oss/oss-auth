import { describe, expect, it } from "vitest";
import {
  constantTimeEqual,
  deriveKey,
  generateToken,
  hashToken,
  isWellFormedToken,
  TOKEN_BYTES,
  TOKEN_LENGTH,
  verifyTokenHash,
} from "../src/index.js";

const SECRET = "correct horse battery staple, 32+ bytes long";
const key = deriveKey(SECRET, "posted", "session");

describe("generateToken", () => {
  it("makes 256-bit base64url tokens", () => {
    expect(TOKEN_BYTES).toBe(32);
    expect(TOKEN_LENGTH).toBe(43);
    for (let i = 0; i < 200; i++) {
      const token = generateToken();
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(Buffer.from(token, "base64url")).toHaveLength(32);
      expect(isWellFormedToken(token)).toBe(true);
    }
  });

  it("does not repeat", () => {
    const tokens = new Set(Array.from({ length: 1000 }, generateToken));
    expect(tokens.size).toBe(1000);
  });
});

describe("isWellFormedToken", () => {
  it("rejects anything that is not exactly 32 bytes of base64url", () => {
    const token = generateToken();
    for (const value of [
      "",
      token.slice(0, 42),
      `${token}A`,
      `${token.slice(0, 42)}=`,
      `${token.slice(0, 41)}+/`,
      // 43 characters whose last one carries bits beyond 32 bytes.
      `${"A".repeat(42)}B`,
      ` ${token.slice(1)}`,
      undefined,
      null,
      42,
    ])
      expect(isWellFormedToken(value)).toBe(false);
    expect(isWellFormedToken(`${"A".repeat(42)}w`)).toBe(true);
  });
});

describe("hashToken", () => {
  it("matches the known-answer vector", () => {
    // HMAC-SHA256 under the posted/session key, computed with Python's hmac.
    expect(hashToken(key, "dGhpcyBpcyBub3QgYSByZWFsIHNlc3Npb24gdG9rZW4")).toBe(
      "3a36b1ab24fb7dfeae6157f7d4a53d08335e269720f89501d96d3b1db4387e58",
    );
  });

  it("is 64 hex characters, keyed, and deterministic", () => {
    const token = generateToken();
    const hash = hashToken(key, token);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken(key, token)).toBe(hash);
    expect(hashToken(deriveKey(SECRET, "posted", "api-key"), token)).not.toBe(
      hash,
    );
    expect(hashToken(deriveKey(SECRET, "mill", "session"), token)).not.toBe(
      hash,
    );
  });

  it("refuses keys shorter than 32 bytes", () => {
    expect(() => hashToken(new Uint8Array(31), "x")).toThrow(RangeError);
    expect(hashToken(new Uint8Array(32), "x")).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("verifyTokenHash", () => {
  it("accepts the right token and rejects everything else", () => {
    const token = generateToken();
    const stored = hashToken(key, token);
    expect(verifyTokenHash(key, token, stored)).toBe(true);
    expect(verifyTokenHash(key, generateToken(), stored)).toBe(false);
    expect(
      verifyTokenHash(deriveKey(SECRET, "posted", "api-key"), token, stored),
    ).toBe(false);
    expect(verifyTokenHash(key, token, stored.toUpperCase())).toBe(false);
    expect(verifyTokenHash(key, token, stored.slice(0, 63))).toBe(false);
    expect(verifyTokenHash(key, token, "")).toBe(false);
  });
});

describe("constantTimeEqual", () => {
  it("compares strings and bytes exactly", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("", "")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
    expect(constantTimeEqual("abc", "")).toBe(false);
    expect(constantTimeEqual("\u00e9", "e\u0301")).toBe(false);
    expect(
      constantTimeEqual(Buffer.from([1, 2, 3]), new Uint8Array([1, 2, 3])),
    ).toBe(true);
    expect(constantTimeEqual(Buffer.from("abc"), "abc")).toBe(true);
    expect(
      constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0])),
    ).toBe(false);
  });
});
