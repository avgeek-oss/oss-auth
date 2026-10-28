import { hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createKeyring,
  deriveKey,
  KEY_DERIVATION_SALT,
  KEY_LABELS,
  SecretTooShortError,
  UnknownKeyLabelError,
  type KeyLabel,
} from "../src/index.js";

const SECRET = "correct horse battery staple, 32+ bytes long";

describe("deriveKey", () => {
  // Computed independently with Python's hmac module (RFC 5869 by hand).
  // These pin the derivation: if one changes, every stored hash breaks.
  it("matches the known-answer vectors", () => {
    const vectors: [string, string, KeyLabel, string][] = [
      [
        SECRET,
        "posted",
        "session",
        "b2fd21ecd3877e9aa588bd5619d7df07318586877655129a7250292c92ced72d",
      ],
      [
        SECRET,
        "posted",
        "api-key",
        "9ea7b9e0fe642a3f98069fe1b8ca43c8e6542dd0ef997214d044281435cb88e8",
      ],
      [
        SECRET,
        "posted",
        "scim-token",
        "c5b4e91f44cc09caa9615bbd4d88e6dfeeeb51e539ec2afee90900fc67e53737",
      ],
      [
        SECRET,
        "posted",
        "idempotency",
        "47743fc30b397d1303b65eb9a2e260f72293b299105e869b918e949e0f8cf903",
      ],
      [
        SECRET,
        "mill",
        "session",
        "0928b0de9b005e9c8a6f32e595cc85518547f70ab7c3d15fbfcaa96db529ac36",
      ],
      [
        SECRET,
        "vitalog",
        "oauth-code",
        "69fafb2f489d2f5f86ad34ee9e13be96e98b45bb397d1b2485e26f2633ce208b",
      ],
      [
        "pässwörd-ünïcode-sécret-ëxämple-ok",
        "towbar",
        "break-glass",
        "9fbb4cfc8a2b660716480b52da98b5d5860f87c6bbcc343e06a4f687b4ca134e",
      ],
    ];
    for (const [secret, app, label, hex] of vectors)
      expect(deriveKey(secret, app, label).toString("hex")).toBe(hex);
  });

  it("is HKDF-SHA256 with the documented salt and info", () => {
    expect(KEY_DERIVATION_SALT).toBe("avgeek-oss/auth-core");
    for (const label of KEY_LABELS)
      expect(deriveKey(SECRET, "rootset", label)).toEqual(
        Buffer.from(
          hkdfSync(
            "sha256",
            SECRET,
            KEY_DERIVATION_SALT,
            `rootset:${label}:v1`,
            32,
          ),
        ),
      );
  });

  it("gives every label and every app a different 32-byte key", () => {
    const seen = new Set<string>();
    for (const app of ["mill", "posted", "rootset", "towbar", "vitalog"])
      for (const label of KEY_LABELS) {
        const key = deriveKey(SECRET, app, label);
        expect(key).toHaveLength(32);
        seen.add(key.toString("hex"));
      }
    expect(seen.size).toBe(5 * KEY_LABELS.length);
  });

  it("keeps a fixed registry of unique labels", () => {
    expect(KEY_LABELS).toEqual([
      "session",
      "oidc-transaction",
      "scim-token",
      "api-key",
      "oauth-code",
      "oauth-access-token",
      "oauth-refresh-token",
      "idempotency",
      "break-glass",
    ]);
    expect(new Set(KEY_LABELS).size).toBe(KEY_LABELS.length);
  });

  it("refuses secrets under 32 bytes", () => {
    expect(() => deriveKey("", "posted", "session")).toThrow(
      SecretTooShortError,
    );
    expect(() => deriveKey("x".repeat(31), "posted", "session")).toThrow(
      SecretTooShortError,
    );
    expect(deriveKey("x".repeat(32), "posted", "session")).toHaveLength(32);
    // Bytes, not characters: 16 two-byte characters are enough.
    expect(deriveKey("é".repeat(16), "posted", "session")).toHaveLength(32);
    expect(() => deriveKey("é".repeat(15), "posted", "session")).toThrow(
      SecretTooShortError,
    );
  });

  it("refuses labels outside the registry", () => {
    expect(() => deriveKey(SECRET, "posted", "sessions" as KeyLabel)).toThrow(
      UnknownKeyLabelError,
    );
    expect(() => deriveKey(SECRET, "posted", "" as KeyLabel)).toThrow(
      UnknownKeyLabelError,
    );
  });

  it("refuses invalid app ids", () => {
    expect(() => deriveKey(SECRET, "Posted", "session")).toThrow(TypeError);
    expect(() => deriveKey(SECRET, "pos:ted", "session")).toThrow(TypeError);
  });
});

describe("createKeyring", () => {
  it("returns the derived keys", () => {
    const ring = createKeyring(SECRET, "posted");
    for (const label of KEY_LABELS)
      expect(ring.key(label)).toEqual(deriveKey(SECRET, "posted", label));
  });

  it("hands out copies, so callers cannot change the cached key", () => {
    const ring = createKeyring(SECRET, "posted");
    const first = ring.key("session");
    first.fill(0);
    expect(ring.key("session")).toEqual(deriveKey(SECRET, "posted", "session"));
  });

  it("validates the secret and app id up front", () => {
    expect(() => createKeyring("short", "posted")).toThrow(SecretTooShortError);
    expect(() => createKeyring(SECRET, "Posted")).toThrow(TypeError);
  });

  it("still refuses unknown labels", () => {
    expect(() =>
      createKeyring(SECRET, "posted").key("nope" as KeyLabel),
    ).toThrow(UnknownKeyLabelError);
  });
});
