import { describe, expect, it } from "vitest";
import { deriveKey } from "../../src/index.js";
import {
  openTransaction,
  sealTransaction,
  TRANSACTION_TTL_SECONDS,
  type OidcTransaction,
} from "../../src/oidc/index.js";

const key = deriveKey("s".repeat(32), "posted", "oidc-transaction");
const now = Date.parse("2026-10-28T12:00:00Z");
const transaction: OidcTransaction = {
  state: "state-1",
  nonce: "nonce-1",
  verifier: "verifier-1",
  returnTo: "/boards",
  purpose: "sign-in",
  requestedAt: now,
};
const AAD = "posted-oidc";

describe("sealed transactions", () => {
  it("round-trips and hides the contents", () => {
    const sealed = sealTransaction(key, transaction, AAD);
    expect(sealed).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(sealed, "base64url").toString("latin1")).not.toContain(
      "nonce-1",
    );
    expect(openTransaction(key, sealed, AAD, now)).toEqual(transaction);
    const stepUp = {
      ...transaction,
      purpose: "step-up" as const,
      sessionIdHash: "a".repeat(64),
    };
    expect(
      openTransaction(key, sealTransaction(key, stepUp, AAD), AAD, now),
    ).toEqual(stepUp);
  });

  it("uses a fresh IV every time", () => {
    expect(sealTransaction(key, transaction, AAD)).not.toBe(
      sealTransaction(key, transaction, AAD),
    );
  });

  it("rejects any changed byte", () => {
    const raw = Buffer.from(
      sealTransaction(key, transaction, AAD),
      "base64url",
    );
    for (const index of [0, 1, 13, raw.length - 17, raw.length - 1]) {
      const copy = Buffer.from(raw);
      copy[index] = (copy[index] ?? 0) ^ 1;
      expect(
        openTransaction(key, copy.toString("base64url"), AAD, now),
      ).toBeNull();
    }
  });

  it("rejects another key, another binding or garbage", () => {
    const sealed = sealTransaction(key, transaction, AAD);
    expect(
      openTransaction(
        deriveKey("t".repeat(32), "posted", "oidc-transaction"),
        sealed,
        AAD,
        now,
      ),
    ).toBeNull();
    expect(
      openTransaction(
        deriveKey("s".repeat(32), "mill", "oidc-transaction"),
        sealed,
        AAD,
        now,
      ),
    ).toBeNull();
    expect(openTransaction(key, sealed, "mill-oidc", now)).toBeNull();
    for (const value of [
      "",
      "x",
      "AAAA",
      `${sealed}=`,
      sealed.slice(0, 20),
      "!!!",
    ])
      expect(openTransaction(key, value, AAD, now)).toBeNull();
  });

  it("expires after ten minutes and refuses ones from the future", () => {
    const sealed = sealTransaction(key, transaction, AAD);
    expect(TRANSACTION_TTL_SECONDS).toBe(600);
    expect(openTransaction(key, sealed, AAD, now + 600_000)).not.toBeNull();
    expect(openTransaction(key, sealed, AAD, now + 600_001)).toBeNull();
    expect(openTransaction(key, sealed, AAD, now - 61_000)).toBeNull();
  });

  it("rejects a sealed value that is not a transaction", () => {
    const bogus = sealTransaction(
      key,
      { state: 1 } as unknown as OidcTransaction,
      AAD,
    );
    expect(openTransaction(key, bogus, AAD, now)).toBeNull();
  });

  it("needs a 32-byte key", () => {
    expect(() => sealTransaction(new Uint8Array(16), transaction, AAD)).toThrow(
      RangeError,
    );
  });
});
