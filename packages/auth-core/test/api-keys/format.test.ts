import { describe, expect, it } from "vitest";
import {
  apiKeyChecksum,
  apiKeyPattern,
  API_KEY_CHECKSUM_LENGTH,
  API_KEY_ID_LENGTH,
  API_KEY_SECRET_LENGTH,
  formatApiKey,
  generateApiKey,
  generateApiKeyId,
  InvalidApiKeyError,
  isValidApiKey,
  parseApiKey,
  type InvalidApiKeyReason,
} from "../../src/index.js";

const ID = "01JBX5E8W6TGGDFXR9NB7QH4PC";
const SECRET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
// Checksums computed with Python's zlib.crc32.
const KEY = `posted_${ID}_${SECRET}_2THQJt`;

function reason(fn: () => unknown): InvalidApiKeyReason {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidApiKeyError);
    return (error as InvalidApiKeyError).reason;
  }
  throw new Error("expected the key to be rejected");
}

describe("apiKeyChecksum", () => {
  it("matches the known-answer vectors", () => {
    expect(apiKeyChecksum(`posted_${ID}_${SECRET}`)).toBe("2THQJt");
    expect(
      apiKeyChecksum(`mill_7ZZZZZZZZZZZZZZZZZZZZZZZZZ_${"z".repeat(43)}`),
    ).toBe("0aZcE5");
    expect(apiKeyChecksum("")).toBe("000000");
  });
});

describe("formatApiKey", () => {
  it("joins the parts and appends the checksum", () => {
    expect(formatApiKey({ prefix: "posted", id: ID, secret: SECRET })).toBe(
      KEY,
    );
  });

  it("refuses malformed parts", () => {
    const ok = { prefix: "posted", id: ID, secret: SECRET };
    for (const parts of [
      { ...ok, prefix: "Posted" },
      { ...ok, prefix: "p" },
      { ...ok, prefix: "p".repeat(17) },
      { ...ok, prefix: "post_ed" },
      { ...ok, prefix: "1posted" },
      { ...ok, id: ID.slice(1) },
      { ...ok, id: `8${ID.slice(1)}` },
      { ...ok, id: ID.replace("J", "I") },
      { ...ok, id: ID.toLowerCase() },
      { ...ok, secret: SECRET.slice(1) },
      { ...ok, secret: `${SECRET.slice(1)}-` },
      { ...ok, secret: `${SECRET.slice(1)}_` },
    ])
      expect(() => formatApiKey(parts)).toThrow(TypeError);
  });
});

describe("generateApiKey", () => {
  it("makes keys that parse back to their parts", () => {
    for (let i = 0; i < 200; i++) {
      const generated = generateApiKey("posted");
      expect(generated.id).toHaveLength(API_KEY_ID_LENGTH);
      expect(generated.secret).toHaveLength(API_KEY_SECRET_LENGTH);
      expect(generated.key).toMatch(
        /^posted_[0-7][0-9A-HJKMNP-TV-Z]{25}_[0-9A-Za-z]{43}_[0-9A-Za-z]{6}$/,
      );
      expect(parseApiKey(generated.key, "posted")).toEqual({
        prefix: "posted",
        id: generated.id,
        secret: generated.secret,
      });
    }
  });

  it("uses a given id", () => {
    const generated = generateApiKey("mill", ID);
    expect(generated.id).toBe(ID);
    expect(generated.key.startsWith(`mill_${ID}_`)).toBe(true);
  });

  it("spreads secret characters evenly across base62", () => {
    const counts = new Map<string, number>();
    for (let i = 0; i < 2000; i++)
      for (const char of generateApiKey("posted").secret)
        counts.set(char, (counts.get(char) ?? 0) + 1);
    // 86,000 draws over 62 characters: 1,387 each, standard deviation 37.
    // The band is six deviations wide each way. Plain `byte % 62` would give
    // the first eight characters about 1,680 each, outside it.
    expect(counts.size).toBe(62);
    for (const count of counts.values()) {
      expect(count).toBeGreaterThan(1165);
      expect(count).toBeLessThan(1610);
    }
  });

  it("refuses an invalid prefix", () => {
    expect(() => generateApiKey("Posted")).toThrow(TypeError);
  });
});

describe("generateApiKeyId", () => {
  it("makes distinct 128-bit Crockford ids", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 500; i++) {
      const id = generateApiKeyId();
      expect(id).toMatch(/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/);
      ids.add(id);
    }
    expect(ids.size).toBe(500);
  });
});

describe("parseApiKey", () => {
  it("parses a valid key", () => {
    expect(parseApiKey(KEY)).toEqual({
      prefix: "posted",
      id: ID,
      secret: SECRET,
    });
    expect(parseApiKey(KEY, "posted").id).toBe(ID);
  });

  it("rejects malformed keys", () => {
    for (const value of [
      "",
      "posted",
      KEY.slice(0, -1),
      `${KEY}x`,
      ` ${KEY}`,
      `${KEY}\n`,
      KEY.replace(/_/g, "-"),
      KEY.replace("posted_", "Posted_"),
      KEY.replace(ID, ID.toLowerCase()),
      `posted_${ID}_${SECRET}`,
      `posted_${ID}_${SECRET.slice(0, 42)}-_2THQJt`,
      `posted__${ID}_${SECRET}_2THQJt`,
      // Rootset's current format: no checksum, base64url secret.
      `rst_${ID}_${"A".repeat(43)}`,
    ])
      expect(reason(() => parseApiKey(value))).toBe("malformed");
    expect(reason(() => parseApiKey(42 as unknown as string))).toBe(
      "malformed",
    );
  });

  it("rejects keys for another app", () => {
    expect(reason(() => parseApiKey(KEY, "mill"))).toBe("prefix");
  });

  it("rejects a bad checksum, including single-character typos", () => {
    expect(reason(() => parseApiKey(`${KEY.slice(0, -6)}000000`))).toBe(
      "checksum",
    );
    const positions = [8, 20, 34, 60, 76, 80];
    for (const position of positions) {
      const char = KEY[position] === "A" ? "B" : "A";
      const typo = KEY.slice(0, position) + char + KEY.slice(position + 1);
      expect(reason(() => parseApiKey(typo))).toBe("checksum");
    }
    // Swapping two different neighbours.
    const swapped = KEY.slice(0, 34) + KEY[35] + KEY[34] + KEY.slice(36);
    expect(swapped).not.toBe(KEY);
    expect(reason(() => parseApiKey(swapped))).toBe("checksum");
  });

  it("checks the prefix before the checksum", () => {
    const wrong = `${KEY.slice(0, -6)}000000`;
    expect(reason(() => parseApiKey(wrong, "mill"))).toBe("prefix");
  });

  it("refuses an invalid expected prefix as a programming error", () => {
    expect(() => parseApiKey(KEY, "POSTED")).toThrow(TypeError);
  });
});

describe("isValidApiKey", () => {
  it("returns a boolean for any input", () => {
    expect(isValidApiKey(KEY)).toBe(true);
    expect(isValidApiKey(KEY, "posted")).toBe(true);
    expect(isValidApiKey(KEY, "mill")).toBe(false);
    expect(isValidApiKey(`${KEY.slice(0, -1)}u`)).toBe(false);
    expect(isValidApiKey("nonsense")).toBe(false);
    for (const value of [undefined, null, 1, {}, [KEY]])
      expect(isValidApiKey(value)).toBe(false);
  });

  it("still throws for an invalid expected prefix", () => {
    expect(() => isValidApiKey(KEY, "bad prefix")).toThrow(TypeError);
  });
});

describe("apiKeyPattern", () => {
  it("finds keys in text for secret scanning", () => {
    const other = generateApiKey("posted").key;
    const text = `token=${KEY}\nAuthorization: Bearer ${other}. mill_${ID}_${SECRET}_2THQJt`;
    expect(
      [...text.matchAll(apiKeyPattern("posted"))].map((m) => m[0]),
    ).toEqual([KEY, other]);
  });

  it("does not match inside longer words", () => {
    const pattern = apiKeyPattern("posted");
    expect(`x${KEY}`.match(pattern)).toBeNull();
    expect(`${KEY}x`.match(pattern)).toBeNull();
    expect(`my_${KEY}`.match(pattern)).toBeNull();
  });

  it("refuses an invalid prefix", () => {
    expect(() => apiKeyPattern("a.b")).toThrow(TypeError);
  });

  it("keeps the documented lengths", () => {
    expect([
      API_KEY_ID_LENGTH,
      API_KEY_SECRET_LENGTH,
      API_KEY_CHECKSUM_LENGTH,
    ]).toEqual([26, 43, 6]);
    expect(KEY).toHaveLength("posted".length + 1 + 26 + 1 + 43 + 1 + 6);
  });
});
