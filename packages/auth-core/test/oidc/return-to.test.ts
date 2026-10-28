import { describe, expect, it } from "vitest";
import { safeReturnTo } from "../../src/oidc/index.js";

const WEB = "https://posted.example.com";

describe("safeReturnTo", () => {
  it("accepts paths on the web origin", () => {
    expect(safeReturnTo(undefined, WEB)).toBe("/");
    expect(safeReturnTo(null, WEB)).toBe("/");
    expect(safeReturnTo("", WEB)).toBe("/");
    expect(safeReturnTo("/", WEB)).toBe("/");
    expect(safeReturnTo("/boards/42?tab=mine#top", WEB)).toBe(
      "/boards/42?tab=mine#top",
    );
    expect(safeReturnTo("/a/../b", WEB)).toBe("/b");
    expect(safeReturnTo("/search?q=%20x", WEB)).toBe("/search?q=%20x");
  });

  // Each of these is a known open-redirect trick.
  it.each([
    ["absolute https URL", "https://evil.example"],
    ["absolute http URL", "http://evil.example/path"],
    ["scheme-relative", "//evil.example"],
    ["scheme-relative with path", "//evil.example/posted.example.com"],
    ["backslash host", "/\\evil.example"],
    ["double backslash", "\\\\evil.example"],
    ["backslash after slash", "/\\/evil.example"],
    ["javascript scheme", "javascript:alert(1)"],
    ["data scheme", "data:text/html,<script>alert(1)</script>"],
    ["relative path", "boards"],
    ["dot path", "./boards"],
    ["tab inside scheme-relative", "/\t/evil.example"],
    ["newline", "/\nevil"],
    ["carriage return", "/x\r\nLocation: https://evil.example"],
    ["NUL", "/x\u0000"],
    ["space", "/ /evil.example"],
    ["encoded slash", "/%2F%2Fevil.example"],
    ["encoded backslash", "/%5Cevil.example"],
    ["encoded NUL", "/x%00"],
    ["userinfo trick", "https://posted.example.com@evil.example"],
    ["overlong", `/${"a".repeat(2048)}`],
    ["unicode line separator", "/ evil"],
  ])("rejects %s", (_name, value) => {
    expect(safeReturnTo(value, WEB)).toBeNull();
  });
});
