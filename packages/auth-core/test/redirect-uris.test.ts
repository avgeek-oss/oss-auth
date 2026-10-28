import { describe, expect, it } from "vitest";
import { isValidRedirectUri, redirectMatches } from "../src/index.js";

describe("isValidRedirectUri", () => {
  it("accepts https and loopback http, and nothing else", () => {
    for (const uri of [
      "https://app.example.com/cb",
      "https://app.example.com/cb?x=1",
      "http://127.0.0.1/cb",
      "http://127.0.0.1:8080/cb",
      "http://[::1]:8080/cb",
      "http://localhost:3000/cb",
    ])
      expect(isValidRedirectUri(uri), uri).toBe(true);
    for (const uri of [
      "http://app.example.com/cb",
      "http://127.0.0.1.example.com/cb",
      "https://app.example.com/cb#frag",
      "https://user:pass@app.example.com/cb",
      "javascript:alert(1)",
      "com.example.app:/cb",
      "not a url",
      `https://app.example.com/${"x".repeat(2048)}`,
      42,
    ])
      expect(isValidRedirectUri(uri), String(uri)).toBe(false);
  });
});

describe("redirectMatches", () => {
  it("matches exactly", () => {
    expect(
      redirectMatches(
        "https://app.example.com/cb",
        "https://app.example.com/cb",
      ),
    ).toBe(true);
    for (const supplied of [
      "https://app.example.com/cb/",
      "https://app.example.com/CB",
      "https://app.example.com/cb?x=1",
      "https://app.example.com:443/cb?",
      "https://evil.example.com/cb",
      "https://app.example.com.evil.example/cb",
    ])
      expect(
        redirectMatches("https://app.example.com/cb", supplied),
        supplied,
      ).toBe(false);
  });

  it("lets the port of a loopback IP literal vary, as RFC 8252 allows", () => {
    expect(
      redirectMatches("http://127.0.0.1/cb", "http://127.0.0.1:51234/cb"),
    ).toBe(true);
    expect(
      redirectMatches("http://127.0.0.1:8000/cb", "http://127.0.0.1:9000/cb"),
    ).toBe(true);
    expect(redirectMatches("http://[::1]/cb", "http://[::1]:4000/cb")).toBe(
      true,
    );
    // The rest must still match exactly.
    expect(
      redirectMatches("http://127.0.0.1/cb", "http://127.0.0.1:5000/other"),
    ).toBe(false);
    expect(redirectMatches("http://127.0.0.1/cb", "http://[::1]:5000/cb")).toBe(
      false,
    );
    expect(
      redirectMatches("http://127.0.0.1/cb", "https://127.0.0.1:5000/cb"),
    ).toBe(false);
    // localhost is matched exactly: a name can resolve elsewhere.
    expect(
      redirectMatches("http://localhost:3000/cb", "http://localhost:3001/cb"),
    ).toBe(false);
  });

  it("refuses an invalid registered or supplied URI", () => {
    expect(
      redirectMatches("http://app.example.com/cb", "http://app.example.com/cb"),
    ).toBe(false);
    expect(
      redirectMatches(
        "https://app.example.com/cb",
        "https://app.example.com/cb#x",
      ),
    ).toBe(false);
  });
});
