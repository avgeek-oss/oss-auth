import { describe, expect, it } from "vitest";
import { summarizeUserAgent } from "../src/sessions/index.js";

describe("summarizeUserAgent", () => {
  it("names the browser family and system without versions", () => {
    const cases: [string, string | null, string | null][] = [
      [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "Chrome",
        "macOS",
      ],
      [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
        "Edge",
        "Windows",
      ],
      [
        "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",
        "Firefox",
        "Linux",
      ],
      [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.1 Mobile/15E148 Safari/604.1",
        "Safari",
        "iOS",
      ],
      [
        "Mozilla/5.0 (iPad; CPU OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0 Mobile/15E148 Safari/604.1",
        "Chrome",
        "iPadOS",
      ],
      [
        "Mozilla/5.0 (Linux; Android 16; SM-S931B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/140.0.0.0 Mobile Safari/537.36",
        "Samsung Internet",
        "Android",
      ],
      [
        "Mozilla/5.0 (X11; CrOS x86_64 16000.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "Chrome",
        "ChromeOS",
      ],
      [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 OPR/120.0.0.0",
        "Opera",
        "Windows",
      ],
      // A WebView or another engine that says Safari without Version/.
      [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15",
        null,
        "macOS",
      ],
      ["curl/8.17.0", null, null],
      ["node", null, null],
      ["", null, null],
    ];
    for (const [header, browser, os] of cases)
      expect(summarizeUserAgent(header), header).toEqual({ browser, os });
  });

  it("answers nothing for a missing header, and reads only the start of a long one", () => {
    expect(summarizeUserAgent(undefined)).toEqual({ browser: null, os: null });
    expect(summarizeUserAgent(null)).toEqual({ browser: null, os: null });
    expect(summarizeUserAgent(`${"x".repeat(600)} Firefox/152.0`)).toEqual({
      browser: null,
      os: null,
    });
    const started = performance.now();
    summarizeUserAgent("Mozilla/5.0 (".repeat(100_000));
    expect(performance.now() - started).toBeLessThan(50);
  });
});
