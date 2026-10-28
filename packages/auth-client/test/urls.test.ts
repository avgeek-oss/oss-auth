import { describe, expect, it } from "vitest";
import {
  addReturnTo,
  createAuthClient,
  readAuthRedirectError,
  withoutAuthRedirectError,
} from "../src/index.js";

describe("sign-in and step-up URLs", () => {
  const client = createAuthClient({ apiOrigin: "https://api.example.com" });

  it("encode returnTo as one query parameter", () => {
    expect(client.signInUrl()).toBe("https://api.example.com/auth/sign-in");
    expect(client.signInUrl(null)).toBe("https://api.example.com/auth/sign-in");
    expect(client.signInUrl("/")).toBe(
      "https://api.example.com/auth/sign-in?returnTo=%2F",
    );
    expect(client.signInUrl("/settings?tab=keys&x=1#top")).toBe(
      "https://api.example.com/auth/sign-in?returnTo=%2Fsettings%3Ftab%3Dkeys%26x%3D1%23top",
    );
    expect(client.stepUpUrl("/boards/ä b")).toBe(
      "https://api.example.com/auth/step-up?returnTo=%2Fboards%2F%C3%A4%20b",
    );
    // The value round-trips through URLSearchParams unchanged.
    const url = new URL(client.stepUpUrl("/a?b=c&d=%2F#e"));
    expect(url.searchParams.get("returnTo")).toBe("/a?b=c&d=%2F#e");
  });

  it("appends to a URL that already has a query", () => {
    expect(addReturnTo("/auth/step-up?x=1", "/p")).toBe(
      "/auth/step-up?x=1&returnTo=%2Fp",
    );
    expect(addReturnTo("/auth/step-up", "")).toBe("/auth/step-up");
  });
});

describe("readAuthRedirectError", () => {
  it("reads the code and reason the callback added", () => {
    expect(
      readAuthRedirectError(
        "https://app.example.com/?auth_error=sign_in_denied&auth_error_reason=no_role",
      ),
    ).toEqual({ code: "sign_in_denied", reason: "no_role" });
    expect(
      readAuthRedirectError(
        new URL("https://app.example.com/x?auth_error=step_up_failed"),
      ),
    ).toEqual({ code: "step_up_failed", reason: null });
    expect(
      readAuthRedirectError(
        "/?auth_error=oidc_callback_invalid&auth_error_reason=",
      ),
    ).toEqual({
      code: "oidc_callback_invalid",
      reason: null,
    });
    expect(readAuthRedirectError("https://app.example.com/?x=1")).toBeNull();
    expect(readAuthRedirectError("/?auth_error=")).toBeNull();
    expect(readAuthRedirectError("/#auth_error=forbidden")).toBeNull();
  });
});

describe("withoutAuthRedirectError", () => {
  it("removes only the auth_error parameters, keeping the rest and the hash", () => {
    expect(
      withoutAuthRedirectError(
        "https://app.example.com/p?a=1&auth_error=sign_in_denied&auth_error_reason=no_role&b=2#h",
      ),
    ).toBe("https://app.example.com/p?a=1&b=2#h");
    expect(withoutAuthRedirectError("/?auth_error=x")).toBe("/");
    expect(withoutAuthRedirectError("/p?q=1#top")).toBe("/p?q=1#top");
    expect(
      withoutAuthRedirectError(new URL("http://localhost:5173/?auth_error=x")),
    ).toBe("http://localhost:5173/");
  });
});
