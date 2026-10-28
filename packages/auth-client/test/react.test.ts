// @vitest-environment jsdom
import { act, createElement, StrictMode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthClient, type AuthClient } from "../src/index.js";
import {
  AuthProvider,
  useApiKeys,
  useConsent,
  useRequireRole,
  useSession,
  useStepUp,
} from "../src/react/index.js";
import { apiError, fakeFetch, json, SESSION } from "./support.js";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const roots: Root[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) act(() => root.unmount());
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "/");
});

/** Settles pending promises and the renders they cause. */
const flush = () => act(async () => {});

/** Renders `hook` inside an AuthProvider and returns its latest result. */
async function render<T>(
  hook: () => T,
  client: AuthClient<object>,
  options: { navigate?: (url: string) => void; strict?: boolean } = {},
) {
  const result = { current: undefined as T, renders: 0 };
  function Probe() {
    result.current = hook();
    result.renders++;
    return null;
  }
  const root = createRoot(document.createElement("div"));
  roots.push(root);
  const tree = () => {
    const provider = createElement(
      AuthProvider,
      { client, ...(options.navigate ? { navigate: options.navigate } : {}) },
      createElement(Probe),
    );
    return options.strict
      ? createElement(StrictMode, null, provider)
      : provider;
  };
  await act(async () => {
    root.render(tree());
  });
  /** Renders again, as a parent's state change would. */
  const rerender = async () => {
    await act(async () => {
      root.render(tree());
    });
    await flush();
  };
  return { result, root, rerender };
}

function clientFor(routes: Parameters<typeof fakeFetch>[0]) {
  const fake = fakeFetch(routes);
  return {
    ...fake,
    client: createAuthClient({ apiOrigin: "", fetch: fake.fetch }),
  };
}

const sessionRequests = (seen: { url: string }[]) =>
  seen.filter((r) => r.url === "/auth/session").length;

describe("useSession", () => {
  let visibility: DocumentVisibilityState = "visible";
  beforeEach(() => {
    visibility = "visible";
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => visibility,
    });
  });

  it("goes from loading to signed-in, and to signed-out on refresh after a sign-out", async () => {
    const { client, answer } = clientFor({
      "GET /auth/session": json(SESSION),
    });
    let resolve = () => {};
    const gate = new Promise<void>((r) => (resolve = r));
    const slow = {
      ...client,
      getSession: () => gate.then(() => client.getSession()),
    };
    const { result } = await render(() => useSession(), slow);
    expect(result.current).toMatchObject({
      status: "loading",
      actor: null,
      error: null,
    });
    resolve();
    await flush();
    expect(result.current.status).toBe("signed-in");
    expect(result.current.actor).toEqual(SESSION);
    answer("GET /auth/session", apiError("unauthenticated", 401));
    await act(() => result.current.refresh());
    expect(result.current).toMatchObject({
      status: "signed-out",
      actor: null,
      error: null,
    });
  });

  it("refreshes on window focus and when the page becomes visible again", async () => {
    const { client, seen, answer } = clientFor({
      "GET /auth/session": json(SESSION),
    });
    const { result } = await render(() => useSession(), client);
    expect(sessionRequests(seen)).toBe(1);
    answer("GET /auth/session", apiError("unauthenticated", 401));
    await act(async () => {
      window.dispatchEvent(new Event("focus"));
    });
    await flush();
    expect(sessionRequests(seen)).toBe(2);
    expect(result.current.status).toBe("signed-out");

    answer("GET /auth/session", json(SESSION));
    visibility = "hidden";
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(sessionRequests(seen)).toBe(2);
    visibility = "visible";
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await flush();
    expect(sessionRequests(seen)).toBe(3);
    expect(result.current.status).toBe("signed-in");
  });

  it("shares one request between concurrent refreshes, also under StrictMode", async () => {
    const { client, seen } = clientFor({ "GET /auth/session": json(SESSION) });
    const { result } = await render(() => useSession(), client, {
      strict: true,
    });
    expect(sessionRequests(seen)).toBe(1);
    await act(() =>
      Promise.all([result.current.refresh(), result.current.refresh()]).then(
        () => {},
      ),
    );
    expect(sessionRequests(seen)).toBe(2);
  });

  it("surfaces failures, keeping a known status, and stops listening on unmount", async () => {
    const { client, seen, answer } = clientFor({
      "GET /auth/session": apiError("unavailable", 503),
    });
    const { result, root } = await render(() => useSession(), client);
    // A failure on the first load: signed out, with the error.
    expect(result.current.status).toBe("signed-out");
    expect(result.current.error?.code).toBe("unavailable");
    answer("GET /auth/session", json(SESSION));
    await act(() => result.current.refresh());
    expect(result.current).toMatchObject({ status: "signed-in", error: null });
    // A later failure keeps the session shown.
    answer("GET /auth/session", new Response("<html>", { status: 502 }));
    await act(() => result.current.refresh());
    expect(result.current.status).toBe("signed-in");
    expect(result.current.actor).toEqual(SESSION);
    expect(result.current.error?.code).toBe("invalid_response");

    act(() => root.unmount());
    roots.splice(roots.indexOf(root), 1);
    const before = seen.length;
    window.dispatchEvent(new Event("focus"));
    expect(seen.length).toBe(before);
  });

  it("keeps the session when the provider re-renders with a new navigate", async () => {
    const { client, seen } = clientFor({ "GET /auth/session": json(SESSION) });
    const visited: string[] = [];
    const root = createRoot(document.createElement("div"));
    roots.push(root);
    const statuses: string[] = [];
    function Probe() {
      statuses.push(useSession().status);
      return null;
    }
    const draw = () =>
      act(async () => {
        root.render(
          createElement(
            AuthProvider,
            // A new function on every render, as an inline prop would be.
            { client, navigate: (url: string) => visited.push(url) },
            createElement(Probe),
          ),
        );
      });
    await draw();
    await draw();
    await draw();
    expect(sessionRequests(seen)).toBe(1);
    expect(statuses.at(-1)).toBe("signed-in");
    expect(statuses.lastIndexOf("loading")).toBeLessThan(
      statuses.indexOf("signed-in"),
    );
  });

  it("throws a clear error outside AuthProvider", () => {
    function Bare() {
      useSession();
      return null;
    }
    const root = createRoot(document.createElement("div"));
    // React reports the render error to the console as well.
    const quiet = vi
      .spyOn(globalThis.console, "error")
      .mockImplementation(() => {});
    const swallow = (e: ErrorEvent) => e.preventDefault();
    window.addEventListener("error", swallow);
    try {
      expect(() => act(() => root.render(createElement(Bare)))).toThrow(
        /AuthProvider/,
      );
    } finally {
      window.removeEventListener("error", swallow);
      quiet.mockRestore();
      act(() => root.unmount());
    }
  });
});

describe("useRequireRole", () => {
  it("is allowed at or above the role, forbidden below, and follows the session otherwise", async () => {
    const { client, answer } = clientFor({
      "GET /auth/session": json(SESSION),
    });
    const admin = await render(() => useRequireRole("admin"), client);
    expect(admin.result.current.status).toBe("allowed");
    expect(admin.result.current.actor?.user.id).toBe(SESSION.user.id);

    answer("GET /auth/session", json({ ...SESSION, role: "member" }));
    const member = await render(() => useRequireRole("admin"), client);
    expect(member.result.current).toMatchObject({ status: "forbidden" });
    const viewer = await render(() => useRequireRole("viewer"), client);
    expect(viewer.result.current.status).toBe("allowed");

    answer("GET /auth/session", apiError("unauthenticated", 401));
    const out = await render(() => useRequireRole("viewer"), client);
    expect(out.result.current).toEqual({ status: "signed-out", actor: null });
  });
});

describe("useStepUp", () => {
  const stepUpRequired = apiError("step_up_required", 401, {
    stepUpUrl: "https://elsewhere.example/auth/step-up",
  });

  it("navigates to step-up with the current page as returnTo, and resumes afterwards", async () => {
    window.history.replaceState(
      null,
      "",
      "/settings/keys?tab=new&auth_error=x#form",
    );
    const { client } = clientFor({
      "GET /auth/session": json(SESSION),
      "POST /auth/api-keys": [
        stepUpRequired,
        json({ key: "secret", apiKey: {} }, 201),
      ],
    });
    const visited: string[] = [];
    const first = await render(() => useStepUp(), client, {
      navigate: (url) => visited.push(url),
    });
    let value: unknown = "unset";
    await act(async () => {
      value = await first.result.current.run(
        () => client.apiKeys.create({ name: "x", ceiling: "admin" }),
        { resume: "create-admin-key" },
      );
    });
    expect(value).toBeUndefined();
    // The client's own step-up URL, never one taken from a response.
    expect(visited).toEqual([
      `/auth/step-up?returnTo=${encodeURIComponent("/settings/keys?tab=new#form")}`,
    ]);
    expect(first.result.current.error).toBeNull();

    // Back from the provider on the same page: the action is resumable once.
    window.history.replaceState(null, "", "/settings/keys?tab=new#form");
    const back = await render(() => useStepUp(), client);
    expect(back.result.current.resumed).toBe("create-admin-key");
    await act(async () => {
      value = await back.result.current.run(() =>
        client.apiKeys.create({ name: "x", ceiling: "admin" }),
      );
    });
    expect(value).toEqual({ key: "secret", apiKey: {} });
    act(() => back.result.current.clear());
    expect(back.result.current.resumed).toBeNull();
    const again = await render(() => useStepUp(), client);
    expect(again.result.current.resumed).toBeNull();
  });

  it("does not resume on another page or after a failed step-up", async () => {
    const { client } = clientFor({ "GET /auth/session": json(SESSION) });
    for (const [saved, landed] of [
      ["/a", "/b"],
      ["/a", "/a?auth_error=step_up_failed&auth_error_reason=mfa_missing"],
    ] as const) {
      window.sessionStorage.setItem(
        "avgeek-oss-auth:step-up",
        JSON.stringify({ id: "x", path: saved }),
      );
      window.history.replaceState(null, "", landed);
      const { result } = await render(() => useStepUp(), client);
      expect(result.current.resumed).toBeNull();
      expect(
        window.sessionStorage.getItem("avgeek-oss-auth:step-up"),
      ).toBeNull();
    }
    window.sessionStorage.setItem("avgeek-oss-auth:step-up", "{not json");
    const { result } = await render(() => useStepUp(), client);
    expect(result.current.resumed).toBeNull();
  });

  it("surfaces other failures as error and rejects with them", async () => {
    const { client } = clientFor({
      "GET /auth/session": json(SESSION),
      "DELETE /auth/api-keys/k1": apiError("forbidden", 403),
    });
    const visited: string[] = [];
    const { result } = await render(() => useStepUp(), client, {
      navigate: (url) => visited.push(url),
    });
    let rejected: unknown;
    await act(async () => {
      await result.current
        .run(() => client.apiKeys.revoke("k1"))
        .catch((e: unknown) => {
          rejected = e;
        });
    });
    expect(result.current.error?.code).toBe("forbidden");
    expect(rejected).toBe(result.current.error);
    expect(visited).toEqual([]);
    // The next run clears it.
    await act(async () => {
      await result.current.run(async () => 1);
    });
    expect(result.current.error).toBeNull();
  });
});

describe("data hooks", () => {
  const key = (id: string) => ({ id, name: id, ceiling: "member" });

  it("load, refetch and mutate, keeping data while reloading", async () => {
    const { client, seen, answer } = clientFor({
      "GET /auth/session": json(SESSION),
      "GET /auth/api-keys": json({ apiKeys: [key("a")] }),
      "POST /auth/api-keys": json({ key: "s3cret", apiKey: key("b") }, 201),
    });
    const { result } = await render(() => useApiKeys(), client);
    expect(result.current).toMatchObject({
      data: [key("a")],
      loading: false,
      error: null,
    });

    answer("GET /auth/api-keys", json({ apiKeys: [key("b"), key("a")] }));
    let issued: unknown;
    await act(async () => {
      issued = await result.current.mutate((c) =>
        c.apiKeys.create({ name: "b", ceiling: "member" }),
      );
    });
    expect(issued).toEqual({ key: "s3cret", apiKey: key("b") });
    expect(result.current.data).toEqual([key("b"), key("a")]);
    expect(
      seen.filter((r) => r.url === "/auth/api-keys").map((r) => r.method),
    ).toEqual(["GET", "POST", "GET"]);

    let release = (_: Response) => {};
    answer(
      "GET /auth/api-keys",
      () => new Promise<Response>((r) => (release = r)),
    );
    await act(async () => {
      void result.current.refetch();
    });
    expect(result.current.loading).toBe(true);
    expect(result.current.data).toEqual([key("b"), key("a")]);
    release(json({ apiKeys: [] }));
    await flush();
    expect(result.current).toMatchObject({ data: [], loading: false });
  });

  it("surfaces load and mutation failures", async () => {
    const { client, answer } = clientFor({
      "GET /auth/session": json(SESSION),
      "GET /auth/api-keys": apiError("unauthenticated", 401),
      "POST /auth/api-keys": apiError(
        "rate_limited",
        429,
        {},
        { "retry-after": "9" },
      ),
    });
    const { result } = await render(() => useApiKeys(), client);
    expect(result.current).toMatchObject({ data: null, loading: false });
    expect(result.current.error?.code).toBe("unauthenticated");
    answer("GET /auth/api-keys", json({ apiKeys: [] }));
    await act(() => result.current.refetch());
    expect(result.current).toMatchObject({ data: [], error: null });
    let rejected: unknown;
    await act(async () => {
      await result.current
        .mutate((c) => c.apiKeys.create({ name: "x", ceiling: "viewer" }))
        .catch((e: unknown) => (rejected = e));
    });
    expect(result.current.error).toMatchObject({
      code: "rate_limited",
      retryAfterSeconds: 9,
    });
    expect(rejected).toBe(result.current.error);
  });

  it("loads a consent request only once there is an id, and reloads when it changes", async () => {
    const { client, seen } = clientFor({
      "GET /auth/session": json(SESSION),
      "GET /oauth/consent/r1": json({ client: { name: "One" } }),
      "GET /oauth/consent/r2": json({ client: { name: "Two" } }),
    });
    let id: string | null = null;
    const { result, rerender } = await render(() => useConsent(id), client);
    expect(result.current).toMatchObject({
      data: null,
      loading: false,
      error: null,
    });
    expect(seen.some((r) => r.url.includes("consent"))).toBe(false);
    const show = async (next: string | null) => {
      id = next;
      await rerender();
    };
    await show("r1");
    expect(result.current.data).toEqual({ client: { name: "One" } });
    await show("r2");
    expect(result.current.data).toEqual({ client: { name: "Two" } });
    await show(null);
    expect(result.current).toMatchObject({ data: null, loading: false });
  });
});
