import type { FetchLike } from "../src/index.js";

/** One request the fake API saw. */
export interface SeenRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly credentials: RequestCredentials | undefined;
  readonly body: unknown;
}

/** What the fake API answers: a Response, or a function of the request. */
export type Answer =
  Response | ((request: SeenRequest) => Response | Promise<Response>);

/** JSON with a status and optional headers. */
export function json(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/** auth-core's error body. */
export function apiError(
  code: string,
  status: number,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Response {
  return json(
    { error: { code, message: `${code} message`, ...extra } },
    status,
    headers,
  );
}

/**
 * A fetch that records requests and answers from `routes`, keyed by
 * `METHOD path` (path and query, without the origin). Unknown routes 404
 * with a body that is not auth-core's.
 */
export function fakeFetch(routes: Record<string, Answer | Answer[]> = {}) {
  const seen: SeenRequest[] = [];
  const queues = new Map<string, Answer[]>();
  for (const [key, value] of Object.entries(routes))
    queues.set(key, Array.isArray(value) ? [...value] : [value]);
  const fetch: FetchLike = async (input, init) => {
    const url = new URL(input, "http://page.test");
    const request: SeenRequest = {
      url: input,
      method: init.method ?? "GET",
      headers: { ...init.headers },
      credentials: init.credentials,
      body: typeof init.body === "string" ? JSON.parse(init.body) : undefined,
    };
    seen.push(request);
    const key = `${request.method} ${url.pathname}${url.search}`;
    const queue = queues.get(key);
    const answer = queue && queue.length > 1 ? queue.shift() : queue?.[0];
    if (!answer) return new Response("Not here", { status: 404 });
    return typeof answer === "function" ? answer(request) : answer.clone();
  };
  return {
    fetch,
    seen,
    /** Replaces the answers for `key`. */
    answer: (key: string, value: Answer | Answer[]) => {
      queues.set(key, Array.isArray(value) ? [...value] : [value]);
    },
  };
}

/** A session body as auth-core sends it. */
export const SESSION = {
  user: {
    id: "8f9d3c1e-1111-4a3b-9c2d-000000000001",
    role: "admin",
    email: "ada@example.com",
    displayName: "Ada",
  },
  role: "admin",
  ext: {},
  session: {
    authenticatedAt: "2026-10-28T10:00:00.000Z",
    expiresAt: "2026-10-28T22:00:00.000Z",
    amr: ["mfa"],
  },
} as const;
