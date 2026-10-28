import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import {
  AuthClientError,
  isAuthClientError,
  roleAtLeast,
  withoutAuthRedirectError,
  type ApiKey,
  type AuthClient,
  type AuthSession,
  type ConnectedApp,
  type ConsentRequest,
  type Role,
} from "../index.js";

/** Where the session stands: still loading, signed in or signed out. */
export type SessionStatus = "loading" | "signed-in" | "signed-out";

/** What {@link useSession} returns. */
export interface SessionState<Ext extends object = Record<string, unknown>> {
  readonly status: SessionStatus;
  /** The signed-in caller, or `null`. */
  readonly actor: AuthSession<Ext> | null;
  /**
   * The last refresh's failure, other than being signed out, or `null`. The
   * status and actor are kept, so a network blip does not sign the page
   * out; a failure on the first load leaves it `signed-out`.
   */
  readonly error: AuthClientError | null;
  /** Fetches the session again. Concurrent calls share one request. */
  readonly refresh: () => Promise<void>;
}

interface SessionStore {
  readonly get: () => Omit<SessionState, "refresh">;
  readonly subscribe: (listener: () => void) => () => void;
  readonly refresh: () => Promise<void>;
}

interface AuthContextValue {
  readonly client: AuthClient<object>;
  readonly store: SessionStore;
  readonly navigate: (url: string) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const INITIAL: Omit<SessionState, "refresh"> = {
  status: "loading",
  actor: null,
  error: null,
};

/** An {@link AuthClientError} for anything a hook caught. */
function asClientError(error: unknown): AuthClientError {
  return isAuthClientError(error)
    ? error
    : new AuthClientError({
        code: "invalid_response",
        status: 0,
        message: error instanceof Error ? error.message : String(error),
        cause: error,
      });
}

function createSessionStore(client: AuthClient<object>): SessionStore {
  let state = INITIAL;
  let inflight: Promise<void> | null = null;
  const listeners = new Set<() => void>();
  const set = (next: Omit<SessionState, "refresh">) => {
    state = next;
    for (const listener of listeners) listener();
  };
  return {
    get: () => state,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    refresh: () => {
      inflight ??= client
        .getSession()
        .then(
          (actor) =>
            set({
              status: actor ? "signed-in" : "signed-out",
              actor: actor as AuthSession | null,
              error: null,
            }),
          (error: unknown) =>
            set({
              status: state.status === "loading" ? "signed-out" : state.status,
              actor: state.actor,
              error: asClientError(error),
            }),
        )
        .finally(() => {
          inflight = null;
        });
      return inflight;
    },
  };
}

/** Props of {@link AuthProvider}. */
export interface AuthProviderProps {
  readonly client: AuthClient<object>;
  readonly children?: ReactNode;
  /**
   * How to navigate to sign-in and step-up URLs. Default
   * `window.location.assign`; pass a router's for client-side routes.
   */
  readonly navigate?: (url: string) => void;
}

/**
 * Makes `client` and the session available to the hooks below. Loads the
 * session on mount, and again when the window regains focus or the page
 * becomes visible, so a sign-out in another tab shows up.
 */
export function AuthProvider(props: AuthProviderProps): ReactNode {
  const { client } = props;
  // The latest navigate, without rebuilding the store when an inline
  // function changes identity on every render.
  const navigateRef = useRef(props.navigate);
  navigateRef.current = props.navigate;
  const value = useMemo<AuthContextValue>(
    () => ({
      client,
      store: createSessionStore(client),
      navigate: (url) =>
        (navigateRef.current ?? ((to) => window.location.assign(to)))(url),
    }),
    [client],
  );
  useEffect(() => {
    const refresh = () => void value.store.refresh();
    const visible = () => {
      if (document.visibilityState === "visible") refresh();
    };
    refresh();
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", visible);
    return () => {
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [value]);
  return createElement(AuthContext.Provider, { value }, props.children);
}

function useAuthContext(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value)
    throw new Error("Wrap the app in <AuthProvider> to use the auth hooks.");
  return value;
}

/** The client given to {@link AuthProvider}. */
export function useAuthClient<
  Ext extends object = Record<string, unknown>,
>(): AuthClient<Ext> {
  return useAuthContext().client as AuthClient<Ext>;
}

/** The session: `loading` until the first answer, then signed in or out. */
export function useSession<
  Ext extends object = Record<string, unknown>,
>(): SessionState<Ext> {
  const { store } = useAuthContext();
  const state = useSyncExternalStore(store.subscribe, store.get, () => INITIAL);
  return {
    ...(state as Omit<SessionState<Ext>, "refresh">),
    refresh: store.refresh,
  };
}

/** What {@link useRequireRole} returns. */
export interface RoleCheck<Ext extends object = Record<string, unknown>> {
  /**
   * `allowed` when signed in with `minimum` or higher, `forbidden` when
   * signed in below it, otherwise the session's status.
   */
  readonly status: "loading" | "signed-out" | "forbidden" | "allowed";
  readonly actor: AuthSession<Ext> | null;
}

/** Whether the signed-in caller has at least `minimum`. Renders nothing by itself. */
export function useRequireRole<Ext extends object = Record<string, unknown>>(
  minimum: Role,
): RoleCheck<Ext> {
  const { status, actor } = useSession<Ext>();
  if (!actor)
    return {
      status: status === "loading" ? "loading" : "signed-out",
      actor: null,
    };
  return {
    status: roleAtLeast(actor.role, minimum) ? "allowed" : "forbidden",
    actor,
  };
}

const STEP_UP_KEY = "avgeek-oss-auth:step-up";

/** What {@link useStepUp} returns. */
export interface StepUp {
  /**
   * Runs `action`. If it fails with `step_up_required`, records
   * `options.resume` (when given), navigates to the step-up URL with the
   * current page as `returnTo`, and resolves to `undefined`. Any other
   * failure is set as `error` and rejects.
   */
  readonly run: <T>(
    action: () => Promise<T>,
    options?: { readonly resume?: string },
  ) => Promise<T | undefined>;
  /**
   * The `resume` value of the action that sent the person to step up, now
   * that they are back on the same page after confirming; otherwise
   * `null`. Run the action again, then call `clear`.
   */
  readonly resumed: string | null;
  /** Forgets `resumed`. */
  readonly clear: () => void;
  /** The last failure of `run` other than `step_up_required`, or `null`. */
  readonly error: AuthClientError | null;
}

/** The page's path, without `auth_error` parameters, for `returnTo`. */
function currentPath(): string {
  const { pathname, search, hash } = window.location;
  return withoutAuthRedirectError(`${pathname}${search}${hash}`);
}

function samePage(path: string): boolean {
  const here = currentPath();
  const strip = (value: string) => value.split("#")[0];
  return strip(path) === strip(here);
}

/** Re-confirms the person at the identity provider when an action needs it. */
export function useStepUp(): StepUp {
  const { client, navigate } = useAuthContext();
  const [resumed, setResumed] = useState<string | null>(null);
  const [error, setError] = useState<AuthClientError | null>(null);
  useEffect(() => {
    try {
      const saved = window.sessionStorage.getItem(STEP_UP_KEY);
      if (saved === null) return;
      window.sessionStorage.removeItem(STEP_UP_KEY);
      const { id, path } = JSON.parse(saved) as {
        id?: unknown;
        path?: unknown;
      };
      const failed = new URLSearchParams(window.location.search).has(
        "auth_error",
      );
      if (typeof id === "string" && typeof path === "string" && !failed)
        if (samePage(path)) setResumed(id);
    } catch {
      // No storage (private mode) or a corrupt entry: nothing to resume.
    }
  }, []);
  const run = useCallback<StepUp["run"]>(
    async (action, options) => {
      setError(null);
      try {
        return await action();
      } catch (caught) {
        if (isAuthClientError(caught, "step_up_required")) {
          const path = currentPath();
          if (options?.resume !== undefined)
            try {
              window.sessionStorage.setItem(
                STEP_UP_KEY,
                JSON.stringify({ id: options.resume, path }),
              );
            } catch {
              // Without storage the action is not resumed automatically.
            }
          navigate(client.stepUpUrl(path));
          return undefined;
        }
        if (isAuthClientError(caught)) setError(caught);
        throw caught;
      }
    },
    [client, navigate],
  );
  const clear = useCallback(() => setResumed(null), []);
  return { run, resumed, clear, error };
}

/** What the data hooks return. */
export interface AuthResource<T> {
  /** The last loaded value, kept while reloading; `null` before the first. */
  readonly data: T | null;
  /** The last load's or mutation's failure, or `null`. */
  readonly error: AuthClientError | null;
  readonly loading: boolean;
  /** Loads again. */
  readonly refetch: () => Promise<void>;
  /**
   * Runs `change` with the client, then loads again, and resolves to what
   * `change` returned (such as a new key's secret). A failure is set as
   * `error` and rejects, so it can be wrapped in {@link StepUp.run}.
   */
  readonly mutate: <R>(
    change: (client: AuthClient<object>) => Promise<R>,
  ) => Promise<R>;
}

function useResource<T>(
  load: ((client: AuthClient<object>) => Promise<T>) | null,
  key: string,
): AuthResource<T> {
  const { client } = useAuthContext();
  const [state, setState] = useState<{
    data: T | null;
    error: AuthClientError | null;
    loading: boolean;
  }>({ data: null, error: null, loading: load !== null });
  const latest = useRef(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  const refetch = useCallback(async () => {
    const current = loadRef.current;
    const ticket = ++latest.current;
    if (!current) {
      setState({ data: null, error: null, loading: false });
      return;
    }
    setState((previous) => ({ ...previous, loading: true }));
    try {
      const data = await current(client);
      if (ticket === latest.current)
        setState({ data, error: null, loading: false });
    } catch (caught) {
      if (ticket === latest.current)
        setState((previous) => ({
          ...previous,
          error: asClientError(caught),
          loading: false,
        }));
    }
  }, [client]);

  useEffect(() => {
    void refetch();
    return () => {
      // Answers to a request made for an earlier key are dropped.
      latest.current++;
    };
  }, [refetch, key]);

  const mutate = useCallback<AuthResource<T>["mutate"]>(
    async (change) => {
      try {
        const result = await change(client);
        await refetch();
        return result;
      } catch (caught) {
        const error = asClientError(caught);
        setState((previous) => ({ ...previous, error }));
        throw caught;
      }
    },
    [client, refetch],
  );

  return { ...state, refetch, mutate };
}

/** The signed-in person's API keys. */
export function useApiKeys(): AuthResource<ApiKey[]> {
  return useResource((client) => client.apiKeys.list(), "api-keys");
}

/** The MCP clients the signed-in person connected. */
export function useConnectedApps(): AuthResource<ConnectedApp[]> {
  return useResource((client) => client.connectedApps.list(), "connected-apps");
}

/**
 * The consent request `id` (from the page's `?request=`), or nothing while
 * `id` is `null`. Decide with `mutate((c) => c.consent.decide(id, …))`, or
 * call the client directly, then navigate to the returned `redirectUri`.
 */
export function useConsent(id: string | null): AuthResource<ConsentRequest> {
  return useResource(
    id === null ? null : (client) => client.consent.get(id),
    `consent:${id ?? ""}`,
  );
}
