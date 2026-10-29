// The page, on @avgeek-oss/auth-client and its React hooks: sign-in, the
// session, step-up for a sensitive action, the person's sessions, API keys
// and connected apps, and at /oauth/consent the consent screen for an MCP
// client. It has no styling
// of its own: the design system owns how these screens look.
import { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  createAuthClient,
  readAuthError,
  readAuthRedirectError,
  withoutAuthRedirectError,
  type ActiveSession,
  type IssuedApiKey,
  type Role,
  type SignOutResult,
} from "@avgeek-oss/auth-client";
import {
  AuthProvider,
  useApiKeys,
  useAuthClient,
  useConnectedApps,
  useConsent,
  useSession,
  useStepUp,
} from "@avgeek-oss/auth-client/react";

// The page proxies the API's paths, so the API is on the page's origin.
const client = createAuthClient({ apiOrigin: "" });

function SignInError() {
  const [error] = useState(() => readAuthRedirectError(location.href));
  useEffect(() => {
    if (error)
      history.replaceState(null, "", withoutAuthRedirectError(location.href));
  }, [error]);
  if (!error) return null;
  return (
    <p role="alert">
      Sign-in failed: {error.code}
      {error.reason ? ` (${error.reason})` : ""}.
    </p>
  );
}

function Session() {
  const { status, actor, refresh } = useSession();
  const stepUp = useStepUp();
  const [result, setResult] = useState("");

  const sensitive = () =>
    stepUp.run(
      async () => {
        const response = await fetch("/api/sensitive", {
          method: "POST",
          headers: { "x-requested-with": "fetch" },
        });
        if (!response.ok) throw await readAuthError(response);
        setResult("Sensitive action done.");
      },
      { resume: "sensitive" },
    );

  // Back from step-up: finish what the person asked for.
  const { resumed, clear } = stepUp;
  useEffect(() => {
    if (resumed !== "sensitive") return;
    clear();
    void sensitive().catch(() => {});
  }, [resumed, clear]);

  if (status === "loading") return <p>Loading…</p>;
  if (!actor)
    return (
      <p>
        Not signed in.{" "}
        <button onClick={() => location.assign(client.signInUrl("/"))}>
          Sign in
        </button>
      </p>
    );
  return (
    <>
      <p>
        Signed in as {actor.user.displayName ?? actor.user.email} ({actor.role}
        ), authenticated{" "}
        {new Date(actor.session.authenticatedAt).toLocaleTimeString()}.
      </p>
      <p>
        <button onClick={() => void sensitive().catch(() => {})}>
          Sensitive action
        </button>
        <button
          onClick={async () => {
            const logout = await client.signOut();
            if (logout) location.assign(logout);
            else await refresh();
          }}
        >
          Sign out
        </button>
      </p>
      <p role="status">{stepUp.error?.message ?? result}</p>
      <Sessions />
      <ApiKeys />
      <ConnectedApps />
    </>
  );
}

function Sessions() {
  const auth = useAuthClient();
  const { refresh } = useSession();
  const [sessions, setSessions] = useState<ActiveSession[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    () =>
      auth.sessions.list().then(
        (list) => {
          setSessions(list);
          setError(null);
        },
        (failure: Error) => setError(failure.message),
      ),
    [auth],
  );
  useEffect(() => {
    void load();
  }, [load]);

  // Ending this page's own session signs it out, as Sign out does.
  const signedOut = async ({ endSessionUrl }: SignOutResult) => {
    if (endSessionUrl) location.assign(endSessionUrl);
    else await refresh();
  };
  const signOut = (session: ActiveSession) =>
    auth.sessions.revoke(session.id).then(
      (result) => (result.current ? signedOut(result) : load()),
      (failure: Error) => setError(failure.message),
    );
  const everywhere = () =>
    auth.sessions
      .signOutEverywhere()
      .then(signedOut, (failure: Error) => setError(failure.message));

  return (
    <section>
      <h2>Sessions</h2>
      {error && <p role="alert">{error}</p>}
      <ul>
        {(sessions ?? []).map((session) => (
          <li key={session.id}>
            {session.browser ?? "Unknown browser"} on{" "}
            {session.os ?? "an unknown system"}
            {session.current ? " (this browser)" : ""}, signed in{" "}
            {new Date(session.createdAt).toLocaleString()}, last active{" "}
            {new Date(session.lastSeenAt).toLocaleString()}{" "}
            <button onClick={() => void signOut(session)}>Sign out</button>
          </li>
        ))}
      </ul>
      <p>
        <button onClick={() => void everywhere()}>Sign out everywhere</button>
      </p>
    </section>
  );
}

function ApiKeys() {
  const keys = useApiKeys();
  const stepUp = useStepUp();
  const [name, setName] = useState("");
  const [ceiling, setCeiling] = useState<Role>("viewer");
  const [issued, setIssued] = useState<IssuedApiKey | null>(null);

  const create = () =>
    stepUp
      .run(() => keys.mutate((c) => c.apiKeys.create({ name, ceiling })))
      .then((key) => setIssued(key ?? null))
      .catch(() => {});

  return (
    <section>
      <h2>API keys</h2>
      {issued && (
        <p role="status">
          Copy your new key now, it is not shown again:{" "}
          <code>{issued.key}</code>
        </p>
      )}
      {keys.error && <p role="alert">{keys.error.message}</p>}
      <ul>
        {(keys.data ?? []).map((key) => (
          <li key={key.id}>
            {key.name} ({key.ceiling})
            {key.graceUntil ? `, replaced, works until ${key.graceUntil}` : ""}{" "}
            <button
              onClick={() =>
                void stepUp
                  .run(() =>
                    keys.mutate((c) =>
                      c.apiKeys.rotate(key.id, { graceSeconds: 3600 }),
                    ),
                  )
                  .then((next) => setIssued(next ?? null))
                  .catch(() => {})
              }
            >
              Rotate
            </button>
            <button
              onClick={() =>
                void keys
                  .mutate((c) => c.apiKeys.revoke(key.id))
                  .catch(() => {})
              }
            >
              Revoke
            </button>
          </li>
        ))}
      </ul>
      <p>
        <label>
          Name <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>{" "}
        <label>
          Highest role{" "}
          <select
            value={ceiling}
            onChange={(e) => setCeiling(e.target.value as Role)}
          >
            <option>viewer</option>
            <option>member</option>
            <option>admin</option>
          </select>
        </label>{" "}
        <button onClick={() => void create()}>Create key</button>
      </p>
    </section>
  );
}

function ConnectedApps() {
  const apps = useConnectedApps();
  return (
    <section>
      <h2>Connected apps</h2>
      {apps.error && <p role="alert">{apps.error.message}</p>}
      {apps.data?.length === 0 && <p>None.</p>}
      <ul>
        {(apps.data ?? []).map((app) => (
          <li key={app.id}>
            {app.clientName} ({app.ceiling}), last used{" "}
            {app.lastUsedAt ?? "never"}{" "}
            <button
              onClick={() =>
                void apps
                  .mutate((c) => c.connectedApps.revoke(app.id))
                  .catch(() => {})
              }
            >
              Disconnect
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Consent({ id }: { id: string }) {
  const { status } = useSession();
  const auth = useAuthClient();
  const request = useConsent(status === "signed-in" ? id : null);
  const stepUp = useStepUp();
  const [ceiling, setCeiling] = useState<Role | null>(null);

  // Sign in first, then come back to this request.
  useEffect(() => {
    if (status === "signed-out")
      location.assign(auth.signInUrl(`${location.pathname}${location.search}`));
  }, [status, auth]);

  if (status !== "signed-in") return <p>Loading…</p>;
  if (request.error) return <p role="alert">{request.error.message}</p>;
  const data = request.data;
  if (!data) return <p>Loading…</p>;
  const chosen = ceiling ?? data.defaultCeiling;
  const decide = (approve: boolean) =>
    void stepUp
      .run(() => auth.consent.decide(id, { approve, ceiling: chosen }))
      .then((decision) => {
        if (decision) location.assign(decision.redirectUri);
      })
      .catch(() => {});

  return (
    <section>
      <h2>Connect {data.client.name}?</h2>
      <p>
        It will act for you on{" "}
        <strong>{data.resource.name ?? data.resource.uri}</strong>, and send you
        back to <strong>{data.client.redirectHost}</strong>.
      </p>
      {data.client.localhost && (
        <p>
          That address is on this computer: allow it only if you started the app
          yourself.
        </p>
      )}
      <p>
        <label>
          Highest role it may use{" "}
          <select
            value={chosen}
            onChange={(e) => setCeiling(e.target.value as Role)}
          >
            {data.ceilings.map((role) => (
              <option key={role}>{role}</option>
            ))}
          </select>
        </label>
      </p>
      {stepUp.error && <p role="alert">{stepUp.error.message}</p>}
      <p>
        <button onClick={() => decide(true)}>Allow</button>
        <button onClick={() => decide(false)}>Deny</button>
      </p>
    </section>
  );
}

function Page() {
  const consentId = new URLSearchParams(location.search).get("request");
  return (
    <>
      <h1>Auth reference app</h1>
      <SignInError />
      {location.pathname === "/oauth/consent" && consentId ? (
        <Consent id={consentId} />
      ) : (
        <Session />
      )}
    </>
  );
}

const root = document.getElementById("root");
if (root)
  createRoot(root).render(
    <AuthProvider client={client}>
      <Page />
    </AuthProvider>,
  );
