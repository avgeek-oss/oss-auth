// The page: shows who is signed in, and drives sign-in, step-up and
// sign-out through the API's /auth routes. At /oauth/consent it is the
// consent page for an MCP client.
const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const headers = { "x-requested-with": "fetch" };

interface ErrorBody {
  error: { code: string; message: string; stepUpUrl?: string };
}

async function refresh(): Promise<void> {
  const response = await fetch("/auth/session");
  const signedIn = response.ok;
  $("sign-in").hidden = signedIn;
  $("sign-out").hidden = !signedIn;
  $("sensitive").hidden = !signedIn;
  const error = new URLSearchParams(location.search).get("auth_error");
  if (!signedIn) {
    $("status").textContent = error
      ? `Sign-in failed: ${error}.`
      : "Not signed in.";
    return;
  }
  const body = (await response.json()) as {
    user: { displayName: string | null; email: string | null };
    role: string;
    session: { authenticatedAt: string };
  };
  $("status").textContent =
    `Signed in as ${body.user.displayName ?? body.user.email} (${body.role}), authenticated ${new Date(body.session.authenticatedAt).toLocaleTimeString()}.`;
}

$("sign-in").addEventListener("click", () => {
  location.assign("/auth/sign-in?returnTo=/");
});

$("sign-out").addEventListener("click", async () => {
  const response = await fetch("/auth/sign-out", { method: "POST", headers });
  const body = (await response.json()) as { endSessionUrl: string | null };
  if (body.endSessionUrl) location.assign(body.endSessionUrl);
  else await refresh();
});

$("sensitive").addEventListener("click", async () => {
  const response = await fetch("/api/sensitive", { method: "POST", headers });
  if (response.ok) {
    $("result").textContent = "Sensitive action done.";
    return;
  }
  const body = (await response.json()) as ErrorBody;
  if (body.error.code === "step_up_required" && body.error.stepUpUrl) {
    location.assign(`${body.error.stepUpUrl}?returnTo=/`);
    return;
  }
  $("result").textContent = body.error.message;
});

interface ConsentRequest {
  client: { name: string; redirectHost: string; localhost: boolean };
  resource: { uri: string; name: string | null };
  ceilings: string[];
  defaultCeiling: string;
}

async function consent(id: string): Promise<void> {
  const path = `/oauth/consent/${encodeURIComponent(id)}`;
  const response = await fetch(path);
  if (!response.ok) {
    $("result").textContent = (
      (await response.json()) as ErrorBody
    ).error.message;
    return;
  }
  const request = (await response.json()) as ConsentRequest;
  $("consent").hidden = false;
  $("consent-client").textContent = request.client.name;
  $("consent-resource").textContent =
    request.resource.name ?? request.resource.uri;
  // The redirect host is always shown: it is where the code goes.
  $("consent-host").textContent = request.client.redirectHost;
  $("consent-localhost").hidden = !request.client.localhost;
  const select = $<HTMLSelectElement>("consent-ceiling");
  select.replaceChildren(
    ...request.ceilings.map((role) => new Option(role, role)),
  );
  select.value = request.defaultCeiling;
  const decide = async (decision: "approve" | "deny") => {
    const answer = await fetch(path, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ decision, ceiling: select.value }),
    });
    const body = (await answer.json()) as { redirectUri?: string } & ErrorBody;
    if (answer.ok && body.redirectUri) {
      location.assign(body.redirectUri);
      return;
    }
    if (body.error.code === "step_up_required" && body.error.stepUpUrl) {
      location.assign(
        `${body.error.stepUpUrl}?returnTo=${encodeURIComponent(location.pathname + location.search)}`,
      );
      return;
    }
    $("result").textContent = body.error.message;
  };
  $("consent-allow").addEventListener("click", () => void decide("approve"));
  $("consent-deny").addEventListener("click", () => void decide("deny"));
}

void refresh();
const consentId = new URLSearchParams(location.search).get("request");
if (location.pathname === "/oauth/consent" && consentId)
  void consent(consentId);
