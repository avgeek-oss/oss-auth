// The page: shows who is signed in, and drives sign-in, step-up and
// sign-out through the API's /auth routes.
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

void refresh();
