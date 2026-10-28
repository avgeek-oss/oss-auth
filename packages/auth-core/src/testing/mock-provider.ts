import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import Provider, {
  type Configuration,
  type KoaContextWithOIDC,
} from "oidc-provider";
import { BACKCHANNEL_LOGOUT_EVENT } from "../oidc/logout.js";

/** A person the mock provider can sign in. */
export interface MockUser {
  readonly sub: string;
  readonly email?: string;
  /** Default `true`. */
  readonly emailVerified?: boolean;
  readonly name?: string;
  /** Emitted as the `groups` claim when set. */
  readonly groups?: readonly string[];
  /** Emitted as the `roles` claim when set, as authentik's entitlements do. */
  readonly roles?: readonly string[];
}

/** How the next interactive sign-in at the mock provider completes. */
export interface MockLogin {
  /** Who signs in. */
  readonly sub: string;
  /** The `amr` values. Default `["mfa"]`, as after authentik's MFA stage. */
  readonly amr?: readonly string[];
  /**
   * The authentication time, in seconds since the epoch. Default now. Set it
   * in the past to simulate a provider that did not re-authenticate.
   */
  readonly authTime?: number;
}

/** Options for {@link startMockProvider}. */
export interface MockProviderOptions {
  readonly users?: readonly MockUser[];
  /** The registered callback URLs. */
  readonly redirectUris: readonly string[];
  readonly postLogoutRedirectUris?: readonly string[];
  /** Where the mock sends back-channel logout tokens. */
  readonly backchannelLogoutUri?: string;
  /** Default `test-app`. */
  readonly clientId?: string;
  /**
   * Behave like authentik 2026.8: no `iss` in the authorization response
   * and no `authorization_response_iss_parameter_supported` in discovery.
   */
  readonly authentikLike?: boolean;
  /** Default 0, a free port. */
  readonly port?: number;
}

/** Claims and header overrides for {@link MockProvider.logoutToken}. */
export interface LogoutTokenOverrides {
  readonly claims?: Readonly<Record<string, unknown>>;
  /** Claims to leave out, such as `["jti"]`. */
  readonly omit?: readonly string[];
  /** Sign with a fresh key the provider does not publish. */
  readonly foreignKey?: boolean;
  readonly typ?: string;
}

/** A running in-process OpenID provider, for tests and local development. */
export interface MockProvider {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  /** Adds or replaces a user. */
  setUser(user: MockUser): void;
  /** Sets how the next interactive sign-ins complete, until changed. */
  setLogin(login: MockLogin): void;
  /** Signs a back-channel logout token with the provider's key. */
  logoutToken(
    target: { readonly sub?: string; readonly sid?: string },
    overrides?: LogoutTokenOverrides,
  ): Promise<string>;
  /** Posts a logout token to the client's back-channel logout URI. */
  sendBackchannelLogout(token: string): Promise<Response>;
  close(): Promise<void>;
}

const SCOPE_CLAIMS = {
  // amr rides on openid so it reaches the ID token, as authentik sends it.
  openid: ["sub", "amr"],
  email: ["email", "email_verified"],
  profile: ["name", "preferred_username"],
  groups: ["groups"],
  roles: ["roles"],
  entitlements: ["roles"],
} as const;

async function listen(server: Server, port: number): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve());
  });
  return (server.address() as AddressInfo).port;
}

/**
 * Starts a mock OpenID provider on `127.0.0.1`, built on `oidc-provider`.
 *
 * Sign-ins complete without a page: the mock signs in whoever
 * {@link MockProvider.setLogin} names (by default the first user), with the
 * configured `amr` and `auth_time`. It honours `prompt=login` and `max_age`,
 * puts `auth_time`, `amr`, `sid` and the scope claims in the ID token, skips
 * consent, and supports RP-initiated and back-channel logout.
 */
export async function startMockProvider(
  options: MockProviderOptions,
): Promise<MockProvider> {
  const users = new Map<string, MockUser>();
  for (const user of options.users ?? []) users.set(user.sub, user);
  let login: MockLogin | undefined;
  const clientId = options.clientId ?? "test-app";
  const clientSecret = randomBytes(32).toString("base64url");

  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const kid = randomUUID();
  const signingJwk: JWK = {
    ...(await exportJWK(privateKey)),
    kid,
    alg: "RS256",
    use: "sig",
  };

  const server = createServer();
  const port = await listen(server, options.port ?? 0);
  const issuer = `http://127.0.0.1:${port}`;

  const configuration: Configuration = {
    clients: [
      {
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris: [...options.redirectUris],
        post_logout_redirect_uris: [...(options.postLogoutRedirectUris ?? [])],
        response_types: ["code"],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "client_secret_basic",
        require_auth_time: true,
        ...(options.backchannelLogoutUri
          ? {
              backchannel_logout_uri: options.backchannelLogoutUri,
              backchannel_logout_session_required: true,
            }
          : {}),
      },
    ],
    jwks: { keys: [signingJwk as never] },
    cookies: { keys: [randomBytes(32).toString("base64url")] },
    claims: {
      ...Object.fromEntries(
        Object.entries(SCOPE_CLAIMS).map(([scope, claims]) => [
          scope,
          [...claims],
        ]),
      ),
      acr: null,
      auth_time: null,
      sid: null,
    },
    scopes: Object.keys(SCOPE_CLAIMS),
    conformIdTokenClaims: false,
    pkce: { required: () => true },
    // The app under test listens on loopback, which oidc-provider's SSRF
    // guard refuses. Drop the guard for this test-only provider.
    fetch: (url, init) => {
      const { dispatcher: _dispatcher, ...rest } = (init ??
        {}) as RequestInit & {
        dispatcher?: unknown;
      };
      return fetch(url, rest);
    },
    features: {
      devInteractions: { enabled: false },
      backchannelLogout: { enabled: true },
      rpInitiatedLogout: { enabled: true },
    },
    interactions: {
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
    },
    async findAccount(_ctx, sub) {
      const user = users.get(sub);
      if (!user) return undefined;
      return {
        accountId: sub,
        async claims() {
          return {
            sub,
            ...(user.email === undefined
              ? {}
              : {
                  email: user.email,
                  email_verified: user.emailVerified ?? true,
                }),
            ...(user.name === undefined ? {} : { name: user.name }),
            ...(user.groups === undefined ? {} : { groups: [...user.groups] }),
            ...(user.roles === undefined ? {} : { roles: [...user.roles] }),
          };
        },
      };
    },
    // First-party test client: grant every requested scope without consent.
    async loadExistingGrant(ctx: KoaContextWithOIDC) {
      const session = ctx.oidc.session;
      const client = ctx.oidc.client;
      if (!session?.accountId || !client) return undefined;
      const existing = session.grantIdFor(client.clientId);
      if (existing) {
        const found = await ctx.oidc.provider.Grant.find(existing);
        if (found) return found;
      }
      const grant = new ctx.oidc.provider.Grant({
        clientId: client.clientId,
        accountId: session.accountId,
      });
      grant.addOIDCScope(Object.keys(SCOPE_CLAIMS).join(" "));
      await grant.save();
      return grant;
    },
  };

  const provider = new Provider(issuer, configuration);

  provider.use(async (ctx, next) => {
    const match = /^\/interaction\/([^/]+)$/.exec(ctx.path);
    if (!match || ctx.method !== "GET") {
      await next();
      if (options.authentikLike) {
        if (
          ctx.path === "/.well-known/openid-configuration" &&
          typeof ctx.body === "object" &&
          ctx.body !== null
        )
          delete (ctx.body as Record<string, unknown>)
            .authorization_response_iss_parameter_supported;
        const location = ctx.response.get("location");
        if (
          location &&
          options.redirectUris.some((uri) => location.startsWith(uri))
        ) {
          const url = new URL(location);
          url.searchParams.delete("iss");
          ctx.response.set("location", url.href);
        }
      }
      return;
    }
    const details = await provider.interactionDetails(ctx.req, ctx.res);
    if (details.prompt.name !== "login") {
      ctx.status = 400;
      ctx.body = `Unexpected prompt ${details.prompt.name}`;
      return;
    }
    const chosen =
      login ??
      (users.size > 0 ? { sub: [...users.keys()][0] ?? "" } : undefined);
    if (!chosen || !users.has(chosen.sub)) {
      ctx.status = 400;
      ctx.body = "No mock user is set to sign in.";
      return;
    }
    const redirectTo = await provider.interactionResult(ctx.req, ctx.res, {
      login: {
        accountId: chosen.sub,
        amr: [...(chosen.amr ?? ["mfa"])],
        ts: chosen.authTime ?? Math.floor(Date.now() / 1000),
      },
    });
    ctx.redirect(redirectTo);
  });

  const handle = provider.callback();
  server.on("request", (req, res) => {
    void handle(req, res);
  });

  return {
    issuer,
    clientId,
    clientSecret,
    setUser(user) {
      users.set(user.sub, user);
    },
    setLogin(next) {
      login = next;
    },
    async logoutToken(target, overrides = {}) {
      const key = overrides.foreignKey
        ? (await generateKeyPair("RS256")).privateKey
        : privateKey;
      const claims: Record<string, unknown> = {
        iss: issuer,
        aud: clientId,
        iat: Math.floor(Date.now() / 1000),
        jti: randomUUID(),
        events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
        ...(target.sub === undefined ? {} : { sub: target.sub }),
        ...(target.sid === undefined ? {} : { sid: target.sid }),
        ...overrides.claims,
      };
      for (const name of overrides.omit ?? []) delete claims[name];
      return new SignJWT(claims)
        .setProtectedHeader({
          alg: "RS256",
          kid,
          typ: overrides.typ ?? "logout+jwt",
        })
        .sign(key);
    },
    async sendBackchannelLogout(token) {
      if (!options.backchannelLogoutUri)
        throw new Error("startMockProvider was given no backchannelLogoutUri.");
      return fetch(options.backchannelLogoutUri, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ logout_token: token }),
      });
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
