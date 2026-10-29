// The auth API's JSON, exactly as @avgeek-oss/auth-core sends it. Times are
// ISO 8601 strings. The contract tests in examples/hono-vite keep these in
// step with the server.

/** The three roles, lowest first. */
export const ROLES = ["viewer", "member", "admin"] as const;

/** `viewer` < `member` < `admin`. */
export type Role = (typeof ROLES)[number];

/** True when `role` is `minimum` or higher. */
export function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLES.indexOf(role) >= ROLES.indexOf(minimum);
}

/** The signed-in person, as the app stores them. */
export interface SessionUser {
  /** The app's user id (a UUID). */
  readonly id: string;
  /** Their current role in the app. */
  readonly role: Role;
  /** Email from the identity provider: an attribute, never an identifier. */
  readonly email: string | null;
  /** Display name from the identity provider. */
  readonly displayName: string | null;
}

/**
 * The signed-in caller: `GET <basePath>/session`.
 *
 * @typeParam Ext - The app's own fields, from its `extendActor` hook.
 */
export interface AuthSession<Ext extends object = Record<string, unknown>> {
  readonly user: SessionUser;
  /** The role authorization checks use. */
  readonly role: Role;
  /** App-specific fields. */
  readonly ext: Ext;
  readonly session: {
    /** When the person last signed in at the identity provider. */
    readonly authenticatedAt: string;
    readonly expiresAt: string;
    /** Authentication methods the provider reported, such as `mfa`. */
    readonly amr: readonly string[];
  };
}

/** A personal API key, never with its secret. */
export interface ApiKey {
  readonly id: string;
  readonly name: string;
  /** The highest role the key acts with. */
  readonly ceiling: Role;
  /** The app-defined workspace it was issued for, or `null`. */
  readonly workspace: string | null;
  readonly createdAt: string;
  /** `null` for a key that never expires. */
  readonly expiresAt: string | null;
  readonly lastUsedAt: string | null;
  /** The key that replaced this one in a rotation, or `null`. */
  readonly replacedBy: string | null;
  /** Until when a rotated key still works, or `null`. */
  readonly graceUntil: string | null;
}

/** What {@link ApiKeysApi.create} takes. */
export interface CreateApiKeyInput {
  readonly name: string;
  readonly ceiling: Role;
  /** Only for apps that issue keys per workspace. */
  readonly workspace?: string | null;
  /** Lifetime in seconds; `null` asks for no expiry where the app allows it. */
  readonly expiresInSeconds?: number | null;
}

/** A new or rotated key: `key` is the secret, shown this once only. */
export interface IssuedApiKey {
  readonly key: string;
  readonly apiKey: ApiKey;
}

/** An MCP client (or other OAuth client) the person allowed to act for them. */
export interface ConnectedApp {
  /** The grant id. */
  readonly id: string;
  readonly clientId: string;
  readonly clientName: string;
  readonly logoUri: string | null;
  /** The highest role the app acts with. */
  readonly ceiling: Role;
  /** The resources (such as the MCP endpoint) it may call. */
  readonly resources: readonly string[];
  /** App-defined limits approved with it, or `null`. */
  readonly restrictions: Readonly<Record<string, unknown>> | null;
  readonly createdAt: string;
  readonly lastUsedAt: string | null;
}

/** A pending MCP authorization request, for the consent screen. */
export interface ConsentRequest {
  readonly client: {
    readonly id: string;
    readonly name: string;
    readonly logoUri: string | null;
    /** Registered by the operator, from a metadata document, or dynamic. */
    readonly kind: "configured" | "metadata" | "dynamic";
    readonly redirectUri: string;
    /** Where the code goes. Always show it. */
    readonly redirectHost: string;
    /** The redirect is to this computer: warn the person. */
    readonly localhost: boolean;
  };
  readonly resource: { readonly uri: string; readonly name: string | null };
  /** The role the client asked for, or `null`. */
  readonly scope: Role | null;
  /** The ceilings the person may choose, lowest first. */
  readonly ceilings: readonly Role[];
  readonly defaultCeiling: Role;
  readonly expiresAt: string;
}

/** What {@link ConsentApi.decide} takes. */
export interface ConsentDecisionInput {
  /** True to allow, false to deny. */
  readonly approve: boolean;
  /** The highest role to allow. Required to approve. */
  readonly ceiling?: Role;
  /** App-defined limits, for apps that validate them. */
  readonly restrictions?: Readonly<Record<string, unknown>>;
}

/** The API's answer to a consent decision. */
export interface ConsentDecision {
  /** Where to send the browser next: back to the client, with a code or an error. */
  readonly redirectUri: string;
}

/** The API's answer to sign-out. */
export interface SignOutResult {
  /** The identity provider's logout URL to visit next, or `null`. */
  readonly endSessionUrl: string | null;
}

/**
 * One of the signed-in person's browser sessions: `GET <basePath>/sessions`.
 * `id` is a public id, never the session's token.
 */
export interface ActiveSession {
  readonly id: string;
  readonly createdAt: string;
  /** The last request in this session, to within a minute. */
  readonly lastSeenAt: string;
  /** When it ends unless used before then. */
  readonly idleExpiresAt: string;
  /** When it ends however much it is used. */
  readonly expiresAt: string;
  /** When the person last authenticated at the provider in it. */
  readonly authenticatedAt: string;
  /** The browser family it signed in with, such as `Firefox`, or `null`. */
  readonly browser: string | null;
  /** The operating system it signed in on, such as `macOS`, or `null`. */
  readonly os: string | null;
  /** True for the session of the page asking. */
  readonly current: boolean;
}

/** The API's answer to signing out one session. */
export interface RevokeSessionResult extends SignOutResult {
  /**
   * True when it was the page's own session: the page is signed out, as
   * after `signOut`, and `endSessionUrl` is the provider's logout URL.
   * Otherwise `endSessionUrl` is `null`.
   */
  readonly current: boolean;
}

/** The API's answer to signing out everywhere. */
export interface SignOutEverywhereResult extends SignOutResult {
  /** How many sessions ended, the page's own included. */
  readonly revoked: number;
}

/** The signed-in person's browser sessions. */
export interface SessionsApi {
  /** Their live sessions, newest first, with the page's own marked `current`. */
  readonly list: () => Promise<ActiveSession[]>;
  /**
   * Signs out one of their sessions. Someone else's, or one that already
   * ended, rejects with `not_found`.
   */
  readonly revoke: (id: string) => Promise<RevokeSessionResult>;
  /** Signs out every one of their sessions, this page's included. */
  readonly signOutEverywhere: () => Promise<SignOutEverywhereResult>;
}

/**
 * Where a person stands in the app: `active`; `suspended` (no role, so
 * sign-in and their credentials are refused until the provider gives one
 * back); `deactivated` (inactive at the provider); or `deleted` (removed by
 * the provider).
 */
export type UserStatus = "active" | "suspended" | "deactivated" | "deleted";

/**
 * Where a person's role came from: the role claim at sign-in (`claims`),
 * SCIM group membership (`scim`), or the app itself (`app`).
 */
export type RoleSource = "claims" | "scim" | "app";

/** A person in the app's directory: `GET <basePath>/admin/users`. */
export interface DirectoryUser {
  /** The app's user id (a UUID). */
  readonly id: string;
  readonly displayName: string | null;
  /** An attribute, never an identifier. */
  readonly email: string | null;
  /** `null` while the person has no access. */
  readonly role: Role | null;
  /** `null` until something sets the role. */
  readonly roleSource: RoleSource | null;
  readonly status: UserStatus;
  readonly createdAt: string;
  /** Their last sign-in, or `null` if they never signed in. */
  readonly lastSignInAt: string | null;
  readonly deactivatedAt: string | null;
  readonly deletedAt: string | null;
}

/** What {@link AdminApi.users} `list` takes. Every field is optional. */
export interface ListUsersInput {
  /** The previous page's `nextCursor`; leave out for the first page. */
  readonly cursor?: string | null;
  /** Part of a name or email, ignoring case. */
  readonly q?: string | null;
  /** Only people in this state. */
  readonly status?: UserStatus | null;
  /** People per page, 1 to 100. Default 50. */
  readonly limit?: number;
}

/** A page of the directory. */
export interface UserPage {
  /** Newest first. */
  readonly users: DirectoryUser[];
  /** Pass as `cursor` for the next page; `null` on the last one. */
  readonly nextCursor: string | null;
}

/** API key management for the signed-in person. */
export interface ApiKeysApi {
  /** Their keys, newest first. */
  readonly list: () => Promise<ApiKey[]>;
  /** Issues a key. The secret is in the result only. */
  readonly create: (input: CreateApiKeyInput) => Promise<IssuedApiKey>;
  /**
   * Replaces a key with a new one. The old key keeps working for
   * `graceSeconds` (default 0).
   */
  readonly rotate: (
    id: string,
    options?: { readonly graceSeconds?: number },
  ) => Promise<IssuedApiKey>;
  /** Revokes one of their keys. */
  readonly revoke: (id: string) => Promise<void>;
}

/** The MCP clients the signed-in person connected. */
export interface ConnectedAppsApi {
  readonly list: () => Promise<ConnectedApp[]>;
  /** Disconnects an app: revokes its grant and every token. */
  readonly revoke: (id: string) => Promise<void>;
}

/** The consent screen's API. */
export interface ConsentApi {
  /** The request with the id from the page's `?request=`. */
  readonly get: (id: string) => Promise<ConsentRequest>;
  /** Allows or denies it. Navigate to `redirectUri` afterwards. */
  readonly decide: (
    id: string,
    input: ConsentDecisionInput,
  ) => Promise<ConsentDecision>;
}

/**
 * Admin-only views of other people's credentials, and the directory of
 * everyone the app knows. Read-only for people: roles and access are
 * managed at the identity provider.
 */
export interface AdminApi {
  readonly apiKeys: {
    readonly list: (userId: string) => Promise<ApiKey[]>;
    readonly revoke: (id: string) => Promise<void>;
  };
  readonly connectedApps: {
    readonly list: (userId: string) => Promise<ConnectedApp[]>;
    readonly revoke: (id: string) => Promise<void>;
  };
  readonly users: {
    /** One page of the directory, newest first. */
    readonly list: (input?: ListUsersInput) => Promise<UserPage>;
  };
}
