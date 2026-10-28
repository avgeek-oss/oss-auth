import { minRole, type Role } from "./roles.js";

/**
 * How a request authenticated:
 * - `session`: a browser session cookie, after an OIDC sign-in;
 * - `api_key`: a personal API key;
 * - `oauth`: an access token from the app's MCP authorization server.
 */
export type CredentialKind = "session" | "api_key" | "oauth";

/** The person behind a request, as stored in the `users` table. */
export interface ActorUser {
  /** The app's own user id (a UUID). */
  readonly id: string;
  /** The person's current role in the app. */
  readonly role: Role;
  /** Email from the identity provider. An attribute, never an identifier. */
  readonly email: string | null;
  /** Display name from the identity provider. */
  readonly displayName: string | null;
}

/** The credential a request presented. */
export interface ActorCredential {
  readonly kind: CredentialKind;
  /**
   * The credential's id: the API key id, the OAuth grant id, or for a session
   * the stored hash of its token. Never the token itself.
   */
  readonly id: string;
  /**
   * The highest role this credential may act with, or `null` for none (a
   * session acts with the user's full role).
   */
  readonly ceiling: Role | null;
  /**
   * The app-defined workspace an API key (or OAuth grant) was issued for,
   * or `null`. auth-core stores it and never interprets it: the app must
   * enforce it.
   */
  readonly workspace: string | null;
  /**
   * App-defined limits an OAuth grant was approved with, such as the boards
   * it may touch, or `null`. auth-core stores them and never interprets
   * them: the app must enforce them.
   */
  readonly restrictions: Readonly<Record<string, unknown>> | null;
}

/**
 * An authenticated caller. `role` is what authorization checks use: the
 * lower of the credential's ceiling and the user's current role.
 *
 * @typeParam Ext - App-specific fields, such as a workspace id or the boards
 *   an OAuth grant is restricted to.
 */
export interface Actor<Ext extends object = Record<never, never>> {
  readonly user: ActorUser;
  readonly credential: ActorCredential;
  /** The effective role: `min(ceiling, user.role)`. */
  readonly role: Role;
  /** App-specific fields. auth-core never reads them. */
  readonly ext: Ext;
}

/**
 * The role a credential acts with: its ceiling, capped by the user's current
 * role. A demoted user's keys drop with them without being rewritten.
 */
export function effectiveRole(userRole: Role, ceiling: Role | null): Role {
  return ceiling === null ? userRole : minRole(ceiling, userRole);
}

/** Builds an {@link Actor}, computing its effective role. */
export function createActor<Ext extends object = Record<never, never>>(input: {
  user: ActorUser;
  credential: ActorCredential;
  ext?: Ext;
}): Actor<Ext> {
  return {
    user: input.user,
    credential: input.credential,
    role: effectiveRole(input.user.role, input.credential.ceiling),
    ext: input.ext ?? ({} as Ext),
  };
}
