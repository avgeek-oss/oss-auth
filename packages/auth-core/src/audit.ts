import type { Actor, CredentialKind } from "./actor.js";
import type { Role } from "./roles.js";

/**
 * Who caused an audit event:
 * - `user`: a signed-in person, with the credential they used;
 * - `idp`: the identity provider, through SCIM or back-channel logout;
 * - `operator`: someone at the server, through the break-glass CLI;
 * - `system`: auth-core itself, such as an expiry sweep.
 */
export type AuditActor =
  | {
      readonly type: "user";
      readonly userId: string;
      readonly credential: {
        readonly kind: CredentialKind;
        readonly id: string;
      } | null;
    }
  | { readonly type: "idp"; readonly issuer: string }
  | { readonly type: "operator" }
  | { readonly type: "system" };

/** Which channel changed a user record. */
export type ChangeSource = "oidc" | "bootstrap" | "scim" | "admin" | "operator";

/**
 * Why a session ended before its expiry. `replaced` means a new sign-in in
 * the same browser superseded it.
 */
export type SessionRevokeReason =
  | "sign_out"
  | "sign_out_everywhere"
  | "replaced"
  | "idp_logout"
  | "user_deactivated"
  | "admin"
  | "operator";

/** Why an OIDC sign-in was refused after the provider authenticated it. */
export type SignInDeniedReason =
  "no_role" | "user_inactive" | "user_deleted" | "unknown_user";

/** Request details recorded with an event, when there was a request. */
export interface AuditContext {
  /** The client address, as resolved by the app's trusted-proxy rules. */
  readonly ip: string | null;
  readonly userAgent: string | null;
}

interface EventOf<Type extends string, Data, Subject = string> {
  readonly type: Type;
  readonly actor: AuditActor;
  /** The user the event is about. */
  readonly subjectUserId: Subject;
  readonly data: Data;
  /** Defaults to the database's `now()`. */
  readonly occurredAt?: Date;
  readonly context?: AuditContext;
}

/**
 * Every event auth-core records. Each later feature adds its own members;
 * existing members never change shape.
 */
export type AuditEvent =
  | EventOf<"user.created", { readonly source: ChangeSource }>
  | EventOf<
      "user.updated",
      { readonly source: ChangeSource; readonly fields: readonly string[] }
    >
  | EventOf<
      "user.role_changed",
      { readonly source: ChangeSource; readonly from: Role; readonly to: Role }
    >
  | EventOf<"user.deactivated", { readonly source: ChangeSource }>
  | EventOf<"user.reactivated", { readonly source: ChangeSource }>
  | EventOf<"user.deleted", { readonly source: ChangeSource }>
  | EventOf<"session.created", { readonly amr: readonly string[] }>
  | EventOf<"session.revoked", { readonly reason: SessionRevokeReason }>
  | EventOf<"session.reauthenticated", { readonly amr: readonly string[] }>
  | EventOf<
      "sign_in.denied",
      { readonly reason: SignInDeniedReason },
      string | null
    >;

/** The `type` of an {@link AuditEvent}. */
export type AuditEventType = AuditEvent["type"];

/** Every {@link AuditEventType}, for validation and exhaustive handling. */
export const AUDIT_EVENT_TYPES = [
  "user.created",
  "user.updated",
  "user.role_changed",
  "user.deactivated",
  "user.reactivated",
  "user.deleted",
  "session.created",
  "session.revoked",
  "session.reauthenticated",
  "sign_in.denied",
] as const satisfies readonly AuditEventType[];

/** The {@link AuditActor} for a request made by `actor`. */
export function auditActor(actor: Actor<object>): AuditActor {
  return {
    type: "user",
    userId: actor.user.id,
    credential: { kind: actor.credential.kind, id: actor.credential.id },
  };
}
