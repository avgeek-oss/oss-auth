import type { AuditActor, ChangeSource, SignInDeniedReason } from "../audit.js";
import type { AuthConfig } from "../config.js";
import { quoteIdent } from "../identifiers.js";
import { insertAuditEvent } from "../postgres/audit.js";
import type { SqlQueryable } from "../postgres/sql.js";
import { resolveRole, type Role } from "../roles.js";

/** Where a user's role came from. Stored in `users.role_source`. */
export type RoleSource =
  "none" | "oidc" | "bootstrap" | "scim" | "admin" | "operator";

/** A row of the `users` table, as auth-core reads it. */
export interface UserRecord {
  readonly id: string;
  readonly iss: string;
  readonly sub: string | null;
  readonly email: string | null;
  readonly displayName: string | null;
  readonly role: Role;
  readonly roleSource: RoleSource;
  readonly active: boolean;
  readonly deletedAt: Date | null;
}

/** The outcome of {@link signInUser}. */
export type SignInOutcome =
  | {
      readonly kind: "allowed";
      readonly user: UserRecord;
      readonly created: boolean;
    }
  | {
      readonly kind: "denied";
      readonly reason: SignInDeniedReason;
      readonly userId: string | null;
    };

const COLUMNS = `id, iss, sub, email, display_name AS "displayName", role,
  role_source AS "roleSource", active, deleted_at AS "deletedAt"`;

function stringClaim(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "") return null;
  return Array.from(trimmed).slice(0, max).join("");
}

function bootstrapMatches(
  config: AuthConfig,
  claims: Readonly<Record<string, unknown>>,
): boolean {
  const bootstrap = config.bootstrapAdmin;
  if (bootstrap === null) return false;
  if (bootstrap.kind === "sub") return claims.sub === bootstrap.value;
  return (
    claims.email_verified === true &&
    typeof claims.email === "string" &&
    claims.email.trim().toLowerCase() === bootstrap.value
  );
}

/**
 * Maps validated ID token claims to a user, inside the caller's transaction,
 * and records what changed in the audit log.
 *
 * - The user is found by `(iss, sub)` and created on first sign-in. Email
 *   and display name are refreshed from the claims every time.
 * - A deleted or deactivated user is refused.
 * - The role comes from {@link resolveRole}. `"none"` refuses the sign-in.
 *   `null` (the claim is missing) keeps a returning user's role; a new user
 *   is refused unless they are the bootstrap admin.
 * - The bootstrap admin (`<APP>_BOOTSTRAP_ADMIN`) becomes `admin` while the
 *   role claim is missing and SCIM has not set their role.
 *
 * A refusal is returned, not thrown, so the caller can commit its audit
 * event.
 */
export async function signInUser(
  tx: SqlQueryable,
  config: AuthConfig,
  claims: Readonly<Record<string, unknown>> & { iss: string; sub: string },
): Promise<SignInOutcome> {
  const users = `${quoteIdent(config.schema)}.users`;
  const schema = { schema: config.schema };
  const idp: AuditActor = { type: "idp", issuer: claims.iss };
  const email = stringClaim(claims.email, 320);
  const displayName =
    stringClaim(claims.name, 256) ??
    stringClaim(claims.preferred_username, 256);
  const resolved = resolveRole(claims, config.oidc.roleMap);
  const bootstrap = bootstrapMatches(config, claims);

  const deny = async (
    reason: SignInDeniedReason,
    userId: string | null,
  ): Promise<SignInOutcome> => {
    await insertAuditEvent(
      tx,
      {
        type: "sign_in.denied",
        actor: idp,
        subjectUserId: userId,
        data: { reason },
      },
      schema,
    );
    return { kind: "denied", reason, userId };
  };

  const select = async () =>
    (
      await tx.query<UserRecord>(
        `SELECT ${COLUMNS} FROM ${users} WHERE iss = $1 AND sub = $2 FOR UPDATE`,
        [claims.iss, claims.sub],
      )
    )[0];

  let existing = await select();
  if (existing === undefined) {
    let role: Role;
    let source: RoleSource;
    if (resolved === "none") return deny("no_role", null);
    if (resolved !== null) {
      role = resolved;
      source = "oidc";
    } else if (bootstrap) {
      role = "admin";
      source = "bootstrap";
    } else return deny("no_role", null);
    const [created] = await tx.query<UserRecord>(
      `INSERT INTO ${users} (iss, sub, email, display_name, role, role_source)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT ON CONSTRAINT users_iss_sub_key DO NOTHING
       RETURNING ${COLUMNS}`,
      [claims.iss, claims.sub, email, displayName, role, source],
    );
    if (created !== undefined) {
      await insertAuditEvent(
        tx,
        {
          type: "user.created",
          actor: idp,
          subjectUserId: created.id,
          data: { source: source === "bootstrap" ? "bootstrap" : "oidc" },
        },
        schema,
      );
      return { kind: "allowed", user: created, created: true };
    }
    // Another sign-in created the user first; continue as a returning user.
    existing = await select();
    if (existing === undefined)
      throw new Error("The user vanished during sign-in.");
  }

  if (existing.deletedAt !== null) return deny("user_deleted", existing.id);
  if (!existing.active) return deny("user_inactive", existing.id);
  if (resolved === "none") return deny("no_role", existing.id);

  let role = existing.role;
  let source = existing.roleSource;
  if (resolved !== null) {
    role = resolved;
    source = "oidc";
  } else if (bootstrap && existing.roleSource !== "scim") {
    role = "admin";
    source = "bootstrap";
  }

  const fields: string[] = [];
  if (email !== existing.email) fields.push("email");
  if (displayName !== existing.displayName) fields.push("display_name");
  if (
    fields.length === 0 &&
    role === existing.role &&
    source === existing.roleSource
  )
    return { kind: "allowed", user: existing, created: false };

  const [updated] = await tx.query<UserRecord>(
    `UPDATE ${users} SET email = $2, display_name = $3, role = $4, role_source = $5
     WHERE id = $1 RETURNING ${COLUMNS}`,
    [existing.id, email, displayName, role, source],
  );
  if (updated === undefined)
    throw new Error("The user vanished during sign-in.");
  const changeSource: ChangeSource =
    source === "bootstrap" ? "bootstrap" : "oidc";
  if (fields.length > 0)
    await insertAuditEvent(
      tx,
      {
        type: "user.updated",
        actor: idp,
        subjectUserId: existing.id,
        data: { source: "oidc", fields },
      },
      schema,
    );
  if (role !== existing.role)
    await insertAuditEvent(
      tx,
      {
        type: "user.role_changed",
        actor: idp,
        subjectUserId: existing.id,
        data: { source: changeSource, from: existing.role, to: role },
      },
      schema,
    );
  return { kind: "allowed", user: updated, created: false };
}
