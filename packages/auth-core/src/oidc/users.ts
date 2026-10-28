import type { AuthConfig } from "../config.js";
import { quoteIdent } from "../identifiers.js";
import type { SqlQueryable } from "../postgres/sql.js";
import { resolveRole, type Role } from "../roles.js";

/**
 * Where a user's role was last set, including to `null`. Stored in
 * `users.role_source`; `null` until something sets the role.
 */
export type RoleSource = "oidc" | "scim" | "admin";

/** Why an OIDC sign-in was refused after the provider authenticated it. */
export type SignInDeniedReason =
  "no_role" | "unassigned" | "user_inactive" | "user_deleted";

/** A row of the `users` table, as auth-core reads it. */
export interface UserRecord {
  readonly id: string;
  readonly iss: string;
  readonly sub: string | null;
  readonly email: string | null;
  readonly displayName: string | null;
  /** `null` while the person has no access. */
  readonly role: Role | null;
  readonly roleSource: RoleSource | null;
  readonly active: boolean;
  readonly deletedAt: Date | null;
}

/** The outcome of {@link signInUser}. */
export type SignInOutcome =
  | {
      readonly kind: "allowed";
      readonly user: UserRecord & { readonly role: Role };
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

/**
 * Maps validated ID token claims to a user, inside the caller's transaction.
 *
 * - The user is found by `(iss, sub)`. With
 *   `<APP>_SCIM_EXTERNAL_ID_IS_SUBJECT=true`, a user SCIM created (no `sub`
 *   yet) is linked on first sign-in by `iss` and `external_id = sub`. Users
 *   are never linked by email.
 * - A deleted or deactivated user is refused, and `"none"` from
 *   {@link resolveRole} always refuses.
 * - With `<APP>_ROLE_SOURCE=claims` (the default), the role claim sets the
 *   role, and `"none"` sets it to `null` (no access). A missing claim keeps
 *   the role of a user who has one, and refuses a user without one: a role
 *   only ever comes from the provider.
 * - With `<APP>_ROLE_SOURCE=scim`, SCIM group membership sets the role and
 *   sign-in never changes it or creates users: a person SCIM has not
 *   provisioned and assigned is refused as `unassigned`.
 * - Email and display name are refreshed from the claims every time.
 *
 * A refusal is returned, not thrown, so the caller decides how to answer.
 */
export async function signInUser(
  tx: SqlQueryable,
  config: AuthConfig,
  claims: Readonly<Record<string, unknown>> & { iss: string; sub: string },
): Promise<SignInOutcome> {
  const users = `${quoteIdent(config.schema)}.users`;
  const email = stringClaim(claims.email, 320);
  const displayName =
    stringClaim(claims.name, 256) ??
    stringClaim(claims.preferred_username, 256);
  const resolved = resolveRole(claims, config.oidc.roleMap);
  const scimRoles = config.roleSource === "scim";

  const deny = (
    reason: SignInDeniedReason,
    userId: string | null,
  ): SignInOutcome => ({ kind: "denied", reason, userId });

  const select = async () =>
    (
      await tx.query<UserRecord>(
        `SELECT ${COLUMNS} FROM ${users} WHERE iss = $1 AND sub = $2 FOR UPDATE`,
        [claims.iss, claims.sub],
      )
    )[0];

  // A SCIM-provisioned user whose externalId is this subject. Tombstones
  // are found too, so a deleted user is refused rather than recreated.
  const selectProvisioned = async () =>
    config.scim.externalIdIsSubject
      ? (
          await tx.query<UserRecord>(
            `SELECT ${COLUMNS} FROM ${users}
             WHERE iss = $1 AND sub IS NULL AND external_id = $2 FOR UPDATE`,
            [claims.iss, claims.sub],
          )
        )[0]
      : undefined;

  let existing = await select();
  let linked = false;
  if (existing === undefined) {
    existing = await selectProvisioned();
    linked = existing !== undefined;
  }
  if (existing === undefined) {
    if (scimRoles) return deny("unassigned", null);
    if (resolved === null || resolved === "none") return deny("no_role", null);
    const role: Role = resolved;
    const source: RoleSource = "oidc";
    const [created] = await tx.query<UserRecord>(
      `INSERT INTO ${users} (iss, sub, email, display_name, role, role_source)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT ON CONSTRAINT users_iss_sub_key DO NOTHING
       RETURNING ${COLUMNS}`,
      [claims.iss, claims.sub, email, displayName, role, source],
    );
    if (created !== undefined)
      return hasRole(created)
        ? { kind: "allowed", user: created, created: true }
        : deny("no_role", created.id);
    // Another sign-in created the user first; continue as a returning user.
    existing = await select();
    if (existing === undefined)
      throw new Error("The user vanished during sign-in.");
  }

  if (existing.deletedAt !== null) return deny("user_deleted", existing.id);
  if (!existing.active) return deny("user_inactive", existing.id);

  let role = existing.role;
  let source = existing.roleSource;
  if (scimRoles) {
    if (resolved === "none") return deny("no_role", existing.id);
    if (existing.roleSource !== "scim" || existing.role === null)
      return deny("unassigned", existing.id);
  } else if (resolved === "none") {
    // The provider says this person has no role: record it, then refuse.
    role = null;
    source = "oidc";
  } else if (resolved !== null) {
    role = resolved;
    source = "oidc";
  } else if (existing.role === null) {
    // No role and no claim to give one: treat like a new user.
    return deny("no_role", existing.id);
  }

  let user = existing;
  if (
    linked ||
    email !== existing.email ||
    displayName !== existing.displayName ||
    role !== existing.role ||
    source !== existing.roleSource
  ) {
    const [updated] = await tx.query<UserRecord>(
      `UPDATE ${users} SET sub = $6, email = coalesce($2, email),
         display_name = coalesce($3, display_name), role = $4, role_source = $5
       WHERE id = $1 RETURNING ${COLUMNS}`,
      [existing.id, email, displayName, role, source, claims.sub],
    );
    if (updated === undefined)
      throw new Error("The user vanished during sign-in.");
    user = updated;
  }
  return hasRole(user)
    ? { kind: "allowed", user, created: false }
    : deny("no_role", user.id);
}

function hasRole(user: UserRecord): user is UserRecord & { role: Role } {
  return user.role !== null;
}
