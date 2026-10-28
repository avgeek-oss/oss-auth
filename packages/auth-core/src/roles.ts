/**
 * The three roles every app uses, lowest first. OAuth scope strings are the
 * same names.
 */
export const ROLES = ["viewer", "member", "admin"] as const;

/** A person's role in an app: `viewer` < `member` < `admin`. */
export type Role = (typeof ROLES)[number];

/** True when `value` is one of {@link ROLES}. */
export function isRole(value: unknown): value is Role {
  return (
    typeof value === "string" && (ROLES as readonly string[]).includes(value)
  );
}

/** The role's position in {@link ROLES}: 0 for `viewer`, 2 for `admin`. */
export function roleRank(role: Role): number {
  const rank = ROLES.indexOf(role);
  if (rank === -1) throw new TypeError(`Unknown role: ${String(role)}`);
  return rank;
}

/** True when `role` grants at least what `minimum` grants. */
export function roleAtLeast(role: Role, minimum: Role): boolean {
  return roleRank(role) >= roleRank(minimum);
}

/**
 * The lower of two roles. A credential's effective role is
 * `minRole(ceiling, userRole)`, so a key never outranks its owner's current
 * role.
 */
export function minRole(a: Role, b: Role): Role {
  return roleRank(a) <= roleRank(b) ? a : b;
}

/** The higher of two roles. */
export function maxRole(a: Role, b: Role): Role {
  return roleRank(a) >= roleRank(b) ? a : b;
}

/**
 * How identity-provider claims map to roles. Each listed claim may be a
 * string or an array of strings, such as `groups: ["posted-admins"]` or
 * authentik's `roles: ["admin"]`.
 */
export interface RoleMap {
  /** Claim names to read, such as `["roles"]` or `["groups"]`. */
  readonly claims: readonly string[];
  /** Claim value to role, such as `{ "posted-admins": "admin" }`. */
  readonly values: Readonly<Record<string, Role>>;
}

/**
 * The outcome of {@link resolveRole}:
 * - a {@link Role}: the highest role any claim value maps to;
 * - `"none"`: the claims are present but no value maps to a role, so the
 *   provider says this person has no role in the app;
 * - `null`: none of the claims is present (or none is a string or string
 *   array), so the role is unknown and the app keeps the current one.
 */
export type ResolvedRole = Role | "none" | null;

/**
 * Resolves a role from ID token or userinfo claims.
 *
 * A missing claim means "unknown", not "no role": providers drop group
 * claims on overage (Entra) or never send them (Google), and treating that as
 * a demotion would lock people out. Removal is signalled through SCIM
 * instead. When several values match, the highest role wins.
 */
export function resolveRole(
  claims: Readonly<Record<string, unknown>>,
  roleMap: RoleMap,
): ResolvedRole {
  let present = false;
  let best: Role | null = null;
  for (const name of roleMap.claims) {
    if (!Object.hasOwn(claims, name)) continue;
    const value = claims[name];
    const entries =
      typeof value === "string" ? [value] : Array.isArray(value) ? value : null;
    if (entries === null) continue;
    present = true;
    for (const entry of entries) {
      if (typeof entry !== "string" || !Object.hasOwn(roleMap.values, entry))
        continue;
      const role = roleMap.values[entry];
      if (!isRole(role)) continue;
      best = best === null ? role : maxRole(best, role);
    }
  }
  if (best !== null) return best;
  return present ? "none" : null;
}
