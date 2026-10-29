// The people directory behind GET /auth/admin/users: every user the app
// knows, newest first, a page at a time. Read-only: roles and access are
// managed at the identity provider.

import type { AuthConfig } from "../config.js";
import { AuthRequestError } from "../errors.js";
import { quoteIdent } from "../identifiers.js";
import type { RoleSource } from "../oidc/users.js";
import type { SqlQueryable } from "../postgres/sql.js";
import type { Role } from "../roles.js";

/**
 * Where a person stands in the app, most final first: `deleted` (a SCIM
 * tombstone), `deactivated` (SCIM `active: false`), `suspended` (no role,
 * or with `<APP>_ROLE_SOURCE=scim` a role that did not come from SCIM, so
 * sign-in and their credentials are refused), or `active`.
 */
export type DirectoryStatus =
  "active" | "suspended" | "deactivated" | "deleted";

/** The statuses, for validating the `status` filter. */
export const DIRECTORY_STATUSES: readonly DirectoryStatus[] = [
  "active",
  "suspended",
  "deactivated",
  "deleted",
];

/**
 * Where the role came from, in `<APP>_ROLE_SOURCE`'s words: `claims` (the
 * role claim at sign-in), `scim` (SCIM group membership) or `app` (set by
 * the app itself). `null` until something sets it.
 */
export type DirectoryRoleSource = "claims" | "scim" | "app";

/** One person in the directory, as the route sends them. */
export interface DirectoryUser {
  readonly id: string;
  readonly displayName: string | null;
  readonly email: string | null;
  /** `null` while the person has no access. */
  readonly role: Role | null;
  readonly roleSource: DirectoryRoleSource | null;
  readonly status: DirectoryStatus;
  readonly createdAt: string;
  /** The last sign-in that created a session, or `null` if never. */
  readonly lastSignInAt: string | null;
  readonly deactivatedAt: string | null;
  readonly deletedAt: string | null;
}

/** A page of the directory. */
export interface DirectoryPage {
  readonly users: DirectoryUser[];
  /** Pass as `cursor` for the next page; `null` on the last one. */
  readonly nextCursor: string | null;
}

/** What a directory query takes, already validated. */
export interface DirectoryQuery {
  /** A substring of the name or email, case-insensitive, or `null`. */
  readonly q: string | null;
  readonly status: DirectoryStatus | null;
  /** From the previous page's `nextCursor`, or `null` for the first page. */
  readonly cursor: string | null;
  readonly limit: number;
}

/** The default and largest page sizes. */
export const DIRECTORY_PAGE = { default: 50, max: 100 } as const;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Microseconds, so the cursor is exactly the stored timestamp.
const CURSOR_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

const ROLE_SOURCES: Readonly<Record<RoleSource, DirectoryRoleSource>> = {
  oidc: "claims",
  scim: "scim",
  admin: "app",
};

const invalid = (message: string, reason: string) =>
  new AuthRequestError("invalid_request", message, { reason });

/**
 * The directory query in a request's parameters, or an `invalid_request`
 * naming the parameter (`q`, `status`, `limit` or `cursor`).
 */
export function parseDirectoryQuery(params: {
  readonly q?: string | undefined;
  readonly status?: string | undefined;
  readonly cursor?: string | undefined;
  readonly limit?: string | undefined;
}): DirectoryQuery {
  const q = params.q?.trim() ?? "";
  if (q.length > 200) throw invalid("q must be at most 200 characters.", "q");
  const status = params.status ?? "";
  if (status !== "" && !(DIRECTORY_STATUSES as string[]).includes(status))
    throw invalid(
      "status must be active, suspended, deactivated or deleted.",
      "status",
    );
  let limit: number = DIRECTORY_PAGE.default;
  if (params.limit !== undefined) {
    limit = /^\d{1,3}$/.test(params.limit) ? Number(params.limit) : 0;
    if (limit < 1 || limit > DIRECTORY_PAGE.max)
      throw invalid(
        `limit must be a whole number from 1 to ${DIRECTORY_PAGE.max}.`,
        "limit",
      );
  }
  const cursor = params.cursor ?? "";
  if (cursor !== "") decodeCursor(cursor);
  return {
    q: q === "" ? null : q,
    status: status === "" ? null : (status as DirectoryStatus),
    cursor: cursor === "" ? null : cursor,
    limit,
  };
}

function encodeCursor(at: string, id: string): string {
  return Buffer.from(JSON.stringify([at, id])).toString("base64url");
}

function decodeCursor(cursor: string): { at: string; id: string } {
  let value: unknown;
  try {
    value = /^[A-Za-z0-9_-]{1,200}$/.test(cursor)
      ? JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"))
      : null;
  } catch {
    value = null;
  }
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    typeof value[0] !== "string" ||
    typeof value[1] !== "string" ||
    !CURSOR_TIME.test(value[0]) ||
    !UUID.test(value[1])
  )
    throw invalid("The cursor is not one this API returned.", "cursor");
  return { at: value[0], id: value[1] };
}

interface Row {
  id: string;
  displayName: string | null;
  email: string | null;
  role: Role | null;
  roleSource: RoleSource | null;
  status: DirectoryStatus;
  createdAt: Date;
  lastSignInAt: Date | null;
  deactivatedAt: Date | null;
  deletedAt: Date | null;
  cursorAt: string;
}

/** One page of the directory, newest first. */
export async function listDirectory(
  sql: SqlQueryable,
  config: AuthConfig,
  query: DirectoryQuery,
): Promise<DirectoryPage> {
  const users = `${quoteIdent(config.schema)}.users`;
  const after = query.cursor === null ? null : decodeCursor(query.cursor);
  // The same rule as session lookup: in scim mode, a role from anywhere
  // else is not honoured.
  const status = `CASE
    WHEN deleted_at IS NOT NULL THEN 'deleted'
    WHEN NOT active THEN 'deactivated'
    WHEN role IS NULL OR ($1::boolean AND role_source IS DISTINCT FROM 'scim') THEN 'suspended'
    ELSE 'active' END`;
  const rows = await sql.query<Row>(
    `SELECT id, display_name AS "displayName", email, role,
            role_source AS "roleSource", ${status} AS "status",
            created_at AS "createdAt", last_sign_in_at AS "lastSignInAt",
            deactivated_at AS "deactivatedAt", deleted_at AS "deletedAt",
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "cursorAt"
     FROM ${users}
     WHERE ($2::text IS NULL
            OR strpos(lower(coalesce(display_name, '')), lower($2)) > 0
            OR strpos(lower(coalesce(email, '')), lower($2)) > 0)
       AND ($3::text IS NULL OR ${status} = $3)
       AND ($4::timestamptz IS NULL OR (created_at, id) < ($4::timestamptz, $5::uuid))
     ORDER BY created_at DESC, id DESC
     LIMIT $6`,
    [
      config.roleSource === "scim",
      query.q,
      query.status,
      after?.at ?? null,
      after?.id ?? null,
      query.limit + 1,
    ],
  );
  const page = rows.slice(0, query.limit);
  const last = page.at(-1);
  return {
    users: page.map((row) => ({
      id: row.id,
      displayName: row.displayName,
      email: row.email,
      role: row.role,
      roleSource: row.roleSource === null ? null : ROLE_SOURCES[row.roleSource],
      status: row.status,
      createdAt: row.createdAt.toISOString(),
      lastSignInAt: row.lastSignInAt?.toISOString() ?? null,
      deactivatedAt: row.deactivatedAt?.toISOString() ?? null,
      deletedAt: row.deletedAt?.toISOString() ?? null,
    })),
    nextCursor:
      rows.length > query.limit && last
        ? encodeCursor(last.cursorAt, last.id)
        : null,
  };
}
