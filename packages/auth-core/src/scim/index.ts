import { Hono, type Context } from "hono";
import type { AuthConfig } from "../config.js";
import { AuthConfigError } from "../errors.js";
import { quoteIdent } from "../identifiers.js";
import { deriveKey } from "../keys.js";
import type { Sql, SqlQueryable } from "../postgres/sql.js";
import { maxRole, type Role } from "../roles.js";
import { createSessions, type Sessions } from "../sessions/index.js";
import { constantTimeEqual, hashToken } from "../tokens.js";
import { applyProjection, projection } from "./attributes.js";
import {
  MAX_RESULTS,
  resourceTypes,
  SCHEMAS,
  schemas,
  serviceProviderConfig,
} from "./discovery.js";
import { badRequest, conflict, notFound, ScimError } from "./errors.js";
import { parseFilter, type FilterCondition } from "./filter.js";
import {
  groupChange,
  groupResource,
  patchGroup,
  type ScimGroupChange,
  type ScimGroupRow,
} from "./groups.js";
import { parsePatch } from "./patch.js";
import {
  patchUser,
  USER_COLUMNS,
  userFields,
  userResource,
  type ScimUserFields,
  type ScimUserRow,
} from "./users.js";

export { ScimError, type ScimType } from "./errors.js";
export { parseFilter, type FilterCondition } from "./filter.js";
export { SCHEMAS as SCIM_SCHEMAS } from "./discovery.js";

/** Callbacks that run inside the SCIM change's transaction. */
export interface ScimHooks {
  /**
   * A user was deactivated or deleted. Their sessions are already revoked;
   * revoke anything else they hold here, such as API keys or OAuth grants.
   */
  readonly onDeactivate?: (
    userId: string,
    tx: SqlQueryable,
  ) => Promise<void> | void;
  /**
   * With `<APP>_ROLE_SOURCE=scim`, a user's role changed because their
   * groups changed. `null` means no role: the user lost access and their
   * sessions are already revoked. Revoke credentials above `to` here.
   */
  readonly onRoleChange?: (
    userId: string,
    from: Role | null,
    to: Role | null,
    tx: SqlQueryable,
  ) => Promise<void> | void;
}

/** Options for {@link createScim}. */
export interface CreateScimOptions {
  readonly config: AuthConfig;
  readonly sql: Sql;
  /** The app's session service. Created from `config` when left out. */
  readonly sessions?: Sessions<object>;
  readonly hooks?: ScimHooks;
  /** Where the app mounts the sub-app, for `meta.location`. Default `/scim/v2`. */
  readonly basePath?: string;
}

const CONTENT_TYPE = "application/scim+json; charset=utf-8";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The SCIM 2.0 server (RFC 7643 and 7644) for Users and Groups, as a Hono
 * sub-app to mount at `basePath`.
 *
 * Requests authenticate with a bearer token from `<APP>_SCIM_TOKENS`,
 * compared as HMACs under the `scim-token` key in constant time. Bodies are
 * `application/scim+json` or `application/json`. Errors use the SCIM Error
 * schema.
 *
 * Deactivating a user revokes their sessions; deleting tombstones them.
 * With `<APP>_ROLE_SOURCE=scim`, every membership change recomputes the
 * members' roles from the groups' display names in the same transaction.
 *
 * @throws {@link AuthConfigError} when `<APP>_SCIM_TOKENS` is empty.
 */
export function createScim(options: CreateScimOptions): Hono {
  const { config, sql } = options;
  if (config.scim.tokens.length === 0)
    throw new AuthConfigError([
      {
        variable: `${config.app.toUpperCase()}_SCIM_TOKENS`,
        message: "is required to serve SCIM: set at least one bearer token",
      },
    ]);
  const sessions = options.sessions ?? createSessions({ sql, config });
  const hooks = options.hooks ?? {};
  const base = `${config.origins.api}${(options.basePath ?? "/scim/v2").replace(/\/$/, "")}`;
  const key = deriveKey(config.secret, config.app, "scim-token");
  const accepted = config.scim.tokens.map((token) => hashToken(key, token));
  const issuer = config.oidc.issuer;
  const schema = quoteIdent(config.schema);
  const users = `${schema}.users`;
  const groups = `${schema}.scim_groups`;
  const members = `${schema}.scim_group_members`;
  const scimRoles = config.roleSource === "scim";
  const roleByGroup = new Map(
    Object.entries(config.oidc.roleMap.values).map(([name, role]) => [
      name.toLowerCase(),
      role,
    ]),
  );

  const send = (c: Context, body: unknown, status = 200) =>
    c.body(JSON.stringify(body), status as 200, {
      "content-type": CONTENT_TYPE,
    });

  async function readBody(c: Context): Promise<unknown> {
    const type = (c.req.header("content-type") ?? "")
      .split(";")[0]
      ?.trim()
      .toLowerCase();
    if (type !== "application/scim+json" && type !== "application/json")
      throw new ScimError(
        415,
        "Send application/scim+json or application/json.",
      );
    try {
      return JSON.parse(await c.req.text());
    } catch {
      throw badRequest("The body is not valid JSON.", "invalidSyntax");
    }
  }

  function page(c: Context) {
    const start = Number.parseInt(c.req.query("startIndex") ?? "1", 10);
    const count = Number.parseInt(c.req.query("count") ?? "100", 10);
    return {
      startIndex: Number.isFinite(start) && start > 0 ? start : 1,
      count: Number.isFinite(count)
        ? Math.min(Math.max(count, 0), MAX_RESULTS)
        : 100,
    };
  }

  // Users ------------------------------------------------------------------

  async function findUser(
    db: SqlQueryable,
    id: string,
    lock = false,
  ): Promise<ScimUserRow> {
    if (!UUID.test(id)) throw notFound("User");
    const [row] = await db.query<ScimUserRow>(
      `SELECT ${USER_COLUMNS} FROM ${users}
       WHERE id = $1 AND iss = $2 AND deleted_at IS NULL ${lock ? "FOR NO KEY UPDATE" : ""}`,
      [id, issuer],
    );
    if (!row) throw notFound("User");
    return row;
  }

  function userWhere(
    conditions: readonly FilterCondition[],
    params: unknown[],
  ): string {
    return conditions
      .map(({ path, value }) => {
        params.push(value);
        const p = `$${params.length}`;
        switch (path) {
          case "username":
            return `lower(user_name) = lower(${p})`;
          case "externalid":
            return `external_id = ${p}`;
          case "id":
            return UUID.test(value) ? `id = ${p}::uuid` : `${p}::text IS NULL`;
          case "emails.value":
          case 'emails[type eq "work"].value':
            return `lower(email) = lower(${p})`;
          case "displayname":
            return `display_name = ${p}`;
          default:
            throw badRequest(
              `Users cannot be filtered on ${path}.`,
              "invalidFilter",
            );
        }
      })
      .join(" AND ");
  }

  async function assertUniqueUser(
    db: SqlQueryable,
    fields: ScimUserFields,
    exceptId: string | null,
  ): Promise<void> {
    const [clash] = await db.query<{ field: string }>(
      `SELECT CASE WHEN external_id = $3 THEN 'externalId' ELSE 'userName' END AS "field"
       FROM ${users}
       WHERE iss = $1 AND id IS DISTINCT FROM $4::uuid
         AND ((deleted_at IS NULL AND lower(user_name) = lower($2))
              OR ($3::text IS NOT NULL AND external_id = $3))
       LIMIT 1`,
      [issuer, fields.userName, fields.externalId, exceptId],
    );
    if (clash)
      throw conflict(
        clash.field === "externalId"
          ? "A user with this externalId exists, or was deleted and cannot be recreated."
          : "A user with this userName exists.",
      );
  }

  /** Applies a change in `active`: revoke on deactivation. */
  async function afterActiveChange(
    db: SqlQueryable,
    before: boolean,
    after: boolean,
    id: string,
  ) {
    if (before && !after) await hooks.onDeactivate?.(id, db);
  }

  async function writeUser(
    db: SqlQueryable,
    current: ScimUserRow,
    fields: ScimUserFields,
  ): Promise<ScimUserRow> {
    const unchanged = (Object.keys(fields) as (keyof ScimUserFields)[]).every(
      (k) => fields[k] === current[k],
    );
    if (unchanged) return current;
    await assertUniqueUser(db, fields, current.id);
    const [row] = await db.query<ScimUserRow>(
      `UPDATE ${users} SET user_name = $2, external_id = $3, given_name = $4,
         family_name = $5, display_name = $6, email = $7, active = $8,
         deactivated_at = CASE WHEN $8 THEN NULL ELSE coalesce(deactivated_at, now()) END
       WHERE id = $1 RETURNING ${USER_COLUMNS}`,
      [
        current.id,
        fields.userName,
        fields.externalId,
        fields.givenName,
        fields.familyName,
        fields.displayName,
        fields.email,
        fields.active,
      ],
    );
    if (!row) throw notFound("User");
    await afterActiveChange(db, current.active, row.active, row.id);
    return row;
  }

  // Roles ------------------------------------------------------------------

  /**
   * Recomputes roles from group membership for `userIds`, locking each user
   * row in id order so concurrent membership changes serialise and the last
   * one sees every committed membership. The lock is FOR NO KEY UPDATE: it
   * does not conflict with the key-share locks membership inserts take on
   * users, so two transactions adding the same user to different groups
   * queue instead of deadlocking.
   */
  async function recomputeRoles(
    db: SqlQueryable,
    userIds: Iterable<string>,
  ): Promise<void> {
    if (!scimRoles) return;
    for (const id of [...new Set(userIds)].sort()) {
      const [user] = await db.query<{
        role: Role | null;
        source: string | null;
      }>(
        `SELECT role, role_source AS "source" FROM ${users}
         WHERE id = $1 AND deleted_at IS NULL FOR NO KEY UPDATE`,
        [id],
      );
      if (!user) continue;
      const names = await db.query<{ name: string }>(
        `SELECT g.display_name AS "name" FROM ${members} m
         JOIN ${groups} g ON g.id = m.group_id WHERE m.user_id = $1`,
        [id],
      );
      let best: Role | null = null;
      for (const { name } of names) {
        const role = roleByGroup.get(name.toLowerCase());
        if (role) best = best === null ? role : maxRole(best, role);
      }
      const from = user.source === "scim" ? user.role : null;
      if (best === from) continue;
      await db.query(
        `UPDATE ${users} SET role = $2, role_source = 'scim' WHERE id = $1`,
        [id, best],
      );
      if (best === null) await sessions.revokeAll(id, db);
      await hooks.onRoleChange?.(id, from, best, db);
    }
  }

  // Groups -----------------------------------------------------------------

  async function findGroup(
    db: SqlQueryable,
    id: string,
    lock = false,
  ): Promise<ScimGroupRow> {
    if (!UUID.test(id)) throw notFound("Group");
    const [row] = await db.query<Omit<ScimGroupRow, "members">>(
      `SELECT id, display_name AS "displayName", external_id AS "externalId",
         created_at AS "createdAt", updated_at AS "updatedAt"
       FROM ${groups} WHERE id = $1 ${lock ? "FOR UPDATE" : ""}`,
      [id],
    );
    if (!row) throw notFound("Group");
    const list = await db.query<{ value: string; display: string | null }>(
      `SELECT u.id AS "value", u.display_name AS "display" FROM ${members} m
       JOIN ${users} u ON u.id = m.user_id WHERE m.group_id = $1 ORDER BY u.id`,
      [id],
    );
    return { ...row, members: list };
  }

  async function assertUniqueGroup(
    db: SqlQueryable,
    change: ScimGroupChange,
    exceptId: string | null,
  ) {
    const [clash] = await db.query(
      `SELECT 1 FROM ${groups}
       WHERE id IS DISTINCT FROM $3::uuid
         AND (lower(display_name) = lower($1) OR ($2::text IS NOT NULL AND external_id = $2))
       LIMIT 1`,
      [change.displayName, change.externalId, exceptId],
    );
    if (clash)
      throw conflict("A group with this displayName or externalId exists.");
  }

  async function setMembers(
    db: SqlQueryable,
    groupId: string,
    wanted: readonly string[],
  ) {
    const unique = [...new Set(wanted)];
    if (unique.length > 0) {
      const found = await db.query<{ id: string }>(
        `SELECT id FROM ${users} WHERE id = ANY($1::uuid[]) AND iss = $2 AND deleted_at IS NULL`,
        [`{${unique.join(",")}}`, issuer],
      );
      if (found.length !== unique.length)
        throw badRequest(
          "Every member must be a user of this app.",
          "invalidValue",
        );
    }
    const before = await db.query<{ id: string }>(
      `SELECT user_id AS "id" FROM ${members} WHERE group_id = $1`,
      [groupId],
    );
    const had = new Set(before.map((r) => r.id));
    const want = new Set(unique);
    const removed = [...had].filter((id) => !want.has(id));
    const added = unique.filter((id) => !had.has(id));
    if (removed.length > 0)
      await db.query(
        `DELETE FROM ${members} WHERE group_id = $1 AND user_id = ANY($2::uuid[])`,
        [groupId, `{${removed.join(",")}}`],
      );
    if (added.length > 0)
      await db.query(
        `INSERT INTO ${members} (group_id, user_id)
         SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`,
        [groupId, `{${added.join(",")}}`],
      );
    return [...removed, ...added];
  }

  async function writeGroup(
    db: SqlQueryable,
    current: ScimGroupRow,
    change: ScimGroupChange,
  ): Promise<ScimGroupRow> {
    const renamed =
      change.displayName !== current.displayName ||
      change.externalId !== current.externalId;
    if (renamed) {
      await assertUniqueGroup(db, change, current.id);
      await db.query(
        `UPDATE ${groups} SET display_name = $2, external_id = $3 WHERE id = $1`,
        [current.id, change.displayName, change.externalId],
      );
    }
    const touched =
      change.members === null
        ? []
        : await setMembers(db, current.id, change.members);
    // A rename can change the role every member gets.
    const affected =
      renamed &&
      change.displayName.toLowerCase() !== current.displayName.toLowerCase()
        ? [...current.members.map((m) => m.value), ...touched]
        : touched;
    await recomputeRoles(db, affected);
    return findGroup(db, current.id);
  }

  // Routes -----------------------------------------------------------------

  const app = new Hono();

  app.onError((error, c) => {
    if (error instanceof ScimError)
      return send(c, error.toJSON(), error.status);
    const code = (error as { code?: unknown }).code;
    if (code === "23505")
      return send(c, conflict("The value must be unique.").toJSON(), 409);
    if (code === "23514")
      return send(c, badRequest(error.message, "invalidValue").toJSON(), 400);
    throw error;
  });

  app.use("*", async (c, next) => {
    const header = c.req.header("authorization") ?? "";
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    let ok = false;
    if (match) {
      const presented = hashToken(key, match[1] ?? "");
      for (const hash of accepted)
        if (constantTimeEqual(presented, hash)) ok = true;
    }
    if (!ok) {
      c.header("WWW-Authenticate", 'Bearer realm="SCIM"');
      return send(
        c,
        new ScimError(401, "A valid bearer token is required.").toJSON(),
        401,
      );
    }
    await next();
  });

  app.get("/ServiceProviderConfig", (c) =>
    send(c, serviceProviderConfig(base)),
  );
  app.get("/ResourceTypes", (c) => {
    const list = resourceTypes(base);
    return send(c, {
      schemas: [SCHEMAS.list],
      totalResults: list.length,
      startIndex: 1,
      itemsPerPage: list.length,
      Resources: list,
    });
  });
  app.get("/ResourceTypes/:id", (c) => {
    const found = resourceTypes(base).find((r) => r.id === c.req.param("id"));
    if (!found) throw notFound("ResourceType");
    return send(c, found);
  });
  app.get("/Schemas", (c) => {
    const list = schemas(base);
    return send(c, {
      schemas: [SCHEMAS.list],
      totalResults: list.length,
      startIndex: 1,
      itemsPerPage: list.length,
      Resources: list,
    });
  });
  app.get("/Schemas/:id", (c) => {
    const found = schemas(base).find((s) => s.id === c.req.param("id"));
    if (!found) throw notFound("Schema");
    return send(c, found);
  });

  app.get("/Users", async (c) => {
    const filter = c.req.query("filter");
    const conditions = filter ? parseFilter(filter) : [];
    const params: unknown[] = [issuer];
    const where =
      conditions.length > 0 ? `AND ${userWhere(conditions, params)}` : "";
    const { startIndex, count } = page(c);
    const [total] = await sql.query<{ n: number }>(
      `SELECT count(*)::int AS "n" FROM ${users} WHERE iss = $1 AND deleted_at IS NULL ${where}`,
      params,
    );
    const rows =
      count === 0
        ? []
        : await sql.query<ScimUserRow>(
            `SELECT ${USER_COLUMNS} FROM ${users}
             WHERE iss = $1 AND deleted_at IS NULL ${where}
             ORDER BY created_at, id OFFSET ${startIndex - 1} LIMIT ${count}`,
            params,
          );
    const view = projection(c.req.query());
    return send(c, {
      schemas: [SCHEMAS.list],
      totalResults: total?.n ?? 0,
      startIndex,
      itemsPerPage: rows.length,
      Resources: rows.map((r) => applyProjection(userResource(r, base), view)),
    });
  });

  app.get("/Users/:id", async (c) =>
    send(
      c,
      applyProjection(
        userResource(await findUser(sql, c.req.param("id")), base),
        projection(c.req.query()),
      ),
    ),
  );

  app.post("/Users", async (c) => {
    const fields = userFields(await readBody(c));
    const row = await sql.transaction(async (tx) => {
      await assertUniqueUser(tx, fields, null);
      const [created] = await tx.query<ScimUserRow>(
        `INSERT INTO ${users} (iss, user_name, external_id, given_name, family_name,
           display_name, email, active, deactivated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $8 THEN NULL ELSE now() END)
         RETURNING ${USER_COLUMNS}`,
        [
          issuer,
          fields.userName,
          fields.externalId,
          fields.givenName,
          fields.familyName,
          fields.displayName,
          fields.email,
          fields.active,
        ],
      );
      if (!created) throw new Error("INSERT … RETURNING returned no row.");
      return created;
    });
    c.header("Location", `${base}/Users/${row.id}`);
    return send(c, userResource(row, base), 201);
  });

  app.put("/Users/:id", async (c) => {
    const body = await readBody(c);
    const row = await sql.transaction(async (tx) => {
      const current = await findUser(tx, c.req.param("id"), true);
      return writeUser(tx, current, userFields(body, current));
    });
    return send(c, userResource(row, base));
  });

  app.patch("/Users/:id", async (c) => {
    const operations = parsePatch(await readBody(c));
    const row = await sql.transaction(async (tx) => {
      const current = await findUser(tx, c.req.param("id"), true);
      const doc = patchUser(userResource(current, base), operations);
      return writeUser(tx, current, userFields(doc, current));
    });
    return send(c, userResource(row, base));
  });

  app.delete("/Users/:id", async (c) => {
    await sql.transaction(async (tx) => {
      const current = await findUser(tx, c.req.param("id"), true);
      await tx.query(`DELETE FROM ${members} WHERE user_id = $1`, [current.id]);
      await tx.query(
        `UPDATE ${users} SET active = false,
           deactivated_at = coalesce(deactivated_at, now()), deleted_at = now()
         WHERE id = $1`,
        [current.id],
      );
      await sessions.revokeAll(current.id, tx);
      await hooks.onDeactivate?.(current.id, tx);
    });
    return c.body(null, 204);
  });

  app.get("/Groups", async (c) => {
    const filter = c.req.query("filter");
    const conditions = filter ? parseFilter(filter) : [];
    const params: unknown[] = [];
    const where = conditions
      .map(({ path, value }) => {
        params.push(value);
        const p = `$${params.length}`;
        if (path === "displayname") return `lower(display_name) = lower(${p})`;
        if (path === "externalid") return `external_id = ${p}`;
        if (path === "id")
          return UUID.test(value) ? `id = ${p}::uuid` : `${p}::text IS NULL`;
        throw badRequest(
          `Groups cannot be filtered on ${path}.`,
          "invalidFilter",
        );
      })
      .join(" AND ");
    const clause = where === "" ? "" : `WHERE ${where}`;
    const { startIndex, count } = page(c);
    const [total] = await sql.query<{ n: number }>(
      `SELECT count(*)::int AS "n" FROM ${groups} ${clause}`,
      params,
    );
    const ids =
      count === 0
        ? []
        : await sql.query<{ id: string }>(
            `SELECT id FROM ${groups} ${clause}
             ORDER BY created_at, id OFFSET ${startIndex - 1} LIMIT ${count}`,
            params,
          );
    const view = projection(c.req.query());
    const resources = [];
    for (const { id } of ids)
      resources.push(
        applyProjection(groupResource(await findGroup(sql, id), base), view),
      );
    return send(c, {
      schemas: [SCHEMAS.list],
      totalResults: total?.n ?? 0,
      startIndex,
      itemsPerPage: resources.length,
      Resources: resources,
    });
  });

  app.get("/Groups/:id", async (c) =>
    send(
      c,
      applyProjection(
        groupResource(await findGroup(sql, c.req.param("id")), base),
        projection(c.req.query()),
      ),
    ),
  );

  app.post("/Groups", async (c) => {
    const change = groupChange(await readBody(c));
    const row = await sql.transaction(async (tx) => {
      await assertUniqueGroup(tx, change, null);
      const [created] = await tx.query<{ id: string }>(
        `INSERT INTO ${groups} (display_name, external_id) VALUES ($1, $2) RETURNING id`,
        [change.displayName, change.externalId],
      );
      if (!created) throw new Error("INSERT … RETURNING returned no row.");
      const touched = await setMembers(tx, created.id, change.members ?? []);
      await recomputeRoles(tx, touched);
      return findGroup(tx, created.id);
    });
    c.header("Location", `${base}/Groups/${row.id}`);
    return send(c, groupResource(row, base), 201);
  });

  app.put("/Groups/:id", async (c) => {
    const body = await readBody(c);
    const row = await sql.transaction(async (tx) => {
      const current = await findGroup(tx, c.req.param("id"), true);
      return writeGroup(tx, current, groupChange(body, current));
    });
    return send(c, groupResource(row, base));
  });

  app.patch("/Groups/:id", async (c) => {
    const operations = parsePatch(await readBody(c));
    const row = await sql.transaction(async (tx) => {
      const current = await findGroup(tx, c.req.param("id"), true);
      return writeGroup(tx, current, patchGroup(current, operations));
    });
    return send(c, groupResource(row, base));
  });

  app.delete("/Groups/:id", async (c) => {
    await sql.transaction(async (tx) => {
      const current = await findGroup(tx, c.req.param("id"), true);
      await tx.query(`DELETE FROM ${groups} WHERE id = $1`, [current.id]);
      await recomputeRoles(
        tx,
        current.members.map((m) => m.value),
      );
    });
    return c.body(null, 204);
  });

  // A catch-all route rather than notFound(), which a parent app replaces
  // when this one is mounted with route().
  app.all("*", (c) => send(c, notFound("Resource").toJSON(), 404));

  return app;
}
