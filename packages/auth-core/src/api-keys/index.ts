import { createActor, type Actor, type ActorUser } from "../actor.js";
import type { AuthConfig } from "../config.js";
import {
  AuthConfigError,
  AuthRequestError,
  InvalidApiKeyError,
} from "../errors.js";
import { quoteIdent } from "../identifiers.js";
import { deriveKey } from "../keys.js";
import type { Sql, SqlQueryable } from "../postgres/sql.js";
import { isRole, roleAtLeast, type Role } from "../roles.js";
import { constantTimeEqual, hashToken } from "../tokens.js";
import { generateApiKey, parseApiKey } from "./format.js";

/** A stored API key. The key string itself is never stored or returned again. */
export interface ApiKeyRecord {
  /** The public id, the second part of the key. Safe to log and show. */
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  /** The highest role the key acts with. Never changes. */
  readonly ceiling: Role;
  /** The app-defined workspace, or `null`. auth-core never interprets it. */
  readonly workspace: string | null;
  readonly createdAt: Date;
  /** `null` when the key never expires. */
  readonly expiresAt: Date | null;
  /** Updated at most once a minute. */
  readonly lastUsedAt: Date | null;
  readonly revokedAt: Date | null;
  /** The key that replaced this one on rotation. */
  readonly replacedBy: string | null;
  /** After rotation, when this key stops working. */
  readonly graceUntil: Date | null;
}

/** A verified key with its actor, from {@link ApiKeys.verify}. */
export interface ApiKeyVerification<Ext extends object> {
  readonly key: ApiKeyRecord;
  readonly actor: Actor<Ext>;
}

/** A new key: the full string, to show once, and its record. */
export interface IssuedApiKey {
  /** The full key. Shown to the user once; only its hash is stored. */
  readonly key: string;
  readonly record: ApiKeyRecord;
}

/** Options for {@link createApiKeys}. */
export interface ApiKeysOptions<Ext extends object> {
  readonly sql: Sql;
  /** Uses `app`, `secret`, `apiKeys`, `roleSource` and `schema`. */
  readonly config: AuthConfig;
  /** Adds app-specific fields to each actor. */
  readonly extendActor?: (user: ActorUser) => Ext | Promise<Ext>;
  /** The current time. Defaults to the database's `now()`. For tests. */
  readonly now?: () => Date;
}

/** The longest rotation grace period: seven days. */
export const MAX_ROTATION_GRACE_SECONDS = 7 * 86400;

/** The longest key name, in characters. */
export const MAX_API_KEY_NAME_LENGTH = 100;

/** The longest workspace value, in characters. */
export const MAX_WORKSPACE_LENGTH = 255;

/** API key storage, rotation and verification for one app. */
export interface ApiKeys<Ext extends object> {
  /** The key prefix in use, such as `posted`. */
  readonly prefix: string;
  /**
   * Issues a key for an active user and returns the full key once.
   *
   * `expiresInSeconds` defaults to `<APP>_API_KEY_MAX_TTL_DAYS` and may not
   * exceed it; `null` (never expires) needs `<APP>_API_KEY_ALLOW_NO_EXPIRY`.
   *
   * @throws {@link AuthRequestError} `forbidden` (reason `ceiling`) when the
   *   ceiling is above the user's current role, or (reason `user`) when the
   *   user is inactive or has no role; `invalid_request` for a bad name,
   *   workspace or lifetime.
   */
  create(
    input: {
      readonly userId: string;
      readonly name: string;
      readonly ceiling: Role;
      readonly workspace?: string | null;
      readonly expiresInSeconds?: number | null;
    },
    db?: SqlQueryable,
  ): Promise<IssuedApiKey>;
  /** A user's usable keys, newest first, including rotated ones still in grace. */
  list(userId: string): Promise<ApiKeyRecord[]>;
  /** One key, usable or not, or `null`. */
  get(id: string): Promise<ApiKeyRecord | null>;
  /**
   * Revokes a key. With `userId`, only that user's key. Returns whether a
   * key that was not yet revoked was revoked.
   */
  revoke(id: string, options?: { readonly userId?: string }): Promise<boolean>;
  /**
   * Replaces a usable key with a new one with the same name, ceiling and
   * workspace, and the same lifetime (capped by the current maximum). The
   * old key keeps working for `graceSeconds` (0 to seven days). A key is
   * rotated once: of two concurrent rotations, one wins and the other gets
   * `conflict`.
   *
   * @throws {@link AuthRequestError} `not_found`, `conflict` or `forbidden`.
   */
  rotate(
    id: string,
    options: { readonly graceSeconds: number; readonly userId?: string },
  ): Promise<IssuedApiKey>;
  /**
   * Checks a presented key and returns its actor, or `null`. The format and
   * checksum are checked before any database read. The stored hash is
   * compared in constant time, and an unknown id costs the same comparison.
   * The key must not be revoked, expired or past its rotation grace, and its
   * owner must be active with a role; the actor's role is the lower of the
   * ceiling and the owner's current role. Records `last_used_at` at most
   * once a minute.
   */
  verify(key: string | undefined): Promise<ApiKeyVerification<Ext> | null>;
}

const COLUMNS = `k.id, k.user_id AS "userId", k.name, k.ceiling, k.workspace,
  k.created_at AS "createdAt", k.expires_at AS "expiresAt",
  k.last_used_at AS "lastUsedAt", k.revoked_at AS "revokedAt",
  k.replaced_by AS "replacedBy", k.grace_until AS "graceUntil"`;

// A hash no key has, so an unknown id costs the same comparison.
const ABSENT_HASH = "0".repeat(64);

function invalid(message: string, reason: string): AuthRequestError {
  return new AuthRequestError("invalid_request", message, { reason });
}

function checkName(name: unknown): string {
  const trimmed = typeof name === "string" ? name.trim() : "";
  if (
    trimmed === "" ||
    Array.from(trimmed).length > MAX_API_KEY_NAME_LENGTH ||
    /\p{Cc}/u.test(trimmed)
  )
    throw invalid(
      `A key needs a name of 1 to ${MAX_API_KEY_NAME_LENGTH} characters.`,
      "name",
    );
  return trimmed;
}

function checkWorkspace(workspace: unknown): string | null {
  if (workspace === undefined || workspace === null) return null;
  if (
    typeof workspace !== "string" ||
    workspace === "" ||
    workspace.length > MAX_WORKSPACE_LENGTH ||
    /\p{Cc}/u.test(workspace)
  )
    throw invalid(
      `A workspace is 1 to ${MAX_WORKSPACE_LENGTH} characters.`,
      "workspace",
    );
  return workspace;
}

/**
 * Creates the API key service for one app.
 *
 * @throws {@link AuthConfigError} when no key prefix is configured.
 */
export function createApiKeys<Ext extends object = Record<never, never>>(
  options: ApiKeysOptions<Ext>,
): ApiKeys<Ext> {
  const { sql, config } = options;
  const prefix = config.apiKeys.prefix;
  if (prefix === null)
    throw new AuthConfigError([
      {
        variable: `${config.app.toUpperCase()}_API_KEY_PREFIX`,
        message:
          "is required for API keys when the app id is not 2 to 16 characters",
      },
    ]);
  const keyPrefix: string = prefix;
  const hmacKey = deriveKey(config.secret, config.app, "api-key");
  const schema = quoteIdent(config.schema);
  const keys = `${schema}.api_keys`;
  const users = `${schema}.users`;
  const scimRoles = config.roleSource === "scim";
  const { maxTtlSeconds, allowNoExpiry } = config.apiKeys;
  const now = () => options.now?.() ?? null;
  // $1 is always the clock; null means the database's now().
  const T = "coalesce($1::timestamptz, now())";
  const USABLE = `k.revoked_at IS NULL
    AND (k.expires_at IS NULL OR k.expires_at > ${T})
    AND (k.grace_until IS NULL OR k.grace_until > ${T})`;

  function lifetime(seconds: number | null | undefined): number | null {
    if (seconds === undefined) return maxTtlSeconds;
    if (seconds === null) {
      if (!allowNoExpiry)
        throw invalid("API keys must expire in this app.", "expiry");
      return null;
    }
    if (!Number.isInteger(seconds) || seconds < 60 || seconds > maxTtlSeconds)
      throw invalid(
        `A key's lifetime is 60 to ${maxTtlSeconds} seconds.`,
        "expiry",
      );
    return seconds;
  }

  /** Locks the owner and checks they may hold a key with `ceiling`. */
  async function assertOwner(
    db: SqlQueryable,
    userId: string,
    ceiling: Role,
  ): Promise<void> {
    const [owner] = await db.query<{ role: Role | null; usable: boolean }>(
      `SELECT role, active AND deleted_at IS NULL
         AND ($2::boolean IS NOT TRUE OR role_source = 'scim') AS "usable"
       FROM ${users} WHERE id = $1 FOR SHARE`,
      [userId, scimRoles],
    );
    if (!owner?.usable || owner.role === null)
      throw new AuthRequestError(
        "forbidden",
        "This account cannot hold API keys.",
        { reason: "user" },
      );
    if (!roleAtLeast(owner.role, ceiling))
      throw new AuthRequestError(
        "forbidden",
        `A key cannot have a higher role than yours (${owner.role}).`,
        { reason: "ceiling" },
      );
  }

  async function insert(
    db: SqlQueryable,
    input: {
      userId: string;
      name: string;
      ceiling: Role;
      workspace: string | null;
      lifetime: number | null;
    },
  ): Promise<IssuedApiKey> {
    const issued = generateApiKey(keyPrefix);
    const [record] = await db.query<ApiKeyRecord>(
      `INSERT INTO ${keys} AS k
         (id, user_id, name, ceiling, workspace, secret_hash, created_at, expires_at)
       VALUES ($2, $3, $4, $5, $6, $7, ${T},
               ${T} + make_interval(secs => $8::double precision))
       RETURNING ${COLUMNS}`,
      [
        now(),
        issued.id,
        input.userId,
        input.name,
        input.ceiling,
        input.workspace,
        hashToken(hmacKey, issued.key),
        input.lifetime,
      ],
    );
    if (record === undefined)
      throw new Error("INSERT … RETURNING returned no row.");
    return { key: issued.key, record };
  }

  return {
    prefix: keyPrefix,

    async create(input, db) {
      if (!isRole(input.ceiling))
        throw invalid(
          "The ceiling must be viewer, member or admin.",
          "ceiling",
        );
      const fields = {
        userId: input.userId,
        name: checkName(input.name),
        ceiling: input.ceiling,
        workspace: checkWorkspace(input.workspace),
        lifetime: lifetime(input.expiresInSeconds),
      };
      const run = async (tx: SqlQueryable) => {
        await assertOwner(tx, fields.userId, fields.ceiling);
        return insert(tx, fields);
      };
      return db ? run(db) : sql.transaction(run);
    },

    async list(userId) {
      return sql.query<ApiKeyRecord>(
        `SELECT ${COLUMNS} FROM ${keys} k
         WHERE k.user_id = $2 AND ${USABLE}
         ORDER BY k.created_at DESC, k.id`,
        [now(), userId],
      );
    },

    async get(id) {
      const [record] = await sql.query<ApiKeyRecord>(
        `SELECT ${COLUMNS} FROM ${keys} k WHERE k.id = $1`,
        [id],
      );
      return record ?? null;
    },

    async revoke(id, revokeOptions = {}) {
      const rows = await sql.query(
        `UPDATE ${keys} k SET revoked_at = GREATEST(${T}, k.created_at)
         WHERE k.id = $2 AND k.revoked_at IS NULL
           AND ($3::uuid IS NULL OR k.user_id = $3)
         RETURNING k.id`,
        [now(), id, revokeOptions.userId ?? null],
      );
      return rows.length === 1;
    },

    async rotate(id, rotateOptions) {
      const grace = rotateOptions.graceSeconds;
      if (
        !Number.isInteger(grace) ||
        grace < 0 ||
        grace > MAX_ROTATION_GRACE_SECONDS
      )
        throw invalid(
          `The grace period is 0 to ${MAX_ROTATION_GRACE_SECONDS} seconds.`,
          "grace",
        );
      return sql.transaction(async (tx) => {
        const [old] = await tx.query<
          ApiKeyRecord & { usable: boolean; lifetime: number | null }
        >(
          `SELECT ${COLUMNS}, (${USABLE}) AS "usable",
             extract(epoch FROM k.expires_at - k.created_at)::double precision AS "lifetime"
           FROM ${keys} k
           WHERE k.id = $2 AND ($3::uuid IS NULL OR k.user_id = $3)
           FOR UPDATE`,
          [now(), id, rotateOptions.userId ?? null],
        );
        if (!old?.usable)
          throw new AuthRequestError("not_found", "No such API key.");
        if (old.replacedBy !== null)
          throw new AuthRequestError(
            "conflict",
            "This key was already rotated.",
          );
        await assertOwner(tx, old.userId, old.ceiling);
        const issued = await insert(tx, {
          userId: old.userId,
          name: old.name,
          ceiling: old.ceiling,
          workspace: old.workspace,
          lifetime:
            old.lifetime === null
              ? allowNoExpiry
                ? null
                : maxTtlSeconds
              : Math.min(Math.round(old.lifetime), maxTtlSeconds),
        });
        await tx.query(
          `UPDATE ${keys} SET replaced_by = $2,
             grace_until = ${T} + make_interval(secs => $3)
           WHERE id = $4`,
          [now(), issued.record.id, grace, old.id],
        );
        return issued;
      });
    },

    async verify(presented) {
      if (typeof presented !== "string") return null;
      let id: string;
      try {
        id = parseApiKey(presented, keyPrefix).id;
      } catch (error) {
        if (error instanceof InvalidApiKeyError) return null;
        throw error;
      }
      const [row] = await sql.query<
        ApiKeyRecord & {
          secretHash: string;
          usable: boolean;
          role: Role | null;
          email: string | null;
          displayName: string | null;
        }
      >(
        `SELECT ${COLUMNS}, k.secret_hash AS "secretHash", u.role, u.email,
           u.display_name AS "displayName",
           (${USABLE} AND u.active AND u.deleted_at IS NULL AND u.role IS NOT NULL
            AND ($3::boolean IS NOT TRUE OR u.role_source = 'scim')) AS "usable"
         FROM ${keys} k JOIN ${users} u ON u.id = k.user_id
         WHERE k.id = $2`,
        [now(), id, scimRoles],
      );
      const matches = constantTimeEqual(
        hashToken(hmacKey, presented),
        row?.secretHash ?? ABSENT_HASH,
      );
      if (!row || !matches || !row.usable || row.role === null) return null;
      const [used] = await sql.query<{ lastUsedAt: Date }>(
        `UPDATE ${keys} SET last_used_at = ${T}
         WHERE id = $2 AND (last_used_at IS NULL OR last_used_at < ${T} - interval '60 seconds')
         RETURNING last_used_at AS "lastUsedAt"`,
        [now(), id],
      );
      const key: ApiKeyRecord = {
        id: row.id,
        userId: row.userId,
        name: row.name,
        ceiling: row.ceiling,
        workspace: row.workspace,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
        lastUsedAt: used?.lastUsedAt ?? row.lastUsedAt,
        revokedAt: row.revokedAt,
        replacedBy: row.replacedBy,
        graceUntil: row.graceUntil,
      };
      const user: ActorUser = {
        id: key.userId,
        role: row.role,
        email: row.email,
        displayName: row.displayName,
      };
      const ext = options.extendActor
        ? await options.extendActor(user)
        : ({} as Ext);
      return {
        key,
        actor: createActor<Ext>({
          user,
          credential: {
            kind: "api_key",
            id: key.id,
            ceiling: key.ceiling,
            workspace: key.workspace,
            restrictions: null,
          },
          ext,
        }),
      };
    },
  };
}
