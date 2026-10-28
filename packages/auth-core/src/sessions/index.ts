import { createActor, type Actor, type ActorUser } from "../actor.js";
import type { AuthConfig } from "../config.js";
import { quoteIdent } from "../identifiers.js";
import { deriveKey } from "../keys.js";
import type { Sql, SqlQueryable } from "../postgres/sql.js";
import type { Role } from "../roles.js";
import { generateToken, hashToken, isWellFormedToken } from "../tokens.js";

/** A stored session. The token itself is never stored or returned again. */
export interface SessionRecord {
  /** HMAC-SHA256 of the token: the session's id in the database. */
  readonly idHash: string;
  readonly userId: string;
  readonly createdAt: Date;
  /** When the person last authenticated at the provider. */
  readonly authenticatedAt: Date;
  /** The provider's `amr` values for that authentication. */
  readonly amr: readonly string[];
  readonly expiresAt: Date;
  readonly idleExpiresAt: Date;
  readonly providerSid: string | null;
}

/** A live session with its actor, from {@link Sessions.lookup}. */
export interface SessionLookup<Ext extends object> {
  readonly session: SessionRecord;
  readonly actor: Actor<Ext>;
}

/** Options for {@link createSessions}. */
export interface SessionsOptions<Ext extends object> {
  readonly sql: Sql;
  /** Uses `app`, `secret`, `session` and `schema`. */
  readonly config: AuthConfig;
  /** Adds app-specific fields to each actor. */
  readonly extendActor?: (user: ActorUser) => Ext | Promise<Ext>;
  /**
   * The current time. Defaults to the database's `now()`. Tests inject a
   * clock to exercise expiry.
   */
  readonly now?: () => Date;
}

/** Session storage and lookup for one app. */
export interface Sessions<Ext extends object> {
  /**
   * Creates a session for an active user and returns its token, which goes
   * only into the cookie. Every sign-in gets a new token, so a token planted
   * before sign-in never becomes valid. Pass the sign-in transaction as `db`.
   */
  create(
    input: {
      readonly userId: string;
      readonly authenticatedAt: Date;
      readonly amr: readonly string[];
      readonly providerSid: string | null;
    },
    db?: SqlQueryable,
  ): Promise<{ readonly token: string; readonly session: SessionRecord }>;
  /**
   * Finds the live session for `token`: not revoked, within both its
   * absolute and idle expiry, and belonging to an active user. Slides the
   * idle expiry forward, at most once a minute and never past the absolute
   * expiry. Returns `null` for anything else, including malformed tokens.
   */
  lookup(token: string | undefined): Promise<SessionLookup<Ext> | null>;
  /** The hash stored for `token`, or `null` when it is malformed. */
  hash(token: string | undefined): string | null;
  /** Revokes one session. Returns whether a live session was revoked. */
  revoke(idHash: string): Promise<boolean>;
  /**
   * Revokes every live session of a user and returns how many. Pass a
   * transaction as `db` to make it part of a larger change.
   */
  revokeAll(userId: string, db?: SqlQueryable): Promise<number>;
  /** A user's live sessions, newest first. */
  list(userId: string): Promise<SessionRecord[]>;
  /**
   * Records a step-up: moves the session's `authenticated_at` forward and
   * replaces its `amr`. Returns `false` when the session is no longer live.
   */
  reauthenticate(
    idHash: string,
    input: { readonly authenticatedAt: Date; readonly amr: readonly string[] },
  ): Promise<boolean>;
  /**
   * Revokes the sessions a back-channel logout names: by provider `sid`, by
   * `sub`, or by both (sessions matching both). Returns how many. Pass a
   * transaction as `db` to make it part of a larger change.
   */
  revokeForProvider(
    input: {
      readonly iss: string;
      readonly sub: string | null;
      readonly sid: string | null;
    },
    db?: SqlQueryable,
  ): Promise<number>;
}

const SESSION_COLUMNS = `s.id_hash AS "idHash", s.user_id AS "userId",
  s.created_at AS "createdAt", s.authenticated_at AS "authenticatedAt", s.amr,
  s.expires_at AS "expiresAt", s.idle_expires_at AS "idleExpiresAt",
  s.provider_sid AS "providerSid"`;

/** Creates the session service for one app. */
export function createSessions<Ext extends object = Record<never, never>>(
  options: SessionsOptions<Ext>,
): Sessions<Ext> {
  const { sql, config } = options;
  const key = deriveKey(config.secret, config.app, "session");
  const schema = quoteIdent(config.schema);
  const sessions = `${schema}.sessions`;
  const users = `${schema}.users`;
  const maxAge = config.session.maxAgeSeconds;
  const idle = config.session.idleTimeoutSeconds;
  const now = () => options.now?.() ?? null;
  // $1 is always the clock; null means the database's now().
  const T = "coalesce($1::timestamptz, now())";

  const hash = (token: string | undefined) =>
    isWellFormedToken(token) ? hashToken(key, token) : null;

  async function revokeWhere(
    db: SqlQueryable,
    where: string,
    params: unknown[],
  ): Promise<number> {
    const rows = await db.query(
      `UPDATE ${sessions} s SET revoked_at = ${T}
       WHERE s.revoked_at IS NULL AND ${where}
       RETURNING s.id_hash`,
      [now(), ...params],
    );
    return rows.length;
  }

  return {
    hash,

    async create(input, db = sql) {
      const token = generateToken();
      const idHash = hashToken(key, token);
      const [session] = await db.query<SessionRecord>(
        `INSERT INTO ${sessions} AS s
           (id_hash, user_id, created_at, authenticated_at, amr, expires_at,
            idle_expires_at, provider_sid)
         VALUES ($2, $3, ${T}, LEAST($4::timestamptz, ${T}),
                 ARRAY(SELECT jsonb_array_elements_text($5::text::jsonb)),
                 ${T} + make_interval(secs => $6), ${T} + make_interval(secs => $7), $8)
         RETURNING ${SESSION_COLUMNS}`,
        [
          now(),
          idHash,
          input.userId,
          input.authenticatedAt,
          JSON.stringify(input.amr.filter((v) => typeof v === "string")),
          maxAge,
          Math.min(idle, maxAge),
          input.providerSid,
        ],
      );
      if (session === undefined)
        throw new Error("INSERT … RETURNING returned no row.");
      return { token, session };
    },

    async lookup(token) {
      const idHash = hash(token);
      if (idHash === null) return null;
      const [row] = await sql.query<
        SessionRecord & {
          role: Role;
          email: string | null;
          displayName: string | null;
        }
      >(
        `SELECT ${SESSION_COLUMNS}, u.role, u.email, u.display_name AS "displayName"
         FROM ${sessions} s JOIN ${users} u ON u.id = s.user_id
         WHERE s.id_hash = $2 AND s.revoked_at IS NULL
           AND s.expires_at > ${T} AND s.idle_expires_at > ${T}
           AND u.active AND u.deleted_at IS NULL AND u.role IS NOT NULL
           AND ($3::boolean IS NOT TRUE OR u.role_source = 'scim')`,
        [now(), idHash, config.roleSource === "scim"],
      );
      if (row === undefined) return null;
      const [slid] = await sql.query<{ idleExpiresAt: Date }>(
        `UPDATE ${sessions}
         SET idle_expires_at = LEAST(${T} + make_interval(secs => $3), expires_at)
         WHERE id_hash = $2 AND revoked_at IS NULL
           AND idle_expires_at < LEAST(${T} + make_interval(secs => $3), expires_at) - interval '60 seconds'
         RETURNING idle_expires_at AS "idleExpiresAt"`,
        [now(), idHash, idle],
      );
      const { role, email, displayName, ...rest } = row;
      const session: SessionRecord = {
        ...rest,
        idleExpiresAt: slid?.idleExpiresAt ?? row.idleExpiresAt,
      };
      const user: ActorUser = { id: row.userId, role, email, displayName };
      const ext = options.extendActor
        ? await options.extendActor(user)
        : ({} as Ext);
      return {
        session,
        actor: createActor<Ext>({
          user,
          credential: {
            kind: "session",
            id: idHash,
            ceiling: null,
            workspace: null,
          },
          ext,
        }),
      };
    },

    async revoke(idHash) {
      return (await revokeWhere(sql, "s.id_hash = $2", [idHash])) > 0;
    },

    async revokeAll(userId, db) {
      return revokeWhere(db ?? sql, "s.user_id = $2", [userId]);
    },

    async list(userId) {
      return sql.query<SessionRecord>(
        `SELECT ${SESSION_COLUMNS} FROM ${sessions} s
         WHERE s.user_id = $2 AND s.revoked_at IS NULL
           AND s.expires_at > ${T} AND s.idle_expires_at > ${T}
         ORDER BY s.created_at DESC, s.id_hash`,
        [now(), userId],
      );
    },

    async reauthenticate(idHash, input) {
      const rows = await sql.query(
        `UPDATE ${sessions}
         SET authenticated_at = GREATEST(authenticated_at, LEAST($3::timestamptz, ${T})),
             amr = ARRAY(SELECT jsonb_array_elements_text($4::text::jsonb))
         WHERE id_hash = $2 AND revoked_at IS NULL
           AND expires_at > ${T} AND idle_expires_at > ${T}
         RETURNING id_hash`,
        [now(), idHash, input.authenticatedAt, JSON.stringify(input.amr)],
      );
      return rows.length === 1;
    },

    async revokeForProvider({ iss, sub, sid }, db) {
      if (sub === null && sid === null) return 0;
      return revokeWhere(
        db ?? sql,
        `s.user_id IN (SELECT id FROM ${users} WHERE iss = $2 AND ($3::text IS NULL OR sub = $3))
         AND ($4::text IS NULL OR s.provider_sid = $4)`,
        [iss, sub, sid],
      );
    },
  };
}
