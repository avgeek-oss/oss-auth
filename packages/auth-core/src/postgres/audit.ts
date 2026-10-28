import { AUDIT_EVENT_TYPES, type AuditEvent } from "../audit.js";
import { isValidSchemaName, quoteIdent } from "../identifiers.js";
import { DEFAULT_AUTH_SCHEMA } from "./migrate.js";
import type { SqlQueryable } from "./sql.js";

/** Longest user agent stored, in characters; longer ones are cut. */
export const MAX_USER_AGENT_LENGTH = 512;

/**
 * Appends `event` to `<schema>.audit_events` and returns the new row's id.
 *
 * Run it on the transaction that made the change, so the event and the
 * change commit or roll back together.
 *
 * @param options.schema - The auth schema. Defaults to `auth`.
 * @throws `TypeError` for an event type auth-core does not define. Database
 *   constraint errors, such as a malformed IP address, pass through.
 */
export async function insertAuditEvent(
  sql: SqlQueryable,
  event: AuditEvent,
  options: { readonly schema?: string } = {},
): Promise<string> {
  const schema = options.schema ?? DEFAULT_AUTH_SCHEMA;
  if (!isValidSchemaName(schema))
    throw new TypeError(`"${schema}" is not a valid auth schema name.`);
  if (!(AUDIT_EVENT_TYPES as readonly string[]).includes(event.type))
    throw new TypeError(`Unknown audit event type: ${event.type}`);
  const { actor } = event;
  const credential = actor.type === "user" ? actor.credential : null;
  const userAgent = event.context?.userAgent ?? null;
  const rows = await sql.query<{ id: string }>(
    `INSERT INTO ${quoteIdent(schema)}.audit_events
       (occurred_at, type, actor_type, actor_user_id, actor_issuer,
        credential_kind, credential_id, subject_user_id, ip, user_agent, data)
     VALUES (coalesce($1::timestamptz, now()), $2, $3, $4::uuid, $5, $6, $7,
             $8::uuid, $9::inet, $10, $11::text::jsonb)
     RETURNING id::text AS id`,
    [
      event.occurredAt ?? null,
      event.type,
      actor.type,
      actor.type === "user" ? actor.userId : null,
      actor.type === "idp" ? actor.issuer : null,
      credential?.kind ?? null,
      credential?.id ?? null,
      event.subjectUserId,
      event.context?.ip ?? null,
      userAgent === null
        ? null
        : Array.from(userAgent).slice(0, MAX_USER_AGENT_LENGTH).join(""),
      JSON.stringify(event.data),
    ],
  );
  const id = rows[0]?.id;
  if (id === undefined) throw new Error("INSERT … RETURNING returned no row.");
  return id;
}
