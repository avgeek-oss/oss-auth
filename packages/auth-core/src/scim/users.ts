import { badRequest } from "./errors.js";
import { SCHEMAS } from "./discovery.js";
import {
  parsePath,
  scimBoolean,
  type AttributePath,
  type PatchOperation,
} from "./patch.js";

/** The user attributes this server stores. */
export interface ScimUserFields {
  readonly userName: string;
  readonly externalId: string | null;
  readonly givenName: string | null;
  readonly familyName: string | null;
  readonly displayName: string | null;
  readonly email: string | null;
  readonly active: boolean;
}

/** A user row as SCIM reads it. */
export interface ScimUserRow extends ScimUserFields {
  readonly id: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** The columns {@link ScimUserRow} is read with. */
export const USER_COLUMNS = `id, user_name AS "userName", external_id AS "externalId",
  given_name AS "givenName", family_name AS "familyName",
  display_name AS "displayName", email, active,
  created_at AS "createdAt", updated_at AS "updatedAt"`;

function text(value: unknown, attribute: string, max: number): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string")
    throw badRequest(`${attribute} must be a string.`, "invalidValue");
  const trimmed = value.trim();
  if (trimmed === "") return null;
  if (Array.from(trimmed).length > max)
    throw badRequest(
      `${attribute} is longer than ${max} characters.`,
      "invalidValue",
    );
  return trimmed;
}

interface EmailEntry {
  value?: unknown;
  type?: unknown;
  primary?: unknown;
}

/** The email to keep: the primary one, else the work one, else the first. */
function chooseEmail(emails: unknown): string | null {
  if (emails === undefined || emails === null) return null;
  if (!Array.isArray(emails))
    throw badRequest("emails must be an array.", "invalidValue");
  const entries = emails.filter(
    (e): e is EmailEntry => typeof e === "object" && e !== null,
  );
  const chosen =
    entries.find(
      (e) => e.primary === true || e.primary === "True" || e.primary === "true",
    ) ??
    entries.find(
      (e) => typeof e.type === "string" && e.type.toLowerCase() === "work",
    ) ??
    entries[0];
  return chosen ? text(chosen.value, "emails.value", 320) : null;
}

/**
 * Reads a User resource from a POST or PUT body, or a document a PATCH
 * produced. Unknown attributes and schema extensions are ignored.
 *
 * `current` supplies values a PUT leaves out where leaving them out should
 * not clear them: `externalId` (an identifier the provider may not resend)
 * and `active`.
 */
export function userFields(
  body: unknown,
  current?: ScimUserFields,
): ScimUserFields {
  if (typeof body !== "object" || body === null || Array.isArray(body))
    throw badRequest("The body must be a User object.", "invalidSyntax");
  const doc = body as Record<string, unknown>;
  const get = (name: string) => {
    const key = Object.keys(doc).find(
      (k) => k.toLowerCase() === name.toLowerCase(),
    );
    return key === undefined ? undefined : doc[key];
  };
  const userName = text(get("userName"), "userName", 320);
  if (userName === null)
    throw badRequest("userName is required.", "invalidValue");
  const name = get("name");
  if (
    name !== undefined &&
    name !== null &&
    (typeof name !== "object" || Array.isArray(name))
  )
    throw badRequest("name must be an object.", "invalidValue");
  const nameDoc = (name ?? {}) as Record<string, unknown>;
  const nameGet = (sub: string) => {
    const key = Object.keys(nameDoc).find(
      (k) => k.toLowerCase() === sub.toLowerCase(),
    );
    return key === undefined ? undefined : nameDoc[key];
  };
  const givenName = text(nameGet("givenName"), "name.givenName", 256);
  const familyName = text(nameGet("familyName"), "name.familyName", 256);
  const formatted = text(nameGet("formatted"), "name.formatted", 256);
  const joined = [givenName, familyName].filter((p) => p !== null).join(" ");
  const displayName =
    text(get("displayName"), "displayName", 256) ??
    formatted ??
    (joined === "" ? null : joined);
  const externalIdRaw = get("externalId");
  const activeRaw = get("active");
  return {
    userName,
    externalId:
      externalIdRaw === undefined
        ? (current?.externalId ?? null)
        : text(externalIdRaw, "externalId", 255),
    givenName,
    familyName,
    displayName,
    email: chooseEmail(get("emails")),
    active:
      activeRaw === undefined || activeRaw === null
        ? (current?.active ?? true)
        : scimBoolean(activeRaw, "active"),
  };
}

/** The SCIM representation of a user. */
export function userResource(
  row: ScimUserRow,
  base: string,
): Record<string, unknown> {
  const name: Record<string, string> = {};
  if (row.givenName !== null) name.givenName = row.givenName;
  if (row.familyName !== null) name.familyName = row.familyName;
  const formatted = [row.givenName, row.familyName]
    .filter((p) => p !== null)
    .join(" ");
  if (formatted !== "") name.formatted = formatted;
  return {
    schemas: [SCHEMAS.user],
    id: row.id,
    ...(row.externalId === null ? {} : { externalId: row.externalId }),
    userName: row.userName,
    ...(Object.keys(name).length > 0 ? { name } : {}),
    ...(row.displayName === null ? {} : { displayName: row.displayName }),
    emails:
      row.email === null
        ? []
        : [{ value: row.email, type: "work", primary: true }],
    active: row.active,
    meta: {
      resourceType: "User",
      created: row.createdAt.toISOString(),
      lastModified: row.updatedAt.toISOString(),
      location: `${base}/Users/${row.id}`,
    },
  };
}

type Doc = Record<string, unknown>;

function keyOf(doc: Doc, attribute: string): string {
  return (
    Object.keys(doc).find((k) => k.toLowerCase() === attribute) ?? attribute
  );
}

function emailsOf(doc: Doc): EmailEntry[] {
  const value = doc[keyOf(doc, "emails")];
  return Array.isArray(value)
    ? value
        .filter((e): e is EmailEntry => typeof e === "object" && e !== null)
        .map((e) => ({ ...e }))
    : [];
}

function applyToPath(
  doc: Doc,
  op: PatchOperation["op"],
  path: AttributePath,
  value: unknown,
): void {
  if (path.extension) return;
  const { attribute, sub, filter } = path;
  if (attribute === "emails") {
    const emails = emailsOf(doc);
    if (filter !== null) {
      if (filter.attribute !== "type")
        throw badRequest("emails can only be filtered by type.", "invalidPath");
      const matches = (e: EmailEntry) =>
        typeof e.type === "string" &&
        e.type.toLowerCase() === filter.value.toLowerCase();
      const index = emails.findIndex(matches);
      if (op === "remove") {
        if (index !== -1) emails.splice(index, 1);
      } else if (sub === null || sub === "value") {
        const entryValue = sub === null ? (value as EmailEntry)?.value : value;
        if (index === -1)
          emails.push({
            type: filter.value,
            value: entryValue,
            primary: emails.length === 0,
          });
        else emails[index] = { ...emails[index], value: entryValue };
      } else if (sub === "primary" && index !== -1) {
        emails[index] = { ...emails[index], primary: value };
      }
      doc[keyOf(doc, "emails")] = emails;
      return;
    }
    if (op === "remove") doc[keyOf(doc, "emails")] = [];
    else if (sub === "value")
      doc[keyOf(doc, "emails")] = [{ value, type: "work", primary: true }];
    else if (op === "add" && Array.isArray(value))
      doc[keyOf(doc, "emails")] = [...value, ...emails];
    else doc[keyOf(doc, "emails")] = value;
    return;
  }
  if (attribute === "name") {
    const current = doc[keyOf(doc, "name")];
    const name: Doc =
      typeof current === "object" && current !== null
        ? { ...(current as Doc) }
        : {};
    if (sub === null) {
      if (op === "remove") doc[keyOf(doc, "name")] = {};
      else if (typeof value === "object" && value !== null)
        doc[keyOf(doc, "name")] =
          op === "add" ? { ...name, ...(value as Doc) } : value;
      else throw badRequest("name must be an object.", "invalidValue");
      return;
    }
    if (op === "remove") delete name[keyOf(name, sub)];
    else name[keyOf(name, sub)] = value;
    doc[keyOf(doc, "name")] = name;
    return;
  }
  if (sub !== null || filter !== null) return;
  if (attribute === "username" && op === "remove")
    throw badRequest("userName cannot be removed.", "mutability");
  if (attribute === "active" && op === "remove") return;
  if (!["username", "externalid", "displayname", "active"].includes(attribute))
    return;
  if (op === "remove") delete doc[keyOf(doc, attribute)];
  else doc[keyOf(doc, attribute)] = value;
}

/**
 * Applies PATCH operations to a user's SCIM representation and returns the
 * result. Paths may be `active`, `userName`, `externalId`, `displayName`,
 * `name`, `name.<part>`, `emails`, `emails.value` or
 * `emails[type eq "work"].value`, with or without the core schema URN.
 * Operations without a path apply each key of their value object as a
 * path, as Entra and Okta send them. Unknown attributes and extension
 * attributes are ignored.
 */
export function patchUser(
  resource: Doc,
  operations: readonly PatchOperation[],
): Doc {
  const doc: Doc = structuredClone(resource);
  for (const operation of operations) {
    if (operation.path !== null) {
      applyToPath(
        doc,
        operation.op,
        parsePath(operation.path),
        operation.value,
      );
      continue;
    }
    for (const [key, value] of Object.entries(operation.value as Doc)) {
      if (
        /^urn:/i.test(key) &&
        !/^urn:ietf:params:scim:schemas:core:/i.test(key)
      )
        continue;
      applyToPath(doc, operation.op, parsePath(key), value);
    }
  }
  return doc;
}
