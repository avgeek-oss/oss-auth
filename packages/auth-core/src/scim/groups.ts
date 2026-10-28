import { badRequest } from "./errors.js";
import { SCHEMAS } from "./discovery.js";
import { parsePath, type PatchOperation } from "./patch.js";

/** A group row as SCIM reads it, with its member user ids. */
export interface ScimGroupRow {
  readonly id: string;
  readonly displayName: string;
  readonly externalId: string | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly members: readonly {
    readonly value: string;
    readonly display: string | null;
  }[];
}

/** What a POST, PUT or PATCH sets on a group. `members: null` keeps them. */
export interface ScimGroupChange {
  readonly displayName: string;
  readonly externalId: string | null;
  readonly members: readonly string[] | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function memberIds(value: unknown): string[] {
  if (value === undefined || value === null) return [];
  const entries = Array.isArray(value) ? value : [value];
  return entries.map((entry: unknown) => {
    const id =
      typeof entry === "object" && entry !== null
        ? (entry as { value?: unknown }).value
        : entry;
    if (typeof id !== "string" || !UUID.test(id))
      throw badRequest(
        "Each member needs a value that is a user id.",
        "invalidValue",
      );
    return id.toLowerCase();
  });
}

function textOf(value: unknown, attribute: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string")
    throw badRequest(`${attribute} must be a string.`, "invalidValue");
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

function get(doc: Record<string, unknown>, name: string): unknown {
  const key = Object.keys(doc).find(
    (k) => k.toLowerCase() === name.toLowerCase(),
  );
  return key === undefined ? undefined : doc[key];
}

/**
 * Reads a Group from a POST or PUT body. A PUT without `members` keeps the
 * current members, so a provider renaming a group never empties it; an
 * empty `members` array clears them.
 */
export function groupChange(
  body: unknown,
  current?: ScimGroupRow,
): ScimGroupChange {
  if (typeof body !== "object" || body === null || Array.isArray(body))
    throw badRequest("The body must be a Group object.", "invalidSyntax");
  const doc = body as Record<string, unknown>;
  const displayName = textOf(get(doc, "displayName"), "displayName");
  if (displayName === null)
    throw badRequest("displayName is required.", "invalidValue");
  if (Array.from(displayName).length > 256)
    throw badRequest(
      "displayName is longer than 256 characters.",
      "invalidValue",
    );
  const externalIdRaw = get(doc, "externalId");
  const members = get(doc, "members");
  return {
    displayName,
    externalId:
      externalIdRaw === undefined
        ? (current?.externalId ?? null)
        : textOf(externalIdRaw, "externalId"),
    members: members === undefined ? (current ? null : []) : memberIds(members),
  };
}

/**
 * Applies PATCH operations to a group. Supports `members` add, remove (with
 * or without a value list) and replace, `members[value eq "<id>"]` remove,
 * and `displayName` and `externalId`, also as path-less value objects (as
 * authentik and Okta send renames).
 */
export function patchGroup(
  current: ScimGroupRow,
  operations: readonly PatchOperation[],
): ScimGroupChange {
  let displayName = current.displayName;
  let externalId = current.externalId;
  const members = new Set(current.members.map((m) => m.value));
  let membersChanged = false;

  const apply = (
    op: PatchOperation["op"],
    pathText: string,
    value: unknown,
  ) => {
    const path = parsePath(pathText);
    if (path.extension) return;
    if (path.attribute === "members") {
      membersChanged = true;
      if (path.filter !== null) {
        if (path.filter.attribute !== "value" || op !== "remove")
          throw badRequest(
            'Use remove with members[value eq "<id>"].',
            "invalidPath",
          );
        members.delete(path.filter.value.toLowerCase());
        return;
      }
      if (op === "add") for (const id of memberIds(value)) members.add(id);
      else if (op === "remove") {
        if (value === undefined || value === null) members.clear();
        else for (const id of memberIds(value)) members.delete(id);
      } else {
        members.clear();
        for (const id of memberIds(value)) members.add(id);
      }
      return;
    }
    if (path.sub !== null || path.filter !== null) return;
    if (path.attribute === "displayname") {
      if (op === "remove")
        throw badRequest("displayName cannot be removed.", "mutability");
      const next = textOf(value, "displayName");
      if (next === null)
        throw badRequest("displayName cannot be empty.", "invalidValue");
      displayName = next;
    } else if (path.attribute === "externalid") {
      externalId = op === "remove" ? null : textOf(value, "externalId");
    }
  };

  for (const operation of operations) {
    if (operation.path !== null) {
      apply(operation.op, operation.path, operation.value);
      continue;
    }
    for (const [key, value] of Object.entries(
      operation.value as Record<string, unknown>,
    )) {
      if (
        key.toLowerCase() === "id" ||
        key.toLowerCase() === "schemas" ||
        key.toLowerCase() === "meta"
      )
        continue;
      if (
        /^urn:/i.test(key) &&
        !/^urn:ietf:params:scim:schemas:core:/i.test(key)
      )
        continue;
      apply(operation.op, key, value);
    }
  }
  return {
    displayName,
    externalId,
    members: membersChanged ? [...members] : null,
  };
}

/** The SCIM representation of a group. */
export function groupResource(
  row: ScimGroupRow,
  base: string,
): Record<string, unknown> {
  return {
    schemas: [SCHEMAS.group],
    id: row.id,
    ...(row.externalId === null ? {} : { externalId: row.externalId }),
    displayName: row.displayName,
    members: row.members.map((m) => ({
      value: m.value,
      $ref: `${base}/Users/${m.value}`,
      type: "User",
      ...(m.display === null ? {} : { display: m.display }),
    })),
    meta: {
      resourceType: "Group",
      created: row.createdAt.toISOString(),
      lastModified: row.updatedAt.toISOString(),
      location: `${base}/Groups/${row.id}`,
    },
  };
}
