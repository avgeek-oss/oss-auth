import { badRequest } from "./errors.js";
import { SCHEMAS } from "./discovery.js";

/** One PATCH operation, with `op` lowercased. */
export interface PatchOperation {
  readonly op: "add" | "replace" | "remove";
  readonly path: string | null;
  readonly value: unknown;
}

/** A parsed attribute path: `name.givenName`, `emails[type eq "work"].value`. */
export interface AttributePath {
  /** Lowercased attribute, such as `name` or `emails`. */
  readonly attribute: string;
  /** Lowercased sub-attribute, such as `givenname`, or `null`. */
  readonly sub: string | null;
  /** The value filter, such as `{ attribute: "type", value: "work" }`. */
  readonly filter: {
    readonly attribute: string;
    readonly value: string;
  } | null;
  /** True for a path in a schema extension, which this server ignores. */
  readonly extension: boolean;
}

const PATH =
  /^([A-Za-z$][\w$-]*)(?:\[\s*([A-Za-z$][\w$-]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\])?(?:\.([A-Za-z$][\w$-]*))?$/i;

/**
 * Parses a PATCH `path` or a key of a path-less value object. Schema URN
 * prefixes are accepted: the core User and Group schema is stripped, and any
 * other URN (such as the enterprise extension) marks the path as an
 * extension.
 *
 * @throws 400 `invalidPath` for anything else.
 */
export function parsePath(path: string): AttributePath {
  let rest = path.trim();
  let extension = false;
  if (/^urn:/i.test(rest)) {
    const core = /^urn:ietf:params:scim:schemas:core:2\.0:(?:user|group):/i;
    if (core.test(rest)) rest = rest.replace(core, "");
    else {
      extension = true;
      const lastColon = rest.lastIndexOf(":");
      rest = rest.slice(lastColon + 1) || "extension";
    }
  }
  const match = PATH.exec(rest);
  if (!match)
    throw badRequest(`"${path}" is not a supported path.`, "invalidPath");
  const [, attribute = "", filterAttribute, filterValue, sub] = match;
  return {
    attribute: attribute.toLowerCase(),
    sub: sub ? sub.toLowerCase() : null,
    filter:
      filterAttribute === undefined
        ? null
        : {
            attribute: filterAttribute.toLowerCase(),
            value: JSON.parse(`"${filterValue ?? ""}"`) as string,
          },
    extension,
  };
}

/**
 * Reads a PATCH request body: the PatchOp schema and its `Operations`, with
 * `op` case-insensitive, as Entra sends `Replace` and `Add`.
 */
export function parsePatch(body: unknown): PatchOperation[] {
  const doc = body as { schemas?: unknown; Operations?: unknown } | null;
  if (typeof doc !== "object" || doc === null)
    throw badRequest("The body must be a PatchOp object.", "invalidSyntax");
  if (Array.isArray(doc.schemas) && !doc.schemas.includes(SCHEMAS.patch))
    throw badRequest(`schemas must include ${SCHEMAS.patch}.`, "invalidSyntax");
  const operations = doc.Operations;
  if (!Array.isArray(operations) || operations.length === 0)
    throw badRequest("Operations must be a non-empty array.", "invalidSyntax");
  if (operations.length > 1000)
    throw badRequest("Too many operations in one request.", "tooMany");
  return operations.map((raw: unknown) => {
    const operation = raw as { op?: unknown; path?: unknown; value?: unknown };
    const op =
      typeof operation?.op === "string" ? operation.op.toLowerCase() : "";
    if (op !== "add" && op !== "replace" && op !== "remove")
      throw badRequest(
        `"${String(operation?.op)}" is not a PATCH op; use add, replace or remove.`,
        "invalidSyntax",
      );
    const path =
      typeof operation.path === "string" && operation.path.trim() !== ""
        ? operation.path
        : null;
    if (path === null && op === "remove")
      throw badRequest("remove needs a path.", "noTarget");
    if (
      path === null &&
      (typeof operation.value !== "object" || operation.value === null)
    )
      throw badRequest(
        "An operation without a path needs an object value.",
        "invalidValue",
      );
    return { op, path, value: operation.value };
  });
}

/**
 * SCIM booleans, including the `"True"` and `"False"` strings Entra sends.
 *
 * @throws 400 `invalidValue` for anything else.
 */
export function scimBoolean(value: unknown, attribute: string): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const lowered = value.trim().toLowerCase();
    if (lowered === "true") return true;
    if (lowered === "false") return false;
  }
  throw badRequest(`${attribute} must be true or false.`, "invalidValue");
}
