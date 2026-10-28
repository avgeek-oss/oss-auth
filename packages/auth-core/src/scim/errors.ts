/** The SCIM error schema URN. */
export const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

/** `scimType` values this server uses (RFC 7644 §3.12). */
export type ScimType =
  | "invalidFilter"
  | "invalidSyntax"
  | "invalidPath"
  | "invalidValue"
  | "noTarget"
  | "uniqueness"
  | "mutability"
  | "tooMany";

/**
 * A SCIM request failed. It becomes an RFC 7644 Error response: `status` as
 * a string, `scimType` when there is one, and `detail`.
 */
export class ScimError extends Error {
  readonly status: number;
  readonly scimType: ScimType | null;

  constructor(
    status: number,
    detail: string,
    scimType: ScimType | null = null,
  ) {
    super(detail);
    this.name = "ScimError";
    this.status = status;
    this.scimType = scimType;
  }

  /** The response body. */
  toJSON(): Record<string, unknown> {
    return {
      schemas: [SCIM_ERROR_SCHEMA],
      status: String(this.status),
      ...(this.scimType ? { scimType: this.scimType } : {}),
      detail: this.message,
    };
  }
}

export const badRequest = (detail: string, scimType: ScimType) =>
  new ScimError(400, detail, scimType);
export const notFound = (what: string) =>
  new ScimError(404, `${what} not found.`);
export const conflict = (detail: string) =>
  new ScimError(409, detail, "uniqueness");

/** Unique indexes SCIM writes can hit, and the attribute each guards. */
const UNIQUE: Readonly<Record<string, string>> = {
  users_user_name_key: "userName",
  users_iss_external_id_key: "externalId",
  scim_groups_display_name_key: "displayName",
  scim_groups_external_id_key: "externalId",
};

/** Column checks SCIM writes can hit, and the attribute each guards. */
const CHECKED: Readonly<Record<string, string>> = {
  users_user_name_check: "userName",
  users_external_id_check: "externalId",
  users_given_name_check: "name.givenName",
  users_family_name_check: "name.familyName",
  users_display_name_check: "displayName",
  users_email_check: "emails.value",
  scim_groups_display_name_check: "displayName",
  scim_groups_external_id_check: "externalId",
};

/**
 * The SCIM answer for a known constraint violation, with a fixed message,
 * or `null` for any other error, which the caller rethrows. The database's
 * own message never reaches the client. Reads the constraint name as `pg`
 * (`constraint`) and Postgres.js (`constraint_name`) report it.
 */
export function constraintError(error: unknown): ScimError | null {
  if (typeof error !== "object" || error === null) return null;
  const { code, constraint, constraint_name } = error as Record<
    string,
    unknown
  >;
  const name =
    typeof constraint === "string"
      ? constraint
      : typeof constraint_name === "string"
        ? constraint_name
        : null;
  if (name === null) return null;
  if (code === "23505" && Object.hasOwn(UNIQUE, name))
    return conflict(`${UNIQUE[name]} must be unique.`);
  if (code === "23514" && Object.hasOwn(CHECKED, name))
    return badRequest(`${CHECKED[name]} is empty or too long.`, "invalidValue");
  return null;
}
