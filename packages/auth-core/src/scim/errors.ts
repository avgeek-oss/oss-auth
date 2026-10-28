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
