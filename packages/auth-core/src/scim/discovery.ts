/** Schema URNs this server speaks. */
export const SCHEMAS = {
  user: "urn:ietf:params:scim:schemas:core:2.0:User",
  group: "urn:ietf:params:scim:schemas:core:2.0:Group",
  list: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  patch: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
  config: "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
  resourceType: "urn:ietf:params:scim:schemas:core:2.0:ResourceType",
  schema: "urn:ietf:params:scim:schemas:core:2.0:Schema",
  enterprise: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
} as const;

/** The most resources one list response returns. */
export const MAX_RESULTS = 200;

/** The `/ServiceProviderConfig` document. */
export function serviceProviderConfig(base: string) {
  return {
    schemas: [SCHEMAS.config],
    documentationUri: "https://github.com/avgeek-oss/oss-auth",
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: MAX_RESULTS },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: "oauthbearertoken",
        name: "Bearer token",
        description: "A static bearer token from <APP>_SCIM_TOKENS.",
        primary: true,
      },
    ],
    meta: {
      resourceType: "ServiceProviderConfig",
      location: `${base}/ServiceProviderConfig`,
    },
  };
}

/** The `/ResourceTypes` entries. */
export function resourceTypes(base: string) {
  return [
    {
      schemas: [SCHEMAS.resourceType],
      id: "User",
      name: "User",
      endpoint: "/Users",
      description: "A person who may use the app.",
      schema: SCHEMAS.user,
      schemaExtensions: [],
      meta: {
        resourceType: "ResourceType",
        location: `${base}/ResourceTypes/User`,
      },
    },
    {
      schemas: [SCHEMAS.resourceType],
      id: "Group",
      name: "Group",
      endpoint: "/Groups",
      description: "A group whose display name may map to a role.",
      schema: SCHEMAS.group,
      schemaExtensions: [],
      meta: {
        resourceType: "ResourceType",
        location: `${base}/ResourceTypes/Group`,
      },
    },
  ];
}

const attribute = (
  name: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> => ({
  name,
  type: "string",
  multiValued: false,
  required: false,
  caseExact: false,
  mutability: "readWrite",
  returned: "default",
  uniqueness: "none",
  ...extra,
});

/** The `/Schemas` entries for the attributes this server stores. */
export function schemas(base: string) {
  return [
    {
      schemas: [SCHEMAS.schema],
      id: SCHEMAS.user,
      name: "User",
      description: "User account",
      attributes: [
        attribute("userName", { required: true, uniqueness: "server" }),
        attribute("externalId", { caseExact: true }),
        attribute("name", {
          type: "complex",
          subAttributes: [
            attribute("formatted"),
            attribute("givenName"),
            attribute("familyName"),
          ],
        }),
        attribute("displayName"),
        attribute("emails", {
          type: "complex",
          multiValued: true,
          subAttributes: [
            attribute("value"),
            attribute("type", { canonicalValues: ["work", "home", "other"] }),
            attribute("primary", { type: "boolean" }),
          ],
        }),
        attribute("active", { type: "boolean" }),
      ],
      meta: {
        resourceType: "Schema",
        location: `${base}/Schemas/${SCHEMAS.user}`,
      },
    },
    {
      schemas: [SCHEMAS.schema],
      id: SCHEMAS.group,
      name: "Group",
      description: "Group",
      attributes: [
        attribute("displayName", { required: true, uniqueness: "server" }),
        attribute("externalId", { caseExact: true }),
        attribute("members", {
          type: "complex",
          multiValued: true,
          subAttributes: [
            attribute("value", { mutability: "immutable", caseExact: true }),
            attribute("display", { mutability: "readOnly" }),
            attribute("$ref", { type: "reference", mutability: "immutable" }),
            attribute("type", { mutability: "immutable" }),
          ],
        }),
      ],
      meta: {
        resourceType: "Schema",
        location: `${base}/Schemas/${SCHEMAS.group}`,
      },
    },
  ];
}
