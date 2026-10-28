// Request bodies as each provider sends them, from their documentation and,
// for authentik 2026.8, its default SCIM mappings and clients
// (providers/scim/clients/users.py and groups.py).

const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

export const authentik = {
  /** POST /Users and PUT /Users/{id}: authentik never PATCHes users. */
  user: (overrides: { active?: boolean; name?: string } = {}) => ({
    schemas: [USER],
    userName: "ada@example.com",
    name: {
      formatted: overrides.name ?? "Ada Lovelace",
      givenName: "Ada",
      familyName: "Lovelace",
    },
    displayName: overrides.name ?? "Ada Lovelace",
    photos: [],
    locale: "en",
    active: overrides.active ?? true,
    emails: [{ value: "ada@example.com", type: "other", primary: true }],
    // The hashed user id, which is also the OIDC sub in the default mode.
    externalId:
      "f7a6c3e1b2d4a5968778695a4b3c2d1e0f9e8d7c6b5a4938271605f4e3d2c1b0",
  }),
  /** POST /Groups: externalId is authentik's group pk. */
  group: (members: string[]) => ({
    schemas: [GROUP],
    displayName: "posted-admins",
    externalId: "6b0e2f8a-3c4d-4e5f-9a1b-2c3d4e5f6a7b",
    members: members.map((value) => ({ value })),
  }),
  addMember: (id: string) => ({
    schemas: [PATCH],
    Operations: [{ op: "add", path: "members", value: [{ value: id }] }],
  }),
  removeMember: (id: string) => ({
    schemas: [PATCH],
    Operations: [{ op: "remove", path: `members[value eq "${id}"]` }],
  }),
  /** Attribute changes: replace without a path, always with externalId. */
  replaceGroup: () => ({
    schemas: [PATCH],
    Operations: [
      {
        op: "replace",
        value: {
          displayName: "posted-admins",
          externalId: "6b0e2f8a-3c4d-4e5f-9a1b-2c3d4e5f6a7b",
        },
      },
    ],
  }),
};

export const okta = {
  /** POST /Users, after a GET filter on userName finds nothing. */
  user: () => ({
    schemas: [USER],
    userName: "grace@example.com",
    name: { givenName: "Grace", familyName: "Hopper" },
    emails: [{ primary: true, value: "grace@example.com", type: "work" }],
    displayName: "Grace Hopper",
    locale: "en-US",
    externalId: "00u1a2b3c4d5e6f7g8h9",
    groups: [],
    password: "ignored-by-this-server",
    active: true,
  }),
  /** PUT /Users/{id} on a profile change. */
  replace: (id: string) => ({
    schemas: [USER],
    id,
    userName: "grace@example.com",
    name: { givenName: "Grace", familyName: "Brewster Hopper" },
    emails: [{ primary: true, value: "grace@example.com", type: "work" }],
    displayName: "Grace Brewster Hopper",
    locale: "en-US",
    externalId: "00u1a2b3c4d5e6f7g8h9",
    groups: [],
    active: true,
    meta: { resourceType: "User" },
  }),
  /** Deactivation: PATCH replace with a value object. */
  deactivate: () => ({
    schemas: [PATCH],
    Operations: [{ op: "replace", value: { active: false } }],
  }),
  group: () => ({
    schemas: [GROUP],
    displayName: "posted-members",
    members: [],
  }),
  addMember: (id: string) => ({
    schemas: [PATCH],
    Operations: [
      {
        op: "add",
        path: "members",
        value: [{ value: id, display: "grace@example.com" }],
      },
    ],
  }),
  removeMember: (id: string) => ({
    schemas: [PATCH],
    Operations: [{ op: "remove", path: `members[value eq "${id}"]` }],
  }),
  rename: (id: string) => ({
    schemas: [PATCH],
    Operations: [
      { op: "replace", value: { id, displayName: "posted-admins" } },
    ],
  }),
};

export const entra = {
  /** POST /Users, with the enterprise extension. */
  user: () => ({
    schemas: [USER, ENTERPRISE],
    externalId: "9c5d8f2e-entra-object",
    userName: "Linus@Example.com",
    active: true,
    addresses: [{ primary: true, type: "work", formatted: "Helsinki" }],
    displayName: "Linus Torvalds",
    emails: [{ primary: true, type: "work", value: "linus@example.com" }],
    meta: { resourceType: "User" },
    name: {
      formatted: "Linus Torvalds",
      familyName: "Torvalds",
      givenName: "Linus",
    },
    title: "Engineer",
    [ENTERPRISE]: { department: "Kernel", manager: { value: "boss" } },
  }),
  /** Attribute updates: capitalised ops, paths and path-less objects. */
  update: () => ({
    schemas: [PATCH],
    Operations: [
      { op: "Replace", path: "displayName", value: "Linus B. Torvalds" },
      {
        op: "Replace",
        path: 'emails[type eq "work"].value',
        value: "linus@kernel.example.com",
      },
      {
        op: "Add",
        value: { "name.givenName": "Linus Benedict", title: "Maintainer" },
      },
      { op: "Replace", path: `${ENTERPRISE}:department`, value: "Core" },
    ],
  }),
  /** Soft delete: a string boolean. */
  disable: () => ({
    schemas: [PATCH],
    Operations: [{ op: "Replace", path: "active", value: "False" }],
  }),
  enable: () => ({
    schemas: [PATCH],
    Operations: [{ op: "Replace", path: "active", value: "True" }],
  }),
  group: () => ({
    schemas: [GROUP],
    externalId: "entra-group-object",
    displayName: "posted-viewers",
    members: [],
  }),
  addMember: (id: string) => ({
    schemas: [PATCH],
    Operations: [{ op: "Add", path: "members", value: [{ value: id }] }],
  }),
  removeMember: (id: string) => ({
    schemas: [PATCH],
    Operations: [{ op: "Remove", path: "members", value: [{ value: id }] }],
  }),
};
