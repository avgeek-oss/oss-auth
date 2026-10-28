import { describe, expect, it } from "vitest";
import { ScimError, parseFilter } from "../../src/scim/index.js";
import { applyProjection, projection } from "../../src/scim/attributes.js";
import { patchGroup, type ScimGroupRow } from "../../src/scim/groups.js";
import { parsePatch, parsePath, scimBoolean } from "../../src/scim/patch.js";
import { patchUser, userFields } from "../../src/scim/users.js";

function scimError(fn: () => unknown): ScimError {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(ScimError);
    return error as ScimError;
  }
  throw new Error("expected a ScimError");
}

describe("parseFilter", () => {
  it("parses eq comparisons joined with and", () => {
    expect(parseFilter('userName eq "ada@example.com"')).toEqual([
      { path: "username", value: "ada@example.com" },
    ]);
    expect(parseFilter('externalId eq "x\\"y" and USERNAME EQ "a"')).toEqual([
      { path: "externalid", value: 'x"y' },
      { path: "username", value: "a" },
    ]);
    expect(
      parseFilter('urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"'),
    ).toEqual([{ path: "username", value: "a" }]);
    expect(parseFilter('emails.value eq "a@b.c"')).toEqual([
      { path: "emails.value", value: "a@b.c" },
    ]);
    expect(parseFilter('emails[type eq "work"].value eq "a@b.c"')).toEqual([
      { path: 'emails[type eq "work"].value', value: "a@b.c" },
    ]);
    expect(parseFilter('displayName eq "posted-admins"')).toEqual([
      { path: "displayname", value: "posted-admins" },
    ]);
  });

  it.each([
    ['userName ne "a"', /ne operator/],
    ['userName co "a"', /co operator/],
    ['userName sw "a"', /sw operator/],
    ["userName pr", /pr operator/],
    ['meta.lastModified gt "2026-01-01"', /gt operator/],
    ['userName eq "a" or userName eq "b"', /or is not supported/],
    ['not (userName eq "a")', /not is not supported/],
    ['(userName eq "a")', /Grouping/],
    ["userName eq a", /quoted strings/],
    ["userName eq true", /quoted strings/],
    ['userName eq "unterminated', /unterminated/],
    ['userName like "a"', /not an operator/],
    ['userName eq "a" and', /attribute name/],
    ['userName eq "a" xor userName eq "b"', /Unexpected/],
    ['emails[type ne "work"].value eq "a"', /Value filters/],
    ['user!name eq "a"', /attribute path/],
    ["", /attribute name/],
  ])("rejects %s", (filter, message) => {
    const error = scimError(() => parseFilter(filter));
    expect(error.status).toBe(400);
    expect(error.scimType).toBe("invalidFilter");
    expect(error.message).toMatch(message);
  });

  it("limits length and conditions", () => {
    expect(
      scimError(() => parseFilter(`userName eq "${"a".repeat(1100)}"`))
        .scimType,
    ).toBe("invalidFilter");
    const many = Array.from(
      { length: 12 },
      (_, i) => `userName eq "${i}"`,
    ).join(" and ");
    expect(scimError(() => parseFilter(many)).message).toMatch(/too many/);
  });
});

describe("attribute selection", () => {
  const user = {
    schemas: ["s"],
    id: "1",
    userName: "ada",
    name: { givenName: "Ada", familyName: "Lovelace" },
    emails: [{ value: "a@b.c", type: "work", primary: true }],
    active: true,
    meta: { resourceType: "User" },
  };

  it("keeps everything by default", () => {
    expect(applyProjection(user, projection({}))).toEqual(user);
  });

  it("keeps only the requested attributes, plus schemas and id", () => {
    expect(
      applyProjection(
        user,
        projection({ attributes: "userName, name.givenName" }),
      ),
    ).toEqual({
      schemas: ["s"],
      id: "1",
      userName: "ada",
      name: { givenName: "Ada" },
    });
    expect(
      applyProjection(
        user,
        projection({
          attributes: "urn:ietf:params:scim:schemas:core:2.0:User:emails.value",
        }),
      ),
    ).toEqual({ schemas: ["s"], id: "1", emails: [{ value: "a@b.c" }] });
  });

  it("drops excluded attributes, never id", () => {
    expect(
      applyProjection(
        user,
        projection({ excludedAttributes: "emails,meta,id" }),
      ),
    ).toEqual({
      schemas: ["s"],
      id: "1",
      userName: "ada",
      name: user.name,
      active: true,
    });
  });
});

describe("PATCH parsing", () => {
  it("accepts ops in any case and both path forms", () => {
    expect(
      parsePatch({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          { op: "Replace", path: "active", value: "False" },
          { op: "ADD", value: { displayName: "x" } },
          { op: "remove", path: "name.givenName" },
        ],
      }),
    ).toEqual([
      { op: "replace", path: "active", value: "False" },
      { op: "add", path: null, value: { displayName: "x" } },
      { op: "remove", path: "name.givenName", value: undefined },
    ]);
  });

  it.each([
    [null, "invalidSyntax"],
    [
      { schemas: ["other"], Operations: [{ op: "add", path: "a", value: 1 }] },
      "invalidSyntax",
    ],
    [{ Operations: [] }, "invalidSyntax"],
    [{ Operations: [{ op: "move", path: "a" }] }, "invalidSyntax"],
    [{ Operations: [{ op: "remove" }] }, "noTarget"],
    [{ Operations: [{ op: "replace", value: "x" }] }, "invalidValue"],
  ])("rejects %j", (body, scimType) => {
    expect(scimError(() => parsePatch(body)).scimType).toBe(scimType);
  });

  it("parses paths, URNs and value filters", () => {
    expect(parsePath('emails[type eq "work"].value')).toEqual({
      attribute: "emails",
      sub: "value",
      filter: { attribute: "type", value: "work" },
      extension: false,
    });
    expect(
      parsePath("urn:ietf:params:scim:schemas:core:2.0:User:name.givenName"),
    ).toMatchObject({
      attribute: "name",
      sub: "givenname",
    });
    expect(
      parsePath(
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
      ),
    ).toMatchObject({ extension: true });
    expect(parsePath('members[value eq "abc"]')).toMatchObject({
      attribute: "members",
      filter: { attribute: "value", value: "abc" },
    });
    for (const bad of [
      "",
      "a b",
      "emails[type",
      "emails[type eq work]",
      "a..b",
    ])
      expect(scimError(() => parsePath(bad)).scimType).toBe("invalidPath");
  });

  it("reads SCIM booleans, including Entra's strings", () => {
    expect(scimBoolean(true, "active")).toBe(true);
    expect(scimBoolean("True", "active")).toBe(true);
    expect(scimBoolean("FALSE", "active")).toBe(false);
    for (const bad of ["yes", 1, null, {}])
      expect(scimError(() => scimBoolean(bad, "active")).scimType).toBe(
        "invalidValue",
      );
  });
});

describe("user attributes", () => {
  const body = {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: " ada@example.com ",
    externalId: "ext-1",
    name: { givenName: "Ada", familyName: "Lovelace" },
    emails: [
      { value: "home@example.com", type: "home" },
      { value: "ada@example.com", type: "work" },
    ],
    active: "True",
    title: "ignored",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      department: "x",
    },
  };

  it("reads the core attributes and ignores the rest", () => {
    expect(userFields(body)).toEqual({
      userName: "ada@example.com",
      externalId: "ext-1",
      givenName: "Ada",
      familyName: "Lovelace",
      displayName: "Ada Lovelace",
      email: "ada@example.com",
      active: true,
    });
  });

  it("prefers the primary email, then work, then the first", () => {
    const pick = (emails: unknown) =>
      userFields({ userName: "a", emails }).email;
    expect(
      pick([
        { value: "w@x", type: "work" },
        { value: "p@x", primary: true },
      ]),
    ).toBe("p@x");
    expect(
      pick([
        { value: "o@x", type: "other" },
        { value: "w@x", type: "work" },
      ]),
    ).toBe("w@x");
    expect(pick([{ value: "o@x", type: "other" }])).toBe("o@x");
    expect(pick([])).toBeNull();
  });

  it("keeps externalId and active from the current user when a PUT leaves them out", () => {
    const current = userFields(body);
    expect(
      userFields({ userName: "ada" }, { ...current, active: false }),
    ).toMatchObject({
      externalId: "ext-1",
      active: false,
      givenName: null,
    });
  });

  it.each([
    [{}, /userName is required/],
    [{ userName: "  " }, /userName is required/],
    [{ userName: 5 }, /userName must be a string/],
    [{ userName: "a", name: "Ada" }, /name must be an object/],
    [{ userName: "a", emails: "a@b" }, /emails must be an array/],
    [{ userName: "a", active: "maybe" }, /active must be true or false/],
    [{ userName: "a".repeat(321) }, /longer than 320/],
    [[], /User object/],
  ])("rejects %j", (bad, message) => {
    expect(scimError(() => userFields(bad)).message).toMatch(message);
  });

  it("applies Entra's path-less value objects and string booleans", () => {
    const resource = {
      userName: "ada",
      name: { givenName: "Ada" },
      emails: [{ value: "a@x", type: "work", primary: true }],
      active: true,
    };
    const out = patchUser(resource, [
      {
        op: "replace",
        path: null,
        value: {
          active: "False",
          "name.familyName": "L",
          displayName: "Ada L",
        },
      },
      { op: "add", path: 'emails[type eq "work"].value', value: "new@x" },
      { op: "add", path: 'emails[type eq "home"].value', value: "home@x" },
      {
        op: "replace",
        path: null,
        value: {
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department":
            "x",
        },
      },
      {
        op: "replace",
        path: "urn:ietf:params:scim:schemas:core:2.0:User:userName",
        value: "ada2",
      },
      { op: "add", path: "phoneNumbers", value: [{ value: "1" }] },
    ]);
    expect(userFields(out)).toEqual({
      userName: "ada2",
      externalId: null,
      givenName: "Ada",
      familyName: "L",
      displayName: "Ada L",
      email: "new@x",
      active: false,
    });
    expect(resource.active).toBe(true);
  });

  it("removes attributes and refuses to remove userName", () => {
    const resource = {
      userName: "a",
      displayName: "A",
      name: { givenName: "G" },
      emails: [{ value: "e@x", type: "work" }],
    };
    const out = patchUser(resource, [
      { op: "remove", path: "displayName", value: undefined },
      { op: "remove", path: "name.givenName", value: undefined },
      { op: "remove", path: 'emails[type eq "work"]', value: undefined },
      { op: "remove", path: "active", value: undefined },
    ]);
    expect(userFields(out)).toMatchObject({
      displayName: null,
      givenName: null,
      email: null,
    });
    expect(
      scimError(() =>
        patchUser(resource, [
          { op: "remove", path: "userName", value: undefined },
        ]),
      ).scimType,
    ).toBe("mutability");
  });
});

describe("group PATCH", () => {
  const A = "00000000-0000-4000-8000-00000000000a";
  const B = "00000000-0000-4000-8000-00000000000b";
  const C = "00000000-0000-4000-8000-00000000000c";
  const group: ScimGroupRow = {
    id: "g",
    displayName: "posted-admins",
    externalId: "pk-1",
    createdAt: new Date(),
    updatedAt: new Date(),
    members: [
      { value: A, display: null },
      { value: B, display: null },
    ],
  };

  it("adds, removes by filter or list, and replaces members", () => {
    expect(
      patchGroup(group, [{ op: "add", path: "members", value: [{ value: C }] }])
        .members,
    ).toEqual([A, B, C]);
    expect(
      patchGroup(group, [
        { op: "remove", path: `members[value eq "${A}"]`, value: undefined },
      ]).members,
    ).toEqual([B]);
    expect(
      patchGroup(group, [
        { op: "remove", path: "members", value: [{ value: B }] },
      ]).members,
    ).toEqual([A]);
    expect(
      patchGroup(group, [{ op: "remove", path: "members", value: undefined }])
        .members,
    ).toEqual([]);
    expect(
      patchGroup(group, [
        { op: "replace", path: "members", value: [{ value: C }] },
      ]).members,
    ).toEqual([C]);
  });

  it("renames without touching members, also path-less", () => {
    expect(
      patchGroup(group, [
        {
          op: "replace",
          path: null,
          value: { id: "g", displayName: "posted-members" },
        },
      ]),
    ).toEqual({
      displayName: "posted-members",
      externalId: "pk-1",
      members: null,
    });
    expect(
      patchGroup(group, [{ op: "replace", path: "externalId", value: "pk-2" }])
        .externalId,
    ).toBe("pk-2");
    expect(
      patchGroup(group, [
        { op: "remove", path: "externalId", value: undefined },
      ]).externalId,
    ).toBeNull();
  });

  it("rejects bad member values and paths", () => {
    expect(
      scimError(() =>
        patchGroup(group, [
          { op: "add", path: "members", value: [{ value: "nope" }] },
        ]),
      ).scimType,
    ).toBe("invalidValue");
    expect(
      scimError(() =>
        patchGroup(group, [
          { op: "add", path: `members[value eq "${A}"]`, value: {} },
        ]),
      ).scimType,
    ).toBe("invalidPath");
    expect(
      scimError(() =>
        patchGroup(group, [
          { op: "remove", path: "displayName", value: undefined },
        ]),
      ).scimType,
    ).toBe("mutability");
  });
});
