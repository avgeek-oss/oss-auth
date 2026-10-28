import { describe, expect, it } from "vitest";
import {
  isRole,
  maxRole,
  minRole,
  resolveRole,
  roleAtLeast,
  roleRank,
  ROLES,
  type Role,
  type RoleMap,
} from "../src/index.js";

describe("roles", () => {
  it("orders viewer < member < admin", () => {
    expect(ROLES).toEqual(["viewer", "member", "admin"]);
    expect(ROLES.map(roleRank)).toEqual([0, 1, 2]);
  });

  it("recognises only the three role names", () => {
    for (const role of ROLES) expect(isRole(role)).toBe(true);
    for (const value of [
      "Admin",
      "owner",
      "",
      " admin",
      null,
      1,
      {},
      ["admin"],
    ])
      expect(isRole(value)).toBe(false);
  });

  it("rejects an unknown role at runtime", () => {
    expect(() => roleRank("owner" as Role)).toThrow(TypeError);
  });

  it("compares roles", () => {
    const table: [Role, Role, boolean][] = [
      ["viewer", "viewer", true],
      ["viewer", "member", false],
      ["member", "viewer", true],
      ["member", "admin", false],
      ["admin", "member", true],
      ["admin", "admin", true],
    ];
    for (const [role, minimum, expected] of table)
      expect(roleAtLeast(role, minimum)).toBe(expected);
  });

  it("takes the lower and the higher of two roles", () => {
    for (const a of ROLES)
      for (const b of ROLES) {
        expect(minRole(a, b)).toBe(roleRank(a) <= roleRank(b) ? a : b);
        expect(maxRole(a, b)).toBe(roleRank(a) >= roleRank(b) ? a : b);
        expect(minRole(a, b)).toBe(minRole(b, a));
        expect(maxRole(a, b)).toBe(maxRole(b, a));
      }
  });
});

describe("resolveRole", () => {
  const groups: RoleMap = {
    claims: ["groups"],
    values: {
      "posted-viewers": "viewer",
      "posted-members": "member",
      "posted-admins": "admin",
    },
  };
  const authentik: RoleMap = {
    claims: ["roles"],
    values: { viewer: "viewer", member: "member", admin: "admin" },
  };

  it("maps a single matching group", () => {
    expect(resolveRole({ groups: ["posted-members"] }, groups)).toBe("member");
    expect(resolveRole({ roles: ["admin"] }, authentik)).toBe("admin");
  });

  it("picks the highest role when several groups match", () => {
    expect(
      resolveRole(
        { groups: ["posted-viewers", "posted-admins", "posted-members"] },
        groups,
      ),
    ).toBe("admin");
    expect(
      resolveRole({ groups: ["posted-members", "posted-viewers"] }, groups),
    ).toBe("member");
  });

  it("accepts a claim given as a single string", () => {
    expect(resolveRole({ groups: "posted-admins" }, groups)).toBe("admin");
  });

  it("returns null when the claim is missing, so the current role is kept", () => {
    expect(resolveRole({}, groups)).toBeNull();
    expect(resolveRole({ roles: ["admin"] }, groups)).toBeNull();
    // Entra's overage marker replaces the groups claim.
    expect(
      resolveRole(
        { _claim_names: { groups: "src1" }, _claim_sources: {} },
        groups,
      ),
    ).toBeNull();
  });

  it("treats a claim that is not a string or array as missing", () => {
    for (const value of [null, 42, true, { admin: true }])
      expect(resolveRole({ groups: value }, groups)).toBeNull();
  });

  it("returns none when the claim is present but nothing maps", () => {
    expect(resolveRole({ groups: [] }, groups)).toBe("none");
    expect(resolveRole({ groups: ["mill-admins", "everyone"] }, groups)).toBe(
      "none",
    );
    expect(resolveRole({ groups: "" }, groups)).toBe("none");
  });

  it("ignores non-string entries and is case-sensitive", () => {
    expect(
      resolveRole({ groups: [1, null, { name: "posted-admins" }] }, groups),
    ).toBe("none");
    expect(resolveRole({ groups: ["POSTED-ADMINS"] }, groups)).toBe("none");
    expect(resolveRole({ groups: [7, "posted-viewers"] }, groups)).toBe(
      "viewer",
    );
  });

  it("does not match inherited object keys", () => {
    expect(resolveRole({ groups: ["toString", "constructor"] }, groups)).toBe(
      "none",
    );
    const claims = Object.create({ groups: ["posted-admins"] }) as Record<
      string,
      unknown
    >;
    expect(resolveRole(claims, groups)).toBeNull();
  });

  it("ignores mapped values that are not roles", () => {
    const broken: RoleMap = {
      claims: ["groups"],
      values: { staff: "owner", crew: "member" } as Record<
        string,
        string
      > as Record<string, Role>,
    };
    expect(resolveRole({ groups: ["staff"] }, broken)).toBe("none");
    expect(resolveRole({ groups: ["staff", "crew"] }, broken)).toBe("member");
  });

  it("reads every listed claim and takes the highest across them", () => {
    const both: RoleMap = {
      claims: ["roles", "groups"],
      values: { member: "member", "posted-admins": "admin" },
    };
    expect(
      resolveRole({ roles: ["member"], groups: ["posted-admins"] }, both),
    ).toBe("admin");
    expect(resolveRole({ groups: ["posted-admins"] }, both)).toBe("admin");
    expect(resolveRole({ roles: [], groups: ["unrelated"] }, both)).toBe(
      "none",
    );
    expect(resolveRole({ other: ["member"] }, both)).toBeNull();
  });
});
