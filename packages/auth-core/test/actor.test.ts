import { describe, expect, expectTypeOf, it } from "vitest";
import {
  createActor,
  effectiveRole,
  ROLES,
  roleRank,
  type Actor,
  type ActorUser,
} from "../src/index.js";

const user = (role: ActorUser["role"]): ActorUser => ({
  id: "6f1c1f5e-5d1b-4bb5-9a43-2e1f3b0f7d11",
  role,
  email: "ada@example.com",
  displayName: "Ada",
});

describe("effectiveRole", () => {
  it("uses the user's role when the credential has no ceiling", () => {
    for (const role of ROLES) expect(effectiveRole(role, null)).toBe(role);
  });

  it("caps the role at the lower of ceiling and current role", () => {
    for (const userRole of ROLES)
      for (const ceiling of ROLES)
        expect(effectiveRole(userRole, ceiling)).toBe(
          roleRank(userRole) < roleRank(ceiling) ? userRole : ceiling,
        );
  });

  it("drops a key's power when its owner is demoted", () => {
    expect(effectiveRole("admin", "admin")).toBe("admin");
    expect(effectiveRole("viewer", "admin")).toBe("viewer");
  });
});

describe("createActor", () => {
  it("computes the effective role and keeps the app extension", () => {
    const actor = createActor({
      user: user("member"),
      credential: {
        kind: "api_key",
        id: "01JBX5E8W6TGGDFXR9NB7QH4PC",
        ceiling: "admin",
        workspace: "w1",
      },
      ext: { workspaceId: "w1" },
    });
    expect(actor.role).toBe("member");
    expect(actor.ext.workspaceId).toBe("w1");
    expectTypeOf(actor).toEqualTypeOf<Actor<{ workspaceId: string }>>();
  });

  it("defaults the extension to an empty object", () => {
    const actor = createActor({
      user: user("admin"),
      credential: {
        kind: "session",
        id: "a".repeat(64),
        ceiling: null,
        workspace: null,
      },
    });
    expect(actor.role).toBe("admin");
    expect(actor.ext).toEqual({});
  });

  it("applies an OAuth grant's ceiling", () => {
    const actor = createActor({
      user: user("admin"),
      credential: {
        kind: "oauth",
        id: "grant-1",
        ceiling: "viewer",
        workspace: null,
      },
    });
    expect(actor.role).toBe("viewer");
  });
});
