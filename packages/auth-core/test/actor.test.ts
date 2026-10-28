import { describe, expect, expectTypeOf, it } from "vitest";
import {
  auditActor,
  AUDIT_EVENT_TYPES,
  createActor,
  effectiveRole,
  ROLES,
  roleRank,
  type Actor,
  type ActorUser,
  type AuditEvent,
  type AuditEventType,
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
      credential: { kind: "session", id: "a".repeat(64), ceiling: null },
    });
    expect(actor.role).toBe("admin");
    expect(actor.ext).toEqual({});
  });

  it("applies an OAuth grant's ceiling", () => {
    const actor = createActor({
      user: user("admin"),
      credential: { kind: "oauth", id: "grant-1", ceiling: "viewer" },
    });
    expect(actor.role).toBe("viewer");
  });
});

describe("audit events", () => {
  it("lists every event type exactly once", () => {
    expectTypeOf<
      (typeof AUDIT_EVENT_TYPES)[number]
    >().toEqualTypeOf<AuditEventType>();
    expect(new Set(AUDIT_EVENT_TYPES).size).toBe(AUDIT_EVENT_TYPES.length);
    for (const type of AUDIT_EVENT_TYPES)
      expect(type).toMatch(/^[a-z][a-z_]*(\.[a-z][a-z_]*)+$/);
  });

  it("describes a request's actor without its secret", () => {
    const actor = createActor({
      user: user("member"),
      credential: { kind: "api_key", id: "key-1", ceiling: "viewer" },
    });
    expect(auditActor(actor)).toEqual({
      type: "user",
      userId: actor.user.id,
      credential: { kind: "api_key", id: "key-1" },
    });
  });

  it("types each event's data by its type", () => {
    const event: AuditEvent = {
      type: "user.role_changed",
      actor: {
        type: "idp",
        issuer: "https://auth.example.com/application/o/posted/",
      },
      subjectUserId: user("member").id,
      data: { source: "scim", from: "member", to: "admin" },
    };
    expect(event.data).toEqual({ source: "scim", from: "member", to: "admin" });
    const denied: AuditEvent = {
      type: "sign_in.denied",
      actor: { type: "system" },
      subjectUserId: null,
      data: { reason: "no_role" },
    };
    expect(denied.subjectUserId).toBeNull();
    // @ts-expect-error: a role change needs from and to.
    const broken: AuditEvent = {
      type: "user.role_changed",
      actor: { type: "system" },
      subjectUserId: "u",
      data: { source: "scim" },
    };
    expect(broken.type).toBe("user.role_changed");
  });
});
