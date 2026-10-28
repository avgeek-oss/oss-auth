import { Hono } from "hono";
import { loadAuthConfig, type AuthConfig, type Role } from "../../src/index.js";
import { migrate, quoteIdent, type Sql } from "../../src/postgres/index.js";
import { createScim, type ScimHooks } from "../../src/scim/index.js";
import { createSessions } from "../../src/sessions/index.js";
import { adapters, dropSchemas, uniqueSchema } from "../postgres/support.js";

export const ISSUER = "https://auth.example.com/application/o/posted/";
export const TOKEN = "scim-token-".repeat(4);
export const OLD_TOKEN = "old-scim-token-".repeat(3);

export const ROLE_MAP = {
  "posted-viewers": "viewer",
  "posted-members": "member",
  "posted-admins": "admin",
};

/** A recorded hook call. */
export type HookCall =
  | { readonly hook: "deactivate"; readonly userId: string }
  | {
      readonly hook: "role";
      readonly userId: string;
      readonly from: Role | null;
      readonly to: Role | null;
    };

/** A SCIM server mounted at /scim/v2 on a fresh schema. */
export interface ScimStack {
  readonly sql: Sql;
  readonly config: AuthConfig;
  readonly schema: string;
  readonly hooks: HookCall[];
  /** A request with the bearer token and a SCIM body. */
  request(
    method: string,
    path: string,
    body?: unknown,
    token?: string | null,
    contentType?: string,
  ): Promise<Response>;
  /** Like `request`, returning the status and the parsed body. */
  json(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: Record<string, unknown> }>;
  rows<T extends object>(query: string, params?: unknown[]): Promise<T[]>;
  close(): Promise<void>;
}

/** Starts a SCIM stack on the `pg` adapter. */
export async function startScim(
  env: Readonly<Record<string, string>> = {},
  options: { failHook?: () => boolean } = {},
): Promise<ScimStack> {
  const { sql, close } = (adapters[0] ?? raise()).open();
  const schema = uniqueSchema("scim");
  await migrate(sql, { schema });
  const config = loadAuthConfig("posted", {
    POSTED_SECRET: "s".repeat(32),
    POSTED_OIDC_ISSUER: ISSUER,
    POSTED_OIDC_CLIENT_ID: "posted",
    POSTED_OIDC_CLIENT_SECRET: "x",
    POSTED_OIDC_ROLE_MAP: JSON.stringify(ROLE_MAP),
    POSTED_SCIM_TOKENS: `${TOKEN},${OLD_TOKEN}`,
    POSTED_WEB_ORIGIN: "https://posted.example.com",
    POSTED_API_ORIGIN: "https://api.posted.example.com",
    POSTED_AUTH_SCHEMA: schema,
    ...env,
  });
  const calls: HookCall[] = [];
  const hooks: ScimHooks = {
    onDeactivate: async (userId, tx) => {
      await tx.query("SELECT 1");
      if (options.failHook?.()) throw new Error("hook failed");
      calls.push({ hook: "deactivate", userId });
    },
    onRoleChange: async (userId, from, to, tx) => {
      await tx.query("SELECT 1");
      if (options.failHook?.()) throw new Error("hook failed");
      calls.push({ hook: "role", userId, from, to });
    },
  };
  const app = new Hono();
  app.route(
    "/scim/v2",
    createScim({
      config,
      sql,
      sessions: createSessions({ sql, config }),
      hooks,
    }),
  );

  const request = (
    method: string,
    path: string,
    body?: unknown,
    token: string | null = TOKEN,
    contentType = "application/scim+json",
  ) => {
    const headers: Record<string, string> = {};
    if (token !== null) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers["content-type"] = contentType;
    return Promise.resolve(
      app.request(`/scim/v2${path}`, {
        method,
        headers,
        ...(body === undefined
          ? {}
          : { body: typeof body === "string" ? body : JSON.stringify(body) }),
      }),
    );
  };

  return {
    sql,
    config,
    schema,
    hooks: calls,
    request,
    async json(method, path, body) {
      const response = await request(method, path, body);
      const text = await response.text();
      return {
        status: response.status,
        body: text === "" ? {} : (JSON.parse(text) as Record<string, unknown>),
      };
    },
    rows: (query, params = []) =>
      sql.query(query.replaceAll("{schema}", quoteIdent(schema)), params),
    async close() {
      await dropSchemas(sql, [schema]);
      await close();
    },
  };
}

function raise(): never {
  throw new Error("no adapter");
}

/** A minimal SCIM user body. */
export function userBody(
  userName: string,
  extra: Record<string, unknown> = {},
) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName,
    active: true,
    ...extra,
  };
}

/** A PatchOp body. */
export function patchBody(...Operations: Record<string, unknown>[]) {
  return {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations,
  };
}
