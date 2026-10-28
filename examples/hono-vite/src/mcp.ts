// A tiny MCP server over streamable HTTP, answering with JSON: enough for
// an MCP client to initialize, list tools and call `echo` and `whoami`.
// Real apps use their own server; the point here is the token check in
// front of it.
import type { Context } from "hono";
import type { Actor } from "@avgeek-oss/auth-core";

const PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"];

const TOOLS = [
  {
    name: "echo",
    description: "Returns its text.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"],
    },
  },
  {
    name: "whoami",
    description: "Says who the token acts for, and with which role.",
    inputSchema: { type: "object", properties: {} },
  },
];

interface JsonRpcRequest {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: Record<string, unknown>;
}

function result(c: Context, id: unknown, value: unknown) {
  return c.json({ jsonrpc: "2.0", id, result: value });
}

function failure(c: Context, id: unknown, code: number, message: string) {
  return c.json({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
}

/** Handles one JSON-RPC message for `actor`. */
export async function handleMcp(
  c: Context,
  actor: Actor<object>,
): Promise<Response> {
  let message: JsonRpcRequest;
  try {
    message = (await c.req.json()) as JsonRpcRequest;
  } catch {
    return failure(c, null, -32700, "Parse error");
  }
  if (typeof message !== "object" || message === null || Array.isArray(message))
    return failure(c, null, -32600, "Send one JSON-RPC message");
  // Notifications get no response body.
  if (message.id === undefined) return c.body(null, 202);
  const { id, method, params = {} } = message;
  switch (method) {
    case "initialize": {
      const asked = params.protocolVersion;
      return result(c, id, {
        protocolVersion:
          typeof asked === "string" && PROTOCOL_VERSIONS.includes(asked)
            ? asked
            : PROTOCOL_VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: { name: "auth-reference-app", version: "0.0.0" },
      });
    }
    case "ping":
      return result(c, id, {});
    case "tools/list":
      return result(c, id, { tools: TOOLS });
    case "tools/call": {
      const args = (params.arguments ?? {}) as Record<string, unknown>;
      if (params.name === "echo")
        return result(c, id, {
          content: [
            {
              type: "text",
              text: typeof args.text === "string" ? args.text : "",
            },
          ],
        });
      if (params.name === "whoami")
        return result(c, id, {
          content: [
            {
              type: "text",
              text: `${actor.user.displayName ?? actor.user.email ?? actor.user.id} (${actor.role})`,
            },
          ],
        });
      return failure(c, id, -32602, "Unknown tool");
    }
    default:
      return failure(c, id, -32601, "Method not found");
  }
}
