import type { AuthConfig, OAuthClientConfig } from "../config.js";
import type { SqlQueryable } from "../postgres/sql.js";
import {
  isHttpsUrl,
  isValidRedirectUri,
  MAX_URI_LENGTH,
} from "../redirect-uris.js";
import {
  fetchMetadataDocument,
  MetadataFetchError,
  type MetadataFetchOptions,
} from "./fetch.js";

/** Where a client's registration came from. */
export type ClientKind = "configured" | "metadata" | "dynamic";

/** An OAuth client the server knows. */
export interface OAuthClient {
  readonly clientId: string;
  readonly kind: ClientKind;
  readonly clientName: string;
  readonly logoUri: string | null;
  readonly redirectUris: readonly string[];
  /** Only for a confidential configured client. */
  readonly clientSecret: string | null;
}

/** The longest a client metadata document is cached: 24 hours. */
export const MAX_METADATA_CACHE_SECONDS = 86400;

const COLUMNS = `client_id AS "clientId", kind, client_name AS "clientName",
  logo_uri AS "logoUri", redirect_uris AS "redirectUris"`;

/** Why a client cannot be used. The message is safe to show. */
export class ClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClientError";
  }
}

/**
 * Checks client metadata, from a metadata document (with `expectedId`, the
 * URL it was fetched from) or a dynamic registration. Only public clients
 * using PKCE are accepted this way.
 */
export function readClientMetadata(
  value: unknown,
  expectedId?: string,
): Pick<OAuthClient, "clientName" | "logoUri" | "redirectUris"> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new ClientError("Client metadata must be a JSON object.");
  const v = value as Record<string, unknown>;
  if (expectedId !== undefined && v.client_id !== expectedId)
    throw new ClientError(
      "The metadata document's client_id must equal the URL it is served from.",
    );
  const name = typeof v.client_name === "string" ? v.client_name.trim() : "";
  if (name === "" || name.length > 200)
    throw new ClientError("client_name must be 1 to 200 characters.");
  if (
    !Array.isArray(v.redirect_uris) ||
    v.redirect_uris.length === 0 ||
    v.redirect_uris.length > 20 ||
    !v.redirect_uris.every(isValidRedirectUri)
  )
    throw new ClientError(
      "redirect_uris must list 1 to 20 https or loopback http URIs without fragments.",
    );
  if (v.logo_uri !== undefined && !isHttpsUrl(v.logo_uri))
    throw new ClientError("logo_uri must be an https URL.");
  if (
    v.token_endpoint_auth_method !== undefined &&
    v.token_endpoint_auth_method !== "none"
  )
    throw new ClientError(
      "Only public clients (token_endpoint_auth_method none) with PKCE are accepted.",
    );
  if (
    v.grant_types !== undefined &&
    !(
      Array.isArray(v.grant_types) &&
      v.grant_types.includes("authorization_code")
    )
  )
    throw new ClientError("grant_types must include authorization_code.");
  return {
    clientName: name,
    logoUri: (v.logo_uri as string | undefined) ?? null,
    redirectUris: v.redirect_uris as string[],
  };
}

/** True when `clientId` names a client metadata document. */
export function isMetadataDocumentId(clientId: string): boolean {
  if (!isHttpsUrl(clientId) || clientId.length > MAX_URI_LENGTH) return false;
  return new URL(clientId).pathname !== "/";
}

/** Resolves client ids to clients, caching metadata documents in the table. */
export interface ClientStore {
  /**
   * The client for `clientId`, or `null` when it is unknown. With
   * `fetch: true`, an unknown or expired metadata document is fetched (for
   * `/authorize`); otherwise a cached one is used even if expired (for the
   * token endpoint, which needs only the id and the authentication
   * method).
   *
   * @throws {@link ClientError} when a metadata document is unusable.
   */
  resolve(
    db: SqlQueryable,
    clientId: string,
    options: {
      readonly fetch: boolean;
      /**
       * Runs before a metadata document is fetched, that is on a cache miss
       * only, with the document's URL. Throw to stop the fetch.
       */
      readonly beforeFetch?: (url: URL) => Promise<void>;
    },
  ): Promise<OAuthClient | null>;
  /** Stores a dynamic registration and returns it. */
  register(
    db: SqlQueryable,
    clientId: string,
    metadata: Pick<OAuthClient, "clientName" | "logoUri" | "redirectUris">,
  ): Promise<OAuthClient>;
}

/** The client store for an app. */
export function createClientStore(options: {
  readonly config: AuthConfig;
  readonly table: string;
  readonly clock: () => Date | null;
  readonly fetch?: MetadataFetchOptions;
}): ClientStore {
  const { config, table } = options;
  const T = "coalesce($1::timestamptz, now())";
  const configured = new Map<string, OAuthClientConfig>(
    config.oauth.clients.map((client) => [client.clientId, client]),
  );
  const synced = new Set<string>();

  async function syncConfigured(
    db: SqlQueryable,
    client: OAuthClientConfig,
  ): Promise<void> {
    if (synced.has(client.clientId)) return;
    await db.query(
      `INSERT INTO ${table} (client_id, kind, client_name, logo_uri, redirect_uris)
       VALUES ($1, 'configured', $2, $3, $4::text[])
       ON CONFLICT (client_id) DO UPDATE
         SET client_name = excluded.client_name, logo_uri = excluded.logo_uri,
             redirect_uris = excluded.redirect_uris
         WHERE ${table}.kind = 'configured'
           AND (${table}.client_name, ${table}.logo_uri, ${table}.redirect_uris)
               IS DISTINCT FROM (excluded.client_name, excluded.logo_uri, excluded.redirect_uris)`,
      [
        client.clientId,
        client.clientName,
        client.logoUri,
        `{${client.redirectUris.map((u) => JSON.stringify(u)).join(",")}}`,
      ],
    );
    synced.add(client.clientId);
  }

  return {
    async resolve(db, clientId, { fetch, beforeFetch }) {
      const fromConfig = configured.get(clientId);
      if (fromConfig) {
        await syncConfigured(db, fromConfig);
        return { ...fromConfig, kind: "configured" };
      }
      if (clientId.startsWith("dcr_")) {
        if (!config.oauth.legacyDcr) return null;
        const [row] = await db.query<OAuthClient>(
          `SELECT ${COLUMNS} FROM ${table} WHERE client_id = $1 AND kind = 'dynamic'`,
          [clientId],
        );
        return row ? { ...row, clientSecret: null } : null;
      }
      if (!isMetadataDocumentId(clientId)) return null;
      const [cached] = await db.query<OAuthClient & { fresh: boolean }>(
        `SELECT ${COLUMNS}, expires_at > ${T} AS "fresh" FROM ${table}
         WHERE client_id = $2 AND kind = 'metadata'`,
        [options.clock(), clientId],
      );
      if (cached && (cached.fresh || !fetch))
        return {
          clientId: cached.clientId,
          kind: cached.kind,
          clientName: cached.clientName,
          logoUri: cached.logoUri,
          redirectUris: cached.redirectUris,
          clientSecret: null,
        };
      if (!fetch) return null;
      await beforeFetch?.(new URL(clientId));
      let document: { value: unknown; cacheSeconds: number };
      try {
        document = await fetchMetadataDocument(
          new URL(clientId),
          options.fetch,
        );
      } catch (error) {
        if (error instanceof MetadataFetchError)
          throw new ClientError(error.message);
        throw error;
      }
      const metadata = readClientMetadata(document.value, clientId);
      const seconds = Math.min(
        Math.max(document.cacheSeconds, 0),
        MAX_METADATA_CACHE_SECONDS,
      );
      const [row] = await db.query<OAuthClient>(
        `INSERT INTO ${table}
           (client_id, kind, client_name, logo_uri, redirect_uris, expires_at)
         VALUES ($2, 'metadata', $3, $4, $5::text[], ${T} + make_interval(secs => $6))
         ON CONFLICT (client_id) DO UPDATE
           SET client_name = excluded.client_name, logo_uri = excluded.logo_uri,
               redirect_uris = excluded.redirect_uris, expires_at = excluded.expires_at
           WHERE ${table}.kind = 'metadata'
         RETURNING ${COLUMNS}`,
        [
          options.clock(),
          clientId,
          metadata.clientName,
          metadata.logoUri,
          `{${metadata.redirectUris.map((u) => JSON.stringify(u)).join(",")}}`,
          seconds,
        ],
      );
      if (!row) throw new ClientError("This client id is already in use.");
      return { ...row, clientSecret: null };
    },

    async register(db, clientId, metadata) {
      const [row] = await db.query<OAuthClient>(
        `INSERT INTO ${table} (client_id, kind, client_name, logo_uri, redirect_uris)
         VALUES ($1, 'dynamic', $2, $3, $4::text[])
         RETURNING ${COLUMNS}`,
        [
          clientId,
          metadata.clientName,
          metadata.logoUri,
          `{${metadata.redirectUris.map((u) => JSON.stringify(u)).join(",")}}`,
        ],
      );
      if (!row) throw new Error("INSERT … RETURNING returned no row.");
      return { ...row, clientSecret: null };
    },
  };
}
