-- The OAuth 2.1 authorization server for MCP clients: known clients, consent
-- requests, grants, authorization codes and tokens. Codes, tokens and
-- request ids are stored as HMAC-SHA256 under their own derived keys, never
-- in the clear. A grant acts with the lower of its ceiling and its owner's
-- current role, exactly like an API key.

-- Clients the server has seen: those from <APP>_OAUTH_CLIENTS ('configured',
-- copied here on first use), client metadata documents ('metadata', a cache
-- that expires), and legacy dynamic registrations ('dynamic').
CREATE TABLE oauth_clients (
  client_id text PRIMARY KEY CHECK (client_id <> '' AND length(client_id) <= 2048),
  kind text NOT NULL CHECK (kind IN ('configured', 'metadata', 'dynamic')),
  client_name text NOT NULL CHECK (client_name <> '' AND length(client_name) <= 200),
  logo_uri text CHECK (length(logo_uri) <= 2048),
  redirect_uris text[] NOT NULL CHECK (
    cardinality(redirect_uris) BETWEEN 1 AND 20 AND array_position(redirect_uris, NULL) IS NULL
  ),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- When a cached metadata document must be fetched again.
  expires_at timestamptz,
  CONSTRAINT oauth_clients_cache_expires CHECK ((kind = 'metadata') = (expires_at IS NOT NULL))
);

-- An authorization request waiting for the person's decision on the web
-- origin's consent page. Bound to the first signed-in person who opens it,
-- decided once, and gone after ten minutes.
CREATE TABLE oauth_requests (
  id_hash text PRIMARY KEY CHECK (id_hash ~ '^[0-9a-f]{64}$'),
  client_id text NOT NULL REFERENCES oauth_clients (client_id),
  redirect_uri text NOT NULL CHECK (length(redirect_uri) <= 2048),
  resource text NOT NULL CHECK (length(resource) <= 2048),
  scope text CHECK (scope IN ('viewer', 'member', 'admin')),
  state text CHECK (length(state) <= 1024),
  code_challenge text NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43,128}$'),
  user_id uuid REFERENCES users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  CONSTRAINT oauth_requests_expires_after_created CHECK (expires_at > created_at)
);

CREATE INDEX oauth_requests_expires_at_idx ON oauth_requests (expires_at);

-- What a person allowed a client to do: act as at most `ceiling` on the
-- listed resources. `restrictions` is app-defined and opaque to auth-core.
-- The client's name and logo are kept as approved, for the connected-apps
-- list.
CREATE TABLE oauth_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES oauth_clients (client_id),
  client_name text NOT NULL CHECK (client_name <> '' AND length(client_name) <= 200),
  logo_uri text CHECK (length(logo_uri) <= 2048),
  ceiling text NOT NULL CHECK (ceiling IN ('viewer', 'member', 'admin')),
  resources text[] NOT NULL CHECK (
    cardinality(resources) BETWEEN 1 AND 20 AND array_position(resources, NULL) IS NULL
  ),
  restrictions jsonb CHECK (jsonb_typeof(restrictions) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz CHECK (last_used_at >= created_at),
  revoked_at timestamptz CHECK (revoked_at >= created_at)
);

CREATE INDEX oauth_grants_user_id_idx ON oauth_grants (user_id);

-- A single-use authorization code, valid for 60 seconds.
CREATE TABLE oauth_codes (
  code_hash text PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  grant_id uuid NOT NULL REFERENCES oauth_grants (id) ON DELETE CASCADE,
  client_id text NOT NULL,
  redirect_uri text NOT NULL,
  resource text NOT NULL,
  code_challenge text NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43,128}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CONSTRAINT oauth_codes_expires_after_created CHECK (expires_at > created_at)
);

-- Access tokens (15 minutes) and refresh tokens (30 days idle, 90 days in
-- all). Each code redemption starts a family; every refresh rotates within
-- it, and reusing a rotated refresh token revokes the family.
CREATE TABLE oauth_tokens (
  token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  kind text NOT NULL CHECK (kind IN ('access', 'refresh')),
  grant_id uuid NOT NULL REFERENCES oauth_grants (id) ON DELETE CASCADE,
  family_id uuid NOT NULL,
  -- The audience: the one resource the token was issued for.
  resource text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  -- The family's absolute limit, carried by every refresh token in it.
  family_expires_at timestamptz,
  rotated_at timestamptz,
  revoked_at timestamptz,
  CONSTRAINT oauth_tokens_expires_after_created CHECK (expires_at > created_at),
  CONSTRAINT oauth_tokens_refresh_has_limit CHECK (
    (kind = 'refresh') = (family_expires_at IS NOT NULL)
    AND (kind = 'refresh' OR rotated_at IS NULL)
    AND expires_at <= coalesce(family_expires_at, expires_at)
  )
);

CREATE INDEX oauth_tokens_family_id_idx ON oauth_tokens (family_id);
CREATE INDEX oauth_tokens_grant_id_idx ON oauth_tokens (grant_id);

CREATE FUNCTION oauth_clients_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.client_id <> OLD.client_id OR NEW.kind <> OLD.kind THEN
    RAISE EXCEPTION 'a client''s id and kind never change' USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

CREATE TRIGGER oauth_clients_before_update
BEFORE UPDATE ON oauth_clients
FOR EACH ROW EXECUTE FUNCTION oauth_clients_before_update();

-- Only an active, undeleted user with a role can get a grant.
CREATE FUNCTION oauth_grants_before_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  usable boolean;
BEGIN
  EXECUTE format(
    'SELECT active AND deleted_at IS NULL AND role IS NOT NULL FROM %I.users WHERE id = $1 FOR SHARE',
    TG_TABLE_SCHEMA
  ) INTO usable USING NEW.user_id;
  IF usable IS NOT TRUE THEN
    RAISE EXCEPTION 'user % is not active or has no role; it cannot get a grant', NEW.user_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER oauth_grants_before_insert
BEFORE INSERT ON oauth_grants
FOR EACH ROW EXECUTE FUNCTION oauth_grants_before_insert();

-- A grant's owner, client, ceiling, resources and restrictions are fixed,
-- revocation is final, and last_used_at only moves forward.
CREATE FUNCTION oauth_grants_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.id <> OLD.id
    OR NEW.user_id <> OLD.user_id
    OR NEW.client_id <> OLD.client_id
    OR NEW.ceiling <> OLD.ceiling
    OR NEW.resources <> OLD.resources
    OR NEW.restrictions IS DISTINCT FROM OLD.restrictions
    OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'a grant''s owner, client, ceiling, resources and restrictions never change'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'a revoked grant stays revoked' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.last_used_at < OLD.last_used_at THEN
    RAISE EXCEPTION 'a grant''s last use never moves back' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER oauth_grants_before_update
BEFORE UPDATE ON oauth_grants
FOR EACH ROW EXECUTE FUNCTION oauth_grants_before_update();

-- A code is consumed once; a token rotates once; revocation is final; and
-- nothing else about either changes.
CREATE FUNCTION oauth_codes_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF ROW(NEW.code_hash, NEW.grant_id, NEW.client_id, NEW.redirect_uri, NEW.resource,
         NEW.code_challenge, NEW.created_at, NEW.expires_at)
     IS DISTINCT FROM
     ROW(OLD.code_hash, OLD.grant_id, OLD.client_id, OLD.redirect_uri, OLD.resource,
         OLD.code_challenge, OLD.created_at, OLD.expires_at)
    OR (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at) THEN
    RAISE EXCEPTION 'an authorization code is consumed once and never changes otherwise'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER oauth_codes_before_update
BEFORE UPDATE ON oauth_codes
FOR EACH ROW EXECUTE FUNCTION oauth_codes_before_update();

CREATE FUNCTION oauth_tokens_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF ROW(NEW.token_hash, NEW.kind, NEW.grant_id, NEW.family_id, NEW.resource,
         NEW.created_at, NEW.expires_at, NEW.family_expires_at)
     IS DISTINCT FROM
     ROW(OLD.token_hash, OLD.kind, OLD.grant_id, OLD.family_id, OLD.resource,
         OLD.created_at, OLD.expires_at, OLD.family_expires_at)
    OR (OLD.rotated_at IS NOT NULL AND NEW.rotated_at IS DISTINCT FROM OLD.rotated_at)
    OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
    RAISE EXCEPTION 'a token rotates once, stays revoked, and never changes otherwise'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER oauth_tokens_before_update
BEFORE UPDATE ON oauth_tokens
FOR EACH ROW EXECUTE FUNCTION oauth_tokens_before_update();

-- Grants follow their owner exactly as API keys do (users_revoke_api_keys):
-- deactivation or deletion revokes all of them, a change to a non-NULL role
-- revokes those above it, and a NULL role suspends without revoking.
-- Tokens are refused once their grant is revoked.
CREATE FUNCTION users_revoke_oauth_grants() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  EXECUTE format(
    'UPDATE %I.oauth_grants SET revoked_at = GREATEST(now(), created_at)
     WHERE user_id = $1 AND revoked_at IS NULL
       AND (NOT $2 OR array_position(ARRAY[''viewer'', ''member'', ''admin''], ceiling)
            > array_position(ARRAY[''viewer'', ''member'', ''admin''], $3))',
    TG_TABLE_SCHEMA
  ) USING NEW.id, NEW.active, NEW.role;
  RETURN NULL;
END
$$;

CREATE TRIGGER users_revoke_oauth_grants
AFTER UPDATE OF active, role ON users
FOR EACH ROW
WHEN ((OLD.active AND NOT NEW.active)
  OR (NEW.role IS DISTINCT FROM OLD.role AND NEW.role IS NOT NULL))
EXECUTE FUNCTION users_revoke_oauth_grants();
