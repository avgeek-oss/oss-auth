-- Personal API keys. A key is `<prefix>_<id>_<secret>_<checksum>`; the
-- table keeps the public id and the HMAC-SHA256 of the whole key under the
-- derived "api-key" key, never the key itself. A key acts with the lower of
-- its ceiling and its owner's current role.
CREATE TABLE api_keys (
  id text PRIMARY KEY CHECK (id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  name text NOT NULL CHECK (name <> '' AND length(name) <= 100),
  ceiling text NOT NULL CHECK (ceiling IN ('viewer', 'member', 'admin')),
  -- App-defined and opaque to auth-core; the app enforces it.
  workspace text CHECK (workspace <> '' AND length(workspace) <= 255),
  secret_hash text NOT NULL UNIQUE CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  -- NULL only when <APP>_API_KEY_ALLOW_NO_EXPIRY allowed it at creation.
  expires_at timestamptz CHECK (expires_at > created_at),
  last_used_at timestamptz CHECK (last_used_at >= created_at),
  revoked_at timestamptz CHECK (revoked_at >= created_at),
  -- Rotation: the key that replaced this one, and until when this one still
  -- works.
  replaced_by text UNIQUE REFERENCES api_keys (id),
  grace_until timestamptz,
  CONSTRAINT api_keys_rotation CHECK ((replaced_by IS NULL) = (grace_until IS NULL)),
  CONSTRAINT api_keys_not_self_replaced CHECK (replaced_by <> id)
);

CREATE INDEX api_keys_user_id_idx ON api_keys (user_id);

-- Only an active, undeleted user with a role can get a key.
CREATE FUNCTION api_keys_before_insert() RETURNS trigger
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
    RAISE EXCEPTION 'user % is not active or has no role; it cannot get an API key', NEW.user_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER api_keys_before_insert
BEFORE INSERT ON api_keys
FOR EACH ROW EXECUTE FUNCTION api_keys_before_insert();

-- A key's identity, owner, ceiling, workspace, secret and expiry are fixed.
-- Revocation is final, a key is replaced at most once, and last_used_at only
-- moves forward.
CREATE FUNCTION api_keys_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.id <> OLD.id
    OR NEW.user_id <> OLD.user_id
    OR NEW.ceiling <> OLD.ceiling
    OR NEW.workspace IS DISTINCT FROM OLD.workspace
    OR NEW.secret_hash <> OLD.secret_hash
    OR NEW.created_at <> OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'an API key''s id, owner, ceiling, workspace, secret and expiry never change'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'a revoked API key stays revoked' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.replaced_by IS NOT NULL AND (NEW.replaced_by IS DISTINCT FROM OLD.replaced_by
    OR NEW.grace_until IS DISTINCT FROM OLD.grace_until) THEN
    RAISE EXCEPTION 'an API key is replaced only once' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.last_used_at < OLD.last_used_at THEN
    RAISE EXCEPTION 'an API key''s last use never moves back' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER api_keys_before_update
BEFORE UPDATE ON api_keys
FOR EACH ROW EXECUTE FUNCTION api_keys_before_update();

-- Deactivating or deleting a user (deletion deactivates too) revokes all of
-- their keys in the same transaction, as users_revoke_sessions does for
-- sessions. A change to a non-NULL role revokes the keys whose ceiling is
-- above it, so the key list matches what the keys can do; this covers SCIM,
-- sign-in and any change the app makes.
--
-- A NULL role suspends rather than revokes: keys and sessions are refused
-- while it lasts and work again when a role returns. Providers move people
-- between groups in two requests, and removing before adding passes through
-- NULL. Comparing with the new role alone is enough for a later lower role:
-- no live key is above the last non-NULL role (keys are issued at or below
-- it, and lowering it revoked the rest), so admin, NULL, then member still
-- revokes the admin keys.
CREATE FUNCTION users_revoke_api_keys() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  EXECUTE format(
    'UPDATE %I.api_keys SET revoked_at = GREATEST(now(), created_at)
     WHERE user_id = $1 AND revoked_at IS NULL
       AND (NOT $2 OR array_position(ARRAY[''viewer'', ''member'', ''admin''], ceiling)
            > array_position(ARRAY[''viewer'', ''member'', ''admin''], $3))',
    TG_TABLE_SCHEMA
  ) USING NEW.id, NEW.active, NEW.role;
  RETURN NULL;
END
$$;

CREATE TRIGGER users_revoke_api_keys
AFTER UPDATE OF active, role ON users
FOR EACH ROW
WHEN ((OLD.active AND NOT NEW.active)
  OR (NEW.role IS DISTINCT FROM OLD.role AND NEW.role IS NOT NULL))
EXECUTE FUNCTION users_revoke_api_keys();
