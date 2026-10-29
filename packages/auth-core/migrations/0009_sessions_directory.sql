-- Sessions and the people directory over HTTP.

-- Sessions ----------------------------------------------------------------

-- public_id names a session to its owner (GET and DELETE /auth/sessions):
-- random, never the token or its hash, and unchanged when a rotation
-- re-hashes id_hash. last_seen_at is the last lookup, recorded at most once
-- a minute like the idle expiry; sessions from before this migration start
-- at their creation time. browser and os are a coarse summary of the
-- User-Agent at sign-in, such as 'Firefox' and 'macOS', so people can tell
-- their sessions apart; the header itself is not stored, and neither is
-- the IP address.
ALTER TABLE sessions
  ADD COLUMN public_id uuid NOT NULL DEFAULT gen_random_uuid(),
  ADD COLUMN last_seen_at timestamptz,
  ADD COLUMN browser text CHECK (browser <> '' AND length(browser) <= 32),
  ADD COLUMN os text CHECK (os <> '' AND length(os) <= 32);

UPDATE sessions SET last_seen_at = created_at;

ALTER TABLE sessions
  ALTER COLUMN last_seen_at SET NOT NULL,
  ADD CONSTRAINT sessions_public_id_key UNIQUE (public_id),
  ADD CONSTRAINT sessions_last_seen_after_created CHECK (last_seen_at >= created_at);

-- As in 0001, and a session inserted without last_seen_at was last seen
-- when it was created.
CREATE OR REPLACE FUNCTION sessions_before_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  usable boolean;
BEGIN
  EXECUTE format(
    'SELECT active AND deleted_at IS NULL FROM %I.users WHERE id = $1 FOR SHARE',
    TG_TABLE_SCHEMA
  ) INTO usable USING NEW.user_id;
  IF usable IS NOT TRUE THEN
    RAISE EXCEPTION 'user % is not active; it cannot get a session', NEW.user_id
      USING ERRCODE = 'check_violation';
  END IF;
  NEW.last_seen_at := coalesce(NEW.last_seen_at, NEW.created_at);
  RETURN NEW;
END
$$;

-- As in 0007, and the public id never changes either.
CREATE OR REPLACE FUNCTION sessions_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.id_hash <> OLD.id_hash
      AND current_setting('auth_core.rehash', true) IS DISTINCT FROM OLD.id_hash)
    OR NEW.public_id <> OLD.public_id
    OR NEW.user_id <> OLD.user_id
    OR NEW.created_at <> OLD.created_at
    OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION 'a session''s id, user, creation time and expiry never change'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'a revoked session stays revoked' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.authenticated_at < OLD.authenticated_at THEN
    RAISE EXCEPTION 'a session''s authentication time never moves back'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

-- Users -------------------------------------------------------------------

-- When the person last signed in (a new session from the OIDC callback;
-- step-up is not a sign-in). NULL for someone SCIM provisioned who never
-- signed in, and for sign-ins before this migration.
ALTER TABLE users ADD COLUMN last_sign_in_at timestamptz;

-- The directory pages through users newest first.
CREATE INDEX users_created_at_id_idx ON users (created_at, id);

-- As in 0003, except that recording a sign-in and nothing else keeps
-- updated_at, which SCIM reports as meta.lastModified: the provider's
-- resource did not change.
CREATE OR REPLACE FUNCTION users_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
    IF NEW.deleted_at IS NOT NULL
      OR current_setting('auth_core.revive_user', true) IS DISTINCT FROM OLD.id::text THEN
      RAISE EXCEPTION 'user % is deleted; a tombstone cannot be restored or changed', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.role IS NOT NULL OR NEW.role_source IS NOT NULL THEN
      RAISE EXCEPTION 'user % must come back with no role', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF NEW.id <> OLD.id THEN
    RAISE EXCEPTION 'user ids never change' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.last_sign_in_at IS DISTINCT FROM OLD.last_sign_in_at
    AND to_jsonb(NEW) - 'last_sign_in_at' = to_jsonb(OLD) - 'last_sign_in_at' THEN
    NEW.updated_at := OLD.updated_at;
  ELSE
    NEW.updated_at := now();
  END IF;
  RETURN NEW;
END
$$;
