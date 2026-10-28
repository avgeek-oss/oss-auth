-- Secret rotation. A session or API key made under a previous secret is
-- stored under that secret's key; when it is next used, auth-core re-hashes
-- it under the current one. The id and secret hashes stay fixed otherwise:
-- a change is allowed only for the one row named in the transaction-local
-- setting auth_core.rehash, set to that row's old hash, so any other UPDATE
-- still cannot change it.

CREATE OR REPLACE FUNCTION sessions_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.id_hash <> OLD.id_hash
      AND current_setting('auth_core.rehash', true) IS DISTINCT FROM OLD.id_hash)
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

CREATE OR REPLACE FUNCTION api_keys_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.id <> OLD.id
    OR NEW.user_id <> OLD.user_id
    OR NEW.ceiling <> OLD.ceiling
    OR NEW.workspace IS DISTINCT FROM OLD.workspace
    OR (NEW.secret_hash <> OLD.secret_hash
        AND current_setting('auth_core.rehash', true) IS DISTINCT FROM OLD.secret_hash)
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
