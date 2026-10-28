-- SCIM 2.0 provisioning: the attributes SCIM sends for users, and groups
-- with their members.

-- SCIM's userName and name parts. userName is unique among live users,
-- ignoring case, so a tombstone never blocks a new person with the same
-- name. externalId stays unique per issuer for tombstones too
-- (users_iss_external_id_key): provisioning a deleted user's externalId
-- again revives that row instead of creating a second person.
ALTER TABLE users
  ADD COLUMN user_name text CHECK (user_name <> '' AND length(user_name) <= 320),
  ADD COLUMN given_name text CHECK (length(given_name) <= 256),
  ADD COLUMN family_name text CHECK (length(family_name) <= 256);

-- A SCIM user may arrive with only a userName.
ALTER TABLE users
  DROP CONSTRAINT users_identified,
  ADD CONSTRAINT users_identified
    CHECK (sub IS NOT NULL OR external_id IS NOT NULL OR user_name IS NOT NULL);

CREATE UNIQUE INDEX users_user_name_key ON users (iss, lower(user_name))
  WHERE user_name IS NOT NULL AND deleted_at IS NULL;

-- A group pushed by the identity provider. With <APP>_ROLE_SOURCE=scim,
-- group display names map to roles through <APP>_OIDC_ROLE_MAP.
CREATE TABLE scim_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name text NOT NULL CHECK (display_name <> '' AND length(display_name) <= 256),
  external_id text CHECK (external_id <> '' AND length(external_id) <= 255),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX scim_groups_display_name_key ON scim_groups (lower(display_name));
CREATE UNIQUE INDEX scim_groups_external_id_key ON scim_groups (external_id)
  WHERE external_id IS NOT NULL;

CREATE TABLE scim_group_members (
  group_id uuid NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);

CREATE INDEX scim_group_members_user_id_idx ON scim_group_members (user_id);

CREATE FUNCTION scim_groups_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.id <> OLD.id THEN
    RAISE EXCEPTION 'group ids never change' USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

CREATE TRIGGER scim_groups_before_update
BEFORE UPDATE ON scim_groups
FOR EACH ROW EXECUTE FUNCTION scim_groups_before_update();

-- Tombstoned users belong to no group.
CREATE FUNCTION scim_group_members_before_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  deleted boolean;
BEGIN
  EXECUTE format('SELECT deleted_at IS NOT NULL FROM %I.users WHERE id = $1', TG_TABLE_SCHEMA)
    INTO deleted USING NEW.user_id;
  IF deleted THEN
    RAISE EXCEPTION 'user % is deleted; it cannot join a group', NEW.user_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER scim_group_members_before_insert
BEFORE INSERT ON scim_group_members
FOR EACH ROW EXECUTE FUNCTION scim_group_members_before_insert();

-- SCIM revives a tombstone when the provider provisions the same
-- externalId again, as authentik does when someone is unassigned from the
-- app and later assigned back. Otherwise deletion stays permanent: the
-- revival must be announced in the same transaction with
-- set_config('auth_core.revive_user', <id>, true), and the user comes back
-- with no role. Sessions revoked by the deletion stay revoked.
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
  NEW.updated_at := now();
  RETURN NEW;
END
$$;
