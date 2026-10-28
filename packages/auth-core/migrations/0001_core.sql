-- Core auth tables: users, sessions and the audit log.
--
-- The migration runner sets search_path to the auth schema for this
-- transaction, so names here are unqualified. Functions pin their own
-- search_path and reach tables through TG_TABLE_SCHEMA, so they work in any
-- schema and cannot be redirected by a caller's search_path.

-- Users -------------------------------------------------------------------

-- A person known to the app through the identity provider. The identity key
-- is (iss, sub); email is an attribute and is never unique. A user created by
-- SCIM before their first sign-in has external_id but no sub yet.
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  iss text NOT NULL CHECK (iss <> ''),
  sub text CHECK (sub <> '' AND length(sub) <= 255),
  email text CHECK (email <> '' AND length(email) <= 320),
  display_name text CHECK (length(display_name) <= 256),
  role text NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer', 'member', 'admin')),
  active boolean NOT NULL DEFAULT true,
  external_id text CHECK (external_id <> '' AND length(external_id) <= 255),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deactivated_at timestamptz,
  deleted_at timestamptz,
  CONSTRAINT users_iss_sub_key UNIQUE (iss, sub),
  CONSTRAINT users_iss_external_id_key UNIQUE (iss, external_id),
  CONSTRAINT users_identified CHECK (sub IS NOT NULL OR external_id IS NOT NULL),
  CONSTRAINT users_active_matches_deactivated_at CHECK (active = (deactivated_at IS NULL)),
  -- A deleted user is a tombstone: inactive, and deleted no earlier than
  -- deactivated.
  CONSTRAINT users_deleted_is_inactive CHECK (
    deleted_at IS NULL OR (NOT active AND deleted_at >= deactivated_at)
  )
);

-- Keeps updated_at current and makes deletion permanent.
CREATE FUNCTION users_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
    RAISE EXCEPTION 'user % is deleted; a tombstone cannot be restored or changed', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.id <> OLD.id THEN
    RAISE EXCEPTION 'user ids never change' USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

CREATE TRIGGER users_before_update
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION users_before_update();

-- Deactivating a user ends every live session in the same transaction.
CREATE FUNCTION users_revoke_sessions() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  EXECUTE format(
    'UPDATE %I.sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL',
    TG_TABLE_SCHEMA
  ) USING NEW.id;
  RETURN NULL;
END
$$;

CREATE TRIGGER users_revoke_sessions
AFTER UPDATE OF active ON users
FOR EACH ROW
WHEN (OLD.active AND NOT NEW.active)
EXECUTE FUNCTION users_revoke_sessions();

-- Sessions ----------------------------------------------------------------

-- A browser session. id_hash is the HMAC-SHA256 of the session token under
-- the derived "session" key; the token itself is never stored.
-- authenticated_at is the provider's auth_time, used for step-up, which the
-- app clamps to the present; amr is the provider's amr claim; provider_sid is
-- its sid, for back-channel logout.
CREATE TABLE sessions (
  id_hash text PRIMARY KEY CHECK (id_hash ~ '^[0-9a-f]{64}$'),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  authenticated_at timestamptz NOT NULL,
  amr text[] NOT NULL DEFAULT '{}' CHECK (array_position(amr, NULL) IS NULL),
  expires_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  provider_sid text CHECK (provider_sid <> '' AND length(provider_sid) <= 255),
  CONSTRAINT sessions_expires_after_created CHECK (expires_at > created_at),
  CONSTRAINT sessions_idle_within_expiry CHECK (
    idle_expires_at > created_at AND idle_expires_at <= expires_at
  ),
  CONSTRAINT sessions_revoked_after_created CHECK (revoked_at >= created_at)
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_provider_sid_idx ON sessions (provider_sid) WHERE provider_sid IS NOT NULL;
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- Only an active, undeleted user can get a new session.
CREATE FUNCTION sessions_before_insert() RETURNS trigger
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
  RETURN NEW;
END
$$;

CREATE TRIGGER sessions_before_insert
BEFORE INSERT ON sessions
FOR EACH ROW EXECUTE FUNCTION sessions_before_insert();

-- A session's identity, owner and absolute expiry are fixed, revocation is
-- final, and authenticated_at only moves forward. Only idle_expires_at,
-- authenticated_at, amr and provider_sid change, for activity and step-up.
CREATE FUNCTION sessions_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.id_hash <> OLD.id_hash
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

CREATE TRIGGER sessions_before_update
BEFORE UPDATE ON sessions
FOR EACH ROW EXECUTE FUNCTION sessions_before_update();

-- Audit log ---------------------------------------------------------------

-- One row per AuditEvent. Rows outlive the users they mention, so user ids
-- carry no foreign key. Rows are never updated; old rows may be deleted for
-- retention.
CREATE TABLE audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  type text NOT NULL CHECK (type ~ '^[a-z][a-z_]*(\.[a-z][a-z_]*)+$'),
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'idp', 'operator', 'system')),
  actor_user_id uuid,
  actor_issuer text CHECK (actor_issuer <> ''),
  credential_kind text CHECK (credential_kind IN ('session', 'api_key', 'oauth')),
  credential_id text CHECK (credential_id <> ''),
  subject_user_id uuid,
  ip inet,
  user_agent text CHECK (length(user_agent) <= 512),
  data jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(data) = 'object'),
  CONSTRAINT audit_events_user_actor CHECK ((actor_type = 'user') = (actor_user_id IS NOT NULL)),
  CONSTRAINT audit_events_idp_actor CHECK ((actor_type = 'idp') = (actor_issuer IS NOT NULL)),
  CONSTRAINT audit_events_credential CHECK (
    (credential_kind IS NULL) = (credential_id IS NULL)
    AND (credential_kind IS NULL OR actor_type = 'user')
  )
);

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);
CREATE INDEX audit_events_subject_idx ON audit_events (subject_user_id, occurred_at)
  WHERE subject_user_id IS NOT NULL;
CREATE INDEX audit_events_actor_idx ON audit_events (actor_user_id, occurred_at)
  WHERE actor_user_id IS NOT NULL;

CREATE FUNCTION audit_events_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = 'check_violation';
END
$$;

CREATE TRIGGER audit_events_before_update
BEFORE UPDATE ON audit_events
FOR EACH ROW EXECUTE FUNCTION audit_events_before_update();
