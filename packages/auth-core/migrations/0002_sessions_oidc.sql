-- Sign-in support: where each role came from, the back-channel logout
-- replay cache, and an index for listing and revoking a user's sessions.

-- Where users.role was last set: 'oidc' is the role claim at sign-in.
ALTER TABLE users
  ADD COLUMN role_source text NOT NULL DEFAULT 'none'
  CHECK (role_source IN ('none', 'oidc', 'scim', 'admin', 'operator'));

-- Back-channel logout token ids already accepted, kept until the token would
-- be refused as too old anyway.
CREATE TABLE logout_jtis (
  iss text NOT NULL CHECK (iss <> ''),
  jti text NOT NULL CHECK (jti <> '' AND length(jti) <= 255),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (iss, jti)
);

CREATE INDEX logout_jtis_expires_at_idx ON logout_jtis (expires_at);

-- Replaces sessions_user_id_idx: the same prefix, and covers the
-- "live sessions of a user" filter.
CREATE INDEX sessions_user_id_revoked_at_idx ON sessions (user_id, revoked_at);
DROP INDEX sessions_user_id_idx;
