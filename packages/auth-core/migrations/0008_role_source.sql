-- Roles come from the identity provider: the role claim at sign-in ('oidc')
-- or SCIM group membership ('scim'); 'admin' stays reserved for a role an
-- app's admin sets. There is no operator tool, so 'operator' is no longer a
-- source. Nothing ever wrote it.
ALTER TABLE users DROP CONSTRAINT users_role_source_check;
ALTER TABLE users ADD CONSTRAINT users_role_source_check
  CHECK (role_source IN ('oidc', 'scim', 'admin'));
