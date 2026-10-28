# Avgeek OSS Auth

Shared sign-in, provisioning and access control for Avgeek OSS apps. Each app signs people in through the organisation's OpenID Connect identity provider, accepts SCIM 2.0 provisioning from it, and gives every person one of three roles: `viewer`, `member` or `admin`. The packages in this repository hold the parts that every app would otherwise build again: configuration, key derivation, token handling, roles, the Postgres schema and its migrations.
