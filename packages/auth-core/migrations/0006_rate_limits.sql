-- Rate limit buckets for the generic cell rate algorithm (GCRA): one
-- theoretical arrival time per key. The key is the HMAC-SHA256 of the
-- policy name and the limited value (an IP prefix, a client id, a user id)
-- under the derived "rate-limit" key, so no raw address, email or client id
-- is stored. A bucket whose arrival time has passed is the same as no
-- bucket, so expires_at lets sweeps delete it.
CREATE TABLE rate_limit_buckets (
  key_hash text PRIMARY KEY CHECK (key_hash ~ '^[0-9a-f]{64}$'),
  -- When the bucket is empty again if nothing more arrives.
  tat timestamptz NOT NULL,
  -- Whether the last request was allowed; returned by the same statement.
  allowed boolean NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX rate_limit_buckets_expires_at_idx ON rate_limit_buckets (expires_at);
