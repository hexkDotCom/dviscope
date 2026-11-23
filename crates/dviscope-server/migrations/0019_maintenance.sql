-- Safe restore (plan B.17): maintenance mode (writes refused) and tokens disabled by a
-- restore until re-enabled or rotated (a disabled token's expiry is set to the restore
-- time; its original expiry is kept here for re-enabling).

CREATE TABLE maintenance (
    id          BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    active      BOOLEAN NOT NULL DEFAULT false,
    reason      TEXT NOT NULL DEFAULT '',
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO maintenance (id) VALUES (true);

CREATE TABLE restore_disabled_tokens (
    token_id             BIGINT PRIMARY KEY REFERENCES api_tokens (id),
    original_expires_at  TIMESTAMPTZ NOT NULL,
    disabled_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
