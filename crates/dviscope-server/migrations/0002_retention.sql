-- Retention (plan B.16): tombstones of expired regressions and receipts, so a late record
-- is answered with 410 (E_EXPIRED, E_REPLAY_EXPIRED) instead of being taken as new.

CREATE TABLE expired_regressions (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    producer_id  BIGINT NOT NULL,
    ref          TEXT NOT NULL,
    expired_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, producer_id, ref),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);

CREATE TABLE expired_receipts (
    project_id    BIGINT NOT NULL REFERENCES projects (id),
    producer_id   BIGINT NOT NULL,
    identity      TEXT NOT NULL,
    max_revision  INTEGER NOT NULL CHECK (max_revision > 0),
    expired_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, producer_id, identity),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);

CREATE INDEX receipts_age ON receipts (received_at);
CREATE INDEX regressions_age ON regressions (project_id, started_at);
