-- Equivalent digests of a receipt (Stage 7 F5): a source manifest declared again under a
-- later, compatible development schema label. The receipt keeps the digest it was received
-- with; reconciliation lists the aliases after it, so collectors of either label match.
CREATE TABLE receipt_aliases (
    project_id  BIGINT NOT NULL,
    producer_id BIGINT NOT NULL,
    identity    TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    digest      TEXT NOT NULL,
    PRIMARY KEY (project_id, producer_id, identity, revision, digest),
    FOREIGN KEY (project_id, producer_id, identity, revision)
        REFERENCES receipts (project_id, producer_id, identity, revision) ON DELETE CASCADE
);
