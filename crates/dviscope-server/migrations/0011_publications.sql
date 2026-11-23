-- Published statuses (plan B.11): each publication receipt keeps the evaluation's log-free
-- summary (immutable) and the bookkeeping of the commit status it backs: its target, when
-- the code host accepted it, the last refresh that found the basis unchanged, and the
-- monitoring deadline. A receipt is retired only after the host accepted its replacement
-- or its final pending update.

ALTER TABLE publication_receipts
    ADD COLUMN regression_ref    TEXT,
    ADD COLUMN producer_id       BIGINT,
    ADD COLUMN expect_source     TEXT,
    ADD COLUMN target_repository TEXT,
    ADD COLUMN target_commit     TEXT,
    ADD COLUMN target_context    TEXT,
    ADD COLUMN valid_until       TIMESTAMPTZ,
    ADD COLUMN status_state      TEXT CHECK (status_state IN ('success', 'failure', 'pending', 'error')),
    ADD COLUMN posted_at         TIMESTAMPTZ,
    ADD COLUMN last_refresh_at   TIMESTAMPTZ,
    ADD COLUMN retired_reason    TEXT;

CREATE INDEX publication_receipts_open
    ON publication_receipts (project_id, target_repository, target_commit, target_context)
    WHERE retired_at IS NULL;
