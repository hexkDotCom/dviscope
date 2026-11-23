-- Test growth (health dashboard): each stream's sealed regressions by start, newest first.
-- Serves the period's regressions of a stream and its last one before the period (a top-1
-- lookup) without visiting unsealed regressions or other producers' rows.
CREATE INDEX regressions_stream_sealed
    ON regressions (project_id, producer_id, suite, branch_repository, branch_name,
                    started_at DESC, id DESC)
 WHERE sealed;
