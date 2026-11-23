-- Receipt times must be the server's own (Stage 4 review r1 finding 13, r3 finding 2).
-- Migration 0012 backfilled `received_at` of existing regressions (and their candidate-index
-- rows) from their reported start, which a producer controls. Those rows take the time of the
-- regression's first receipt when it is still kept. Otherwise the receipt time stays unknown
-- (NULL: the regression's time is uncertain, it can never be fresh), and `receipt_bound`
-- records an upper bound (this migration's time: the server had the regression by then),
-- used only to order it against regressions with known times. Rows created after 0012 carry
-- the server's time.

ALTER TABLE regressions ALTER COLUMN received_at DROP NOT NULL;
ALTER TABLE regressions ADD COLUMN receipt_bound TIMESTAMPTZ;
ALTER TABLE candidate_index ALTER COLUMN received_at DROP NOT NULL;
ALTER TABLE candidate_index ADD COLUMN receipt_bound TIMESTAMPTZ;

UPDATE regressions r
   SET received_at = (SELECT min(c.received_at) FROM receipts c
                       WHERE c.project_id = r.project_id AND c.producer_id = r.producer_id
                         AND c.identity = 'regression:' || r.ref),
       receipt_bound = now()
 WHERE r.received_at = r.started_at;

UPDATE regressions SET receipt_bound = NULL WHERE received_at IS NOT NULL;

UPDATE candidate_index i
   SET received_at = r.received_at, receipt_bound = r.receipt_bound
  FROM regressions r
 WHERE i.project_id = r.project_id AND i.regression_id = r.id
   AND i.received_at = i.started_at;

-- Regressions already gone (expired): their backfilled times cannot be verified.
UPDATE candidate_index i
   SET received_at = NULL, receipt_bound = now()
 WHERE i.received_at = i.started_at
   AND NOT EXISTS (SELECT 1 FROM regressions r
                    WHERE r.project_id = i.project_id AND r.id = i.regression_id);
