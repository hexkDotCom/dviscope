-- Bindings for identities that retention had already thinned before migration 0004
-- (Stage 3 review r4). Recover what the retained data still says; every other identity
-- the server has ever seen is bound to a marker no parent can equal ('|' never occurs in
-- an external key), so it is refused for good instead of being claimed by a new parent.

-- Report → attempt from retained payloads.
INSERT INTO report_bindings (project_id, producer_id, report_id, attempt_ref)
SELECT DISTINCT ON (p.project_id, r.producer_id, p.payload->>'report_id')
       p.project_id, r.producer_id, p.payload->>'report_id', a.attempt_ref
  FROM attempt_reports p
  JOIN attempts a ON a.project_id = p.project_id AND a.id = p.attempt_id
  JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
  JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
 WHERE p.payload->>'report_id' IS NOT NULL
 ORDER BY p.project_id, r.producer_id, p.payload->>'report_id', p.report_revision
ON CONFLICT DO NOTHING;

-- Known report identities (live or expired receipts) without a recoverable parent.
INSERT INTO report_bindings (project_id, producer_id, report_id, attempt_ref)
SELECT DISTINCT project_id, producer_id, substr(identity, 20), '|unrecoverable'
  FROM (SELECT project_id, producer_id, identity FROM receipts
         WHERE identity LIKE 'simulation_attempt:%'
        UNION
        SELECT project_id, producer_id, identity FROM expired_receipts
         WHERE identity LIKE 'simulation_attempt:%') k
ON CONFLICT DO NOTHING;

-- Known attempt identities (start records) without a recoverable parent.
INSERT INTO attempt_bindings (project_id, producer_id, attempt_ref, regression_ref, slot_ref)
SELECT DISTINCT project_id, producer_id, substr(identity, 17), '|unrecoverable', ''
  FROM (SELECT project_id, producer_id, identity FROM receipts
         WHERE identity LIKE 'attempt_started:%'
        UNION
        SELECT project_id, producer_id, identity FROM expired_receipts
         WHERE identity LIKE 'attempt_started:%') k
ON CONFLICT DO NOTHING;
