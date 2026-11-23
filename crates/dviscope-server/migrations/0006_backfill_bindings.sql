-- Backfill the identity bindings of migration 0004 from the retained facts, so an
-- upgraded database binds every existing attempt and report before new records arrive.
-- An attempt reference found in several slots (possible before 0004) keeps its first
-- slot; the others cannot be bound and are refused on any new revision.
INSERT INTO attempt_bindings (project_id, producer_id, attempt_ref, regression_ref, slot_ref)
SELECT DISTINCT ON (r.project_id, r.producer_id, a.attempt_ref)
       r.project_id, r.producer_id, a.attempt_ref, r.ref, s.slot_ref
  FROM attempts a
  JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
  JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
 ORDER BY r.project_id, r.producer_id, a.attempt_ref, a.id
ON CONFLICT DO NOTHING;

INSERT INTO report_bindings (project_id, producer_id, report_id, attempt_ref)
SELECT DISTINCT ON (rc.project_id, rc.producer_id, substr(rc.identity, 20))
       rc.project_id, rc.producer_id, substr(rc.identity, 20), a.attempt_ref
  FROM receipts rc
  JOIN attempts a ON a.project_id = rc.project_id
                 AND a.id = (rc.receipt->'server_ids'->>'attempt')::bigint
 WHERE rc.identity LIKE 'simulation_attempt:%'
 ORDER BY rc.project_id, rc.producer_id, substr(rc.identity, 20), rc.revision
ON CONFLICT DO NOTHING;
