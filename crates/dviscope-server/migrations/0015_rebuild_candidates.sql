-- Stage 4 review r2, finding 4: code between migrations 0012 and 0013 deleted the candidate
-- index row of a test/configuration when its last slot was removed. Removals are now judged
-- at evaluation time (a removal that does not count keeps the regression the candidate), so
-- every declared slot, removed or not, has its index row again (with the regression's
-- receipt time, or none and its bound when that time is unknown).

INSERT INTO candidate_index (project_id, branch, test, config_digest, simulator, regression_id,
                             regression_ref, producer_id, started_at, received_at, receipt_bound)
SELECT DISTINCT ON (s.project_id, s.regression_id, s.test, s.config_digest)
       s.project_id, r.branch_repository || '/' || r.branch_name, s.test, s.config_digest,
       coalesce(s.decl #>> '{build_reqs,0,build_config,simulator,vendor}',
                s.decl #>> '{exec_inputs,extra,tool,simulator}', ''),
       r.id, r.ref, r.producer_id, r.started_at, r.received_at, r.receipt_bound
  FROM slots s JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
 ORDER BY s.project_id, s.regression_id, s.test, s.config_digest, s.id
ON CONFLICT DO NOTHING;
