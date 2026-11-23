-- Final pre-release review: repairs of data written before its fixes.
--
-- S2: `repository/branch` names a branch wherever it keys decisions (triage cases,
-- exceptions, feature candidates). A repository name with '/' (now refused at creation)
-- could make two branches one; such data cannot be repaired automatically, so the upgrade
-- stops and names it rather than let a decision cross branches.
DO $$
DECLARE bad TEXT;
BEGIN
    SELECT string_agg(DISTINCT branch_repository, ', ') INTO bad
      FROM regressions WHERE branch_repository = '' OR position('/' in branch_repository) > 0;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'repository names with "/" (or empty) are no longer accepted: %; '
                        'restore this database with the previous version and contact the '
                        'maintainers before upgrading', bad;
    END IF;
    -- A decision whose branch key has two or more '/' ("a/b/c") cannot be attributed: it may
    -- have been made for repository "a/b" (whose regressions retention may have removed) and
    -- would then apply to repository "a", branch "b/c". No stored record tells them apart,
    -- even a surviving regression of "a" + "b/c", so the upgrade stops and names them.
    SELECT string_agg(DISTINCT d.branch, ', ') INTO bad
      FROM (SELECT branch FROM exceptions
            UNION SELECT branch FROM triage_cases
            UNION SELECT branch FROM candidate_index) d
     WHERE d.branch ~ '/.*/';
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'decisions on branch keys with two or more "/" cannot be attributed to '
                        'one repository and branch: %; contact the maintainers before upgrading',
                        bad;
    END IF;
END $$;

-- S4: a manifest chunk replaced before the seal left the feature candidates of its old
-- slots; a live candidate of an existing regression that no slot declares is removed
-- (candidates of regressions retention removed are tombstones and stay).
DELETE FROM candidate_index ci
 WHERE ci.state = 'live'
   AND EXISTS (SELECT 1 FROM regressions r
                WHERE r.project_id = ci.project_id AND r.id = ci.regression_id)
   AND NOT EXISTS (SELECT 1 FROM slots s
                    WHERE s.project_id = ci.project_id AND s.regression_id = ci.regression_id
                      AND s.test = ci.test AND s.config_digest = ci.config_digest);
