-- Stage 4 review r6 finding 3, r7 finding 1: feature selection must not change when a
-- regression's slots expire. Every removal of a slot (credential, time, or legacy: before
-- 0013, credential unknown) is kept permanently in `candidate_removals`, and the candidate
-- index records whether all slots of a regression's test/configuration are removed. A
-- candidate is excluded only when all its slots are removed and none of those removals is
-- untrusted (made by a credential quarantined since before it, or legacy while any
-- credential of the producer is quarantined). Triggers keep both up to date.

ALTER TABLE candidate_index ADD COLUMN removed BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE candidate_removals (
    project_id     BIGINT NOT NULL,
    regression_id  BIGINT NOT NULL,             -- no foreign key: outlives the regression
    slot_ref       TEXT NOT NULL,
    test           TEXT NOT NULL,
    config_digest  TEXT NOT NULL,
    removed_by     BIGINT,                      -- NULL: removed before 0013 (legacy)
    removed_at     TIMESTAMPTZ,
    PRIMARY KEY (project_id, regression_id, slot_ref)
);
CREATE INDEX candidate_removals_candidate
    ON candidate_removals (project_id, regression_id, test, config_digest);

-- Whether every slot of a regression's test/configuration is removed.
CREATE FUNCTION candidate_all_removed(p BIGINT, r BIGINT, t TEXT, c TEXT) RETURNS BOOLEAN AS $$
    SELECT EXISTS (SELECT 1 FROM slots s
                    WHERE s.project_id = p AND s.regression_id = r
                      AND s.test = t AND s.config_digest = c)
       AND NOT EXISTS (SELECT 1 FROM slots s
                        WHERE s.project_id = p AND s.regression_id = r
                          AND s.test = t AND s.config_digest = c
                          AND s.removed_revision IS NULL)
$$ LANGUAGE sql STABLE;

CREATE FUNCTION candidate_removal_from_slot() RETURNS trigger AS $$
BEGIN
    IF NEW.removed_revision IS NOT NULL THEN
        INSERT INTO candidate_removals (project_id, regression_id, slot_ref, test, config_digest,
                                        removed_by, removed_at)
        VALUES (NEW.project_id, NEW.regression_id, NEW.slot_ref, NEW.test, NEW.config_digest,
                NEW.removed_by, NEW.removed_at)
        ON CONFLICT (project_id, regression_id, slot_ref)
        DO UPDATE SET removed_by = EXCLUDED.removed_by, removed_at = EXCLUDED.removed_at;
    ELSE
        DELETE FROM candidate_removals
         WHERE project_id = NEW.project_id AND regression_id = NEW.regression_id
           AND slot_ref = NEW.slot_ref;
    END IF;
    UPDATE candidate_index
       SET removed = candidate_all_removed(NEW.project_id, NEW.regression_id, NEW.test,
                                           NEW.config_digest)
     WHERE project_id = NEW.project_id AND regression_id = NEW.regression_id
       AND test = NEW.test AND config_digest = NEW.config_digest;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER candidate_removal_from_slot
    AFTER INSERT OR UPDATE OF removed_revision, removed_by, removed_at ON slots
    FOR EACH ROW EXECUTE FUNCTION candidate_removal_from_slot();

-- A new index row (a late slot or an index rebuild) starts from its slots' state.
CREATE FUNCTION candidate_index_removed_on_insert() RETURNS trigger AS $$
BEGIN
    NEW.removed := candidate_all_removed(NEW.project_id, NEW.regression_id, NEW.test,
                                         NEW.config_digest);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER candidate_index_removed_on_insert
    BEFORE INSERT ON candidate_index
    FOR EACH ROW EXECUTE FUNCTION candidate_index_removed_on_insert();

-- Backfill from the slots that still exist.
INSERT INTO candidate_removals (project_id, regression_id, slot_ref, test, config_digest,
                                removed_by, removed_at)
SELECT project_id, regression_id, slot_ref, test, config_digest, removed_by, removed_at
  FROM slots WHERE removed_revision IS NOT NULL
ON CONFLICT DO NOTHING;

UPDATE candidate_index c
   SET removed = candidate_all_removed(c.project_id, c.regression_id, c.test, c.config_digest);
