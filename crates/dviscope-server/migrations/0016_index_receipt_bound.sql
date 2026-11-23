-- Stage 4 review r5, finding 1: a candidate-index row inserted after the upgrade for a legacy
-- regression (unknown receipt time) must keep the regression's receipt bound in the
-- permanent index, which outlives the regression. A trigger copies it on insert; existing
-- rows get it now (those whose regression is already gone take this migration's time, a
-- valid upper bound of a receipt that happened before it).

CREATE FUNCTION candidate_index_receipt_bound() RETURNS trigger AS $$
BEGIN
    IF NEW.received_at IS NULL AND NEW.receipt_bound IS NULL THEN
        SELECT coalesce(r.receipt_bound, now()) INTO NEW.receipt_bound
          FROM regressions r
         WHERE r.project_id = NEW.project_id AND r.id = NEW.regression_id;
        IF NEW.receipt_bound IS NULL THEN
            NEW.receipt_bound := now();
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER candidate_index_receipt_bound
    BEFORE INSERT ON candidate_index
    FOR EACH ROW EXECUTE FUNCTION candidate_index_receipt_bound();

UPDATE candidate_index i
   SET receipt_bound = coalesce(r.receipt_bound, now())
  FROM regressions r
 WHERE i.project_id = r.project_id AND i.regression_id = r.id
   AND i.received_at IS NULL AND i.receipt_bound IS NULL;

UPDATE candidate_index
   SET receipt_bound = now()
 WHERE received_at IS NULL AND receipt_bound IS NULL;
