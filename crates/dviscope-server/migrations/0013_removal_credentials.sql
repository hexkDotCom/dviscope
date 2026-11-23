-- Expected-set removals record their credential and time (plan B.13 case 22): a removal by
-- a credential quarantined since before it does not shrink the denominator, and readiness
-- is insufficient until the removal is re-made with a valid credential or the quarantine is
-- released. Earlier removals (unknown credential) stay as they are.

ALTER TABLE slots ADD COLUMN removed_by BIGINT;
ALTER TABLE slots ADD COLUMN removed_at TIMESTAMPTZ;
