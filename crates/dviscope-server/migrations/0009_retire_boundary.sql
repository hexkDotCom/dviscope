-- Corrects the boundary of migration 0008 (Stage 3 review r6, r7): the binding backfill
-- completed with migration 0006 (0004 only created empty tables), so a producer whose
-- regressions retention removed before 0006 was applied is retired too.
UPDATE producers p
   SET retired_at = now(),
       retired_reason = 'identities lost to retention before the binding backfill completed'
 WHERE p.retired_at IS NULL
   AND EXISTS (
       SELECT 1 FROM expired_regressions e
         JOIN schema_migrations m ON m.version = 6
        WHERE e.project_id = p.project_id AND e.producer_id = p.id
          AND e.expired_at < m.applied_at);
