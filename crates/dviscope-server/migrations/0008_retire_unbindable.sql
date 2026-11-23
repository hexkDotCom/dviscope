-- Migration boundary for identities nothing can recover (Stage 3 review r5): a producer
-- whose regressions retention removed before identity bindings existed (migration 0004)
-- may have had attempt references that survive nowhere. Its namespace is retired: every
-- later record from it is refused (410), and the operator creates a new producer and
-- token. Producers without such a loss are unaffected.
ALTER TABLE producers ADD COLUMN retired_at TIMESTAMPTZ;
ALTER TABLE producers ADD COLUMN retired_reason TEXT;

UPDATE producers p
   SET retired_at = now(),
       retired_reason = 'identities lost to retention before identity bindings existed'
 WHERE EXISTS (
       SELECT 1 FROM expired_regressions e
         JOIN schema_migrations m ON m.version = 4
        WHERE e.project_id = p.project_id AND e.producer_id = p.id
          AND e.expired_at < m.applied_at);
