-- Tombstones written before this migration recorded retention's evaluation clock (which
-- a caller could set), not the time of the deletion (Stage 3 review r8): their order
-- against the binding backfill cannot be proven. Conservatively, every producer with such
-- a regression tombstone is retired. From here on retention records the database time.
UPDATE producers p
   SET retired_at = now(),
       retired_reason = 'regressions removed before deletion times were recorded reliably'
 WHERE p.retired_at IS NULL
   AND EXISTS (SELECT 1 FROM expired_regressions e
                WHERE e.project_id = p.project_id AND e.producer_id = p.id);
