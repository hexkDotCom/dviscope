import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, enc, type Changes } from "../api/client";

/**
 * An evaluation is valid at its snapshot only: it becomes stale after any later change of
 * the project (the change feed past its watermark) or once its `valid_until` passes. The
 * page then says so instead of showing a result that may no longer hold.
 */
/** The longest delay a browser timer honors. */
export const MAX_TIMER_MS = 2 ** 31 - 1;

export function useStale(
  project: string,
  changeSeq: number | undefined,
  validUntil: string | null | undefined,
): string | null {
  const [expired, setExpired] = useState(false);
  useEffect(() => {
    setExpired(false);
    if (!validUntil) return;
    const deadline = Date.parse(validUntil);
    if (Number.isNaN(deadline)) return;
    let t: ReturnType<typeof setTimeout> | undefined;
    // Timers cap at about 24.8 days: when one fires early, the deadline is checked again
    // and the rest is scheduled (a long validity never expires early).
    const schedule = () => {
      const ms = deadline - Date.now();
      if (ms <= 0) {
        setExpired(true);
        return;
      }
      t = setTimeout(schedule, Math.min(ms, MAX_TIMER_MS));
    };
    schedule();
    return () => {
      if (t !== undefined) clearTimeout(t);
    };
  }, [validUntil, changeSeq]);
  const feed = useQuery({
    queryKey: ["stale", project, changeSeq],
    enabled: changeSeq !== undefined,
    queryFn: () =>
      api<Changes>(`/api/v1/projects/${enc(project)}/changes?since=${changeSeq ?? 0}`),
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });
  if (expired) return `its validity ended at ${validUntil}`;
  // A failed check is not "unchanged": say freshness is unknown until a check succeeds.
  if (feed.isError) return "freshness cannot be checked (the change feed is unreachable)";
  const n = Array.isArray(feed.data?.changes) ? feed.data.changes.length : 0;
  if (n > 0) {
    return `${n} change(s) since it was evaluated`;
  }
  return null;
}

export function StaleBanner({ reason, onRefresh }: { reason: string | null; onRefresh: () => void }) {
  if (!reason) return null;
  return (
    <p className="stale" role="alert">
      Stale: {reason}. This result may no longer hold.{" "}
      <button type="button" onClick={onRefresh}>
        Re-evaluate
      </button>
    </p>
  );
}
