import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  ApiError,
  api,
  enc,
  type BulkTriageResult,
  type Changes,
  type Comparison,
  type ComparisonRow,
  type FinishCard,
  type Header,
  type RegressionRead,
  type RepairList,
} from "../api/client";
import { CopyButton } from "../components/CopyButton";
import { Empty, ErrorBox, Loading, Section, StateBadge } from "../components/ui";

export function HeaderCounts({ h }: { h: Header }) {
  const parts: [string, number][] = [
    ["planned", h.planned],
    ["passed", h.passed],
    ["failed", h.failed],
    ["blocked", h.blocked],
    ["missing", h.missing],
    ["running", h.running],
    ["cancelled", h.cancelled],
    ["skipped", h.skipped],
  ];
  return (
    <p className="counts">
      {parts
        .filter(([k, n]) => k === "planned" || n > 0)
        .map(([k, n]) => `${n} ${k}`)
        .join(" · ")}
      {h.signatures > 0 &&
        ` — ${h.signatures} signature${h.signatures === 1 ? "" : "s"} over ${h.slots_with_signatures} failed slot${h.slots_with_signatures === 1 ? "" : "s"}`}
    </p>
  );
}

export function FinishCardView({
  f,
  stale = false,
}: {
  f: FinishCard;
  missing?: number;
  stale?: boolean;
}) {
  const kinds = Object.entries(f.merge_blocker_kinds ?? {})
    .map(([k, n]) => `${n} ${k.replace(/_/g, " ")}`)
    .join(", ");
  return (
    <div className="card" data-testid="finish-card">
      <p>
        Triage accounted for: {f.groups - f.needs_decision}/{f.groups} groups ({f.needs_decision}{" "}
        need decision · {f.assigned} assigned · {f.covered} covered).
      </p>
      <p>
        Merge readiness:{" "}
        {stale
          ? "unknown until the comparison is read again (an exception expired)"
          : f.merge_blockers > 0
            ? `blocked by ${f.merge_blockers} blocker${f.merge_blockers === 1 ? "" : "s"} (${kinds})`
            : "no blockers in this regression (the candidate binding is checked on the readiness page)"}
        .
      </p>
      {f.partly_covered_slots && (
        <p className="warning">
          Group coverage is not slot acceptance: some failed slots have an exception for one
          group and stay blocked by another.
        </p>
      )}
    </div>
  );
}

/** Polls the change feed every 30 s; never reorders what is shown until asked. */
function ChangeStrip({ project }: { project: string }) {
  const qc = useQueryClient();
  const since = useRef<number | null>(null);
  const q = useQuery({
    queryKey: ["changes", project],
    queryFn: () =>
      api<Changes>(`/api/v1/projects/${enc(project)}/changes?since=${since.current ?? 0}`),
    refetchInterval: 30_000,
  });
  if (!q.data) return null;
  if (since.current === null) {
    since.current = q.data.change_seq;
    return null;
  }
  const n = q.data.changes.filter((c) => c.seq > (since.current ?? 0)).length;
  if (n === 0) return null;
  return (
    <p className="strip" role="status">
      {n} decision{n === 1 ? "" : "s"} changed since this page loaded.{" "}
      <button
        type="button"
        onClick={() => {
          since.current = q.data.change_seq;
          void qc.invalidateQueries({
            predicate: (x) => x.queryKey[0] !== "changes",
          });
          void qc.invalidateQueries({ queryKey: ["changes", project] });
        }}
      >
        Refresh
      </button>
    </p>
  );
}

/** Most signatures one bulk triage saves (the server's limit). */
export const MAX_BULK = 500;

/** The bulk form's fields, kept by the page: they survive any change of the selection
 * (also through an empty one) until they are saved. */
type BulkDraft = { state: string; owner: string; notes: string; bugs: string };
const EMPTY_DRAFT: BulkDraft = { state: "open", owner: "", notes: "", bugs: "" };

/** The request of a bulk triage: one decision for these rows, each with its base revision. */
function bulkRequest(project: string, branch: string, rows: ComparisonRow[], d: BulkDraft) {
  return api<BulkTriageResult>(`/api/v1/projects/${enc(project)}/triage?branch=${enc(branch)}`, {
    method: "POST",
    body: {
      signatures: rows.map((r) =>
        r.triage_revision != null ? { number: r.number, if_match: r.triage_revision } : { number: r.number },
      ),
      state: d.state,
      owner: d.owner.trim() ? d.owner.trim() : null,
      notes: d.notes,
      bug_urls: d.bugs
        .split("\n")
        .map((x) => x.trim())
        .filter(Boolean),
    },
  });
}

/** The bulk form: one triage decision for the selected signatures of the regression's
 * branch, all or nothing. The page owns its draft and its save, so both survive the form
 * being unmounted (an empty selection, a comparison reloading). */
function BulkTriage({
  branch,
  rows,
  draft,
  setDraft,
  save,
}: {
  branch: string;
  rows: ComparisonRow[];
  draft: BulkDraft;
  setDraft: (d: BulkDraft) => void;
  save: { isPending: boolean; error: Error | null; mutate: () => void };
}) {
  const { state, owner, notes, bugs } = draft;
  const setState = (v: string) => setDraft({ ...draft, state: v });
  const setOwner = (v: string) => setDraft({ ...draft, owner: v });
  const setNotes = (v: string) => setDraft({ ...draft, notes: v });
  const setBugs = (v: string) => setDraft({ ...draft, bugs: v });
  const existing = rows.filter((r) => r.triage_revision != null).length;
  const conflict = save.error instanceof ApiError && save.error.status === 412;
  const tooMany = rows.length > MAX_BULK;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!tooMany) save.mutate();
  };
  return (
    <form className="editor" onSubmit={submit} data-testid="bulk-triage">
      <h3>
        Triage {rows.length} selected signature{rows.length === 1 ? "" : "s"} on {branch}
      </h3>
      {existing > 0 && (
        <p className="warning">
          {existing} of them already {existing === 1 ? "has" : "have"} a triage case on this
          branch: this replaces {existing === 1 ? "its" : "their"} state, owner, notes and bug
          links.
        </p>
      )}
      {/* Frozen while saving: what is sent is what stays shown until it is saved. */}
      <label>
        State
        <select value={state} disabled={save.isPending} onChange={(e) => setState(e.target.value)}>
          <option value="open">open</option>
          <option value="closed">closed</option>
        </select>
      </label>
      <label>
        Owner
        <input value={owner} maxLength={64} disabled={save.isPending} onChange={(e) => setOwner(e.target.value)} />
      </label>
      <label>
        Notes
        <textarea value={notes} disabled={save.isPending} onChange={(e) => setNotes(e.target.value)} />
      </label>
      <label>
        Bug links (one per line)
        <textarea value={bugs} disabled={save.isPending} onChange={(e) => setBugs(e.target.value)} />
      </label>
      {tooMany && (
        <p className="warning" role="alert">
          At most {MAX_BULK} signatures can be triaged at once: clear some of the selection.
        </p>
      )}
      <button type="submit" disabled={save.isPending || tooMany}>
        {save.isPending ? `Saving ${rows.length}…` : `Save triage for ${rows.length}`}
      </button>
      {save.error &&
        (conflict ? (
          <p role="alert" className="error">
            Someone else changed one of these cases ({save.error.message}). Nothing was saved:
            refresh the page and try again.
          </p>
        ) : (
          <ErrorBox error={save.error} />
        ))}
    </form>
  );
}

const DISPOSITION_LABEL: Record<string, string> = {
  needs_decision: "needs decision",
  assigned: "assigned",
  covered: "covered by exception",
};

const BASELINE_LABEL: Record<string, string> = {
  in_baseline: "also in baseline",
  absent_from_baseline: "new",
  not_observed: "not observed in baseline",
  no_baseline: "—",
};

export function RegressionPage() {
  const { project = "", regression = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const producer = params.get("producer");
  const baseline = params.get("baseline");
  const [baselineInput, setBaselineInput] = useState(baseline ?? "");
  const prod = producer ? `producer=${enc(producer)}` : "";
  const root = `/api/v1/projects/${enc(project)}/regressions/${enc(regression)}`;
  const read = useQuery({
    queryKey: ["regression", project, regression, producer],
    queryFn: () => api<RegressionRead>(`${root}?${prod}`),
  });
  const cmp = useQuery({
    queryKey: ["comparison", project, regression, producer, baseline],
    queryFn: () =>
      api<Comparison>(
        `${root}/comparison?${[prod, baseline ? `baseline=${enc(baseline)}` : ""]
          .filter(Boolean)
          .join("&")}`,
      ),
  });
  const repair = useQuery({
    queryKey: ["repair", project, regression, producer],
    queryFn: () => api<RepairList>(`${root}/repair-list?${prod}`),
  });
  const qc = useQueryClient();
  // A row covered by an exception stops being covered when the exception expires. The
  // comparison carries only exceptions active when the server evaluated it, so one that has
  // expired since makes what is shown out of date, however late the answer arrived (also
  // when the page is shown again from the cache, and through re-reads that fail), until a
  // comparison without it arrives; the comparison is read again.
  const [now, setNow] = useState(() => Date.now());
  const expiries = (cmp.data?.comparison.rows ?? [])
    .map((r) => (r.exception ? Date.parse(r.exception.expires_at) : Number.NaN))
    .filter((t) => Number.isFinite(t));
  const claimStale = expiries.some((t) => t <= now);
  const nextExpiry = expiries
    .filter((t) => t > now)
    .reduce((a, b) => Math.min(a, b), Number.POSITIVE_INFINITY);
  // A timer waits at most ~24.8 days; one that wakes before the expiry (a 180-day exception)
  // advances `now` and is armed again.
  useEffect(() => {
    if (!Number.isFinite(nextExpiry)) return;
    const id = setTimeout(
      () => setNow(Date.now()),
      Math.min(nextExpiry - Date.now() + 1000, 2_147_483_647),
    );
    return () => clearTimeout(id);
  }, [nextExpiry, now]);
  // Read again at once when it becomes out of date; while a read still carries the expired
  // exception (the server's clock behind this one), again every few seconds.
  const staleReads = useRef(0);
  useEffect(() => {
    if (!claimStale) {
      staleReads.current = 0;
      return;
    }
    const delay = staleReads.current === 0 ? 0 : 5000;
    staleReads.current += 1;
    const id = setTimeout(
      () => void qc.invalidateQueries({ queryKey: ["comparison", project, regression] }),
      delay,
    );
    return () => clearTimeout(id);
  }, [claimStale, cmp.dataUpdatedAt, qc, project, regression]);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [draft, setDraft] = useState<BulkDraft>(EMPTY_DRAFT);
  // The bulk save belongs to the page: a reload of the comparison (another baseline) never
  // drops it, and the selection and baseline stay frozen until it ends.
  const bulk = useMutation({
    mutationFn: (v: { branch: string; rows: ComparisonRow[]; draft: BulkDraft }) =>
      bulkRequest(project, v.branch, v.rows, v.draft),
    onSuccess: () => {
      setSelected(new Set());
      setDraft(EMPTY_DRAFT);
      void qc.invalidateQueries({ queryKey: ["comparison", project, regression] });
    },
  });
  const busy = bulk.isPending;
  const setBaseline = (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const next = new URLSearchParams(params);
    if (baselineInput.trim()) next.set("baseline", baselineInput.trim());
    else next.delete("baseline");
    setParams(next);
  };
  if (read.isPending) return <Loading what="regression" />;
  if (read.error) return <ErrorBox error={read.error} />;
  const r = read.data;
  const branch = `${r.regression.branch.repository}/${r.regression.branch.name}`;
  const page = `/p/${enc(project)}/r/${enc(regression)}`;
  const q = producer ? `?producer=${enc(producer)}` : "";
  const selectable = (cmp.data?.comparison.rows ?? []).filter(
    (row): row is ComparisonRow & { number: number } => !row.group && row.number !== null,
  );
  const chosen = selectable.filter((row) => selected.has(row.number));
  const toggle = (numbers: number[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      for (const n of numbers) {
        if (on) next.add(n);
        else next.delete(n);
      }
      return next;
    });
  const allChosen = selectable.length > 0 && chosen.length === selectable.length;
  const sigLink = (n: number) =>
    `/p/${enc(project)}/signatures/${n}?branch=${enc(branch)}&suite=${enc(r.regression.suite)}` +
    `&regression=${enc(regression)}${producer ? `&producer=${enc(producer)}` : ""}`;
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /{" "}
        {regression}
      </p>
      <h1>
        {regression} <StateBadge state={r.regression.state} />
      </h1>
      <p className="muted">
        {r.regression.suite} on {branch}, producer {r.regression.producer}, started{" "}
        {r.regression.started_at}
      </p>
      <ChangeStrip project={project} />
      <HeaderCounts h={r.header} />
      {claimStale && (
        <p className="warning" role="alert" data-testid="exception-expired">
          An exception covering a failure here has expired: the comparison is being read
          again, and coverage and blockers below are out of date until it is.
        </p>
      )}
      {cmp.data && (
        <FinishCardView
          f={cmp.data.finish}
          missing={r.header.missing + r.header.running}
          stale={claimStale}
        />
      )}
      <p>
        <Link to={`${page}/readiness${q}`}>Readiness verdict →</Link>
      </p>

      <Section title="Signatures">
        <form className="inline" onSubmit={setBaseline}>
          <label>
            Compare with baseline regression{" "}
            <input
              value={baselineInput}
              disabled={busy}
              onChange={(e) => setBaselineInput(e.target.value)}
              placeholder="regression reference"
            />
          </label>
          <button type="submit" disabled={busy}>
            Compare
          </button>
        </form>
        {cmp.data?.baseline && (
          <p className="muted" data-testid="baseline">
            Baseline: {cmp.data.baseline.ref ?? "none"} ({cmp.data.baseline.reason})
          </p>
        )}
        {cmp.data?.baseline?.simulators_differ && cmp.data.baseline.simulators && (
          <p className="warning" data-testid="baseline-simulators">
            The baseline is on {(cmp.data.baseline.simulators.baseline ?? []).join(", ")}, this
            regression on {cmp.data.baseline.simulators.current.join(", ")}: &ldquo;new&rdquo; and
            &ldquo;also in baseline&rdquo; compare different simulators. Run each simulator in its
            own suite, or compare with another baseline above.
          </p>
        )}
        {cmp.isPending ? (
          <Loading what="comparison" />
        ) : cmp.error ? (
          <ErrorBox error={cmp.error} />
        ) : cmp.data.comparison.rows.length === 0 ? (
          <Empty>No failure signatures.</Empty>
        ) : (
          <>
          <p className="inline">
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                toggle(
                  selectable.filter((row) => row.disposition === "needs_decision").map((row) => row.number),
                  true,
                )
              }
            >
              Select all needing decision
            </button>{" "}
            {chosen.length > 0 && (
              <button type="button" disabled={busy} onClick={() => setSelected(new Set())}>
                Clear selection ({chosen.length})
              </button>
            )}
          </p>
          <table>
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    aria-label="Select all signatures"
                    checked={allChosen}
                    disabled={busy || selectable.length === 0}
                    onChange={(e) => toggle(selectable.map((row) => row.number), e.target.checked)}
                  />
                </th>
                <th>Signature</th>
                <th>Diagnostic</th>
                <th>Failed slots</th>
                <th>Failing attempts</th>
                <th>Diagnostics</th>
                <th>Baseline</th>
                <th>Simulators</th>
                <th>Affected slots</th>
                <th>Decision</th>
                <th>Owner</th>
                <th>Latest note</th>
                <th>Next action</th>
              </tr>
            </thead>
            <tbody>
              {cmp.data.comparison.rows.map((row) => (
                <tr key={row.signature}>
                  <td>
                    {!row.group && row.number !== null && (
                      <input
                        type="checkbox"
                        aria-label={`Select #${row.number}`}
                        checked={selected.has(row.number)}
                        disabled={busy}
                        onChange={(e) => toggle([row.number as number], e.target.checked)}
                      />
                    )}
                  </td>
                  <td>
                    {row.group ? (
                      <span className="group">blocked: {row.group} (no diagnostic)</span>
                    ) : row.number !== null ? (
                      <Link to={sigLink(row.number)}>#{row.number}</Link>
                    ) : (
                      <code>{row.signature.slice(0, 19)}</code>
                    )}
                  </td>
                  <td className="diag">
                    {row.diag_id && (
                      <>
                        <code>{row.diag_id}</code>{" "}
                        <button
                          type="button"
                          className="link"
                          disabled={busy}
                          title={`Select every row with ${row.diag_id}`}
                          onClick={() =>
                            toggle(
                              selectable.filter((x) => x.diag_id === row.diag_id).map((x) => x.number),
                              true,
                            )
                          }
                        >
                          select all {row.diag_id}
                        </button>
                        <br />
                        <span className="template">{row.identity_template ?? ""}</span>
                      </>
                    )}
                  </td>
                  <td className="num">{row.failed_slots}</td>
                  <td className="num">{row.failing_attempts}</td>
                  <td className="num">{row.diagnostics}</td>
                  <td>
                    <span className={`baseline baseline-${row.baseline}`}>
                      {BASELINE_LABEL[row.baseline] ?? row.baseline}
                    </span>
                  </td>
                  <td>{row.simulators.join(", ")}</td>
                  <td>{row.preview.join(", ")}</td>
                  <td>
                    <span className={`disposition disposition-${row.disposition ?? "none"}`}>
                      {DISPOSITION_LABEL[row.disposition ?? ""] ?? "—"}
                    </span>
                    {row.triage_state === "closed" && " (closed)"}
                    {row.exception && ` until ${row.exception.expires_at}`}
                  </td>
                  <td>{row.owner ?? "Unassigned"}</td>
                  <td className="notes">{row.latest_note ?? ""}</td>
                  <td>{row.next_action ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {chosen.length > 0 && (
            <BulkTriage
              branch={branch}
              rows={chosen}
              draft={draft}
              setDraft={setDraft}
              save={{
                isPending: bulk.isPending,
                error: bulk.error,
                mutate: () => bulk.mutate({ branch, rows: chosen, draft }),
              }}
            />
          )}
          </>
        )}
      </Section>

      <Section title="Collection repair list">
        {repair.isPending ? (
          <Loading what="repair list" />
        ) : repair.error ? (
          <ErrorBox error={repair.error} />
        ) : repair.data.groups.every((g) => g.slots.length === 0) ? (
          <Empty>Every slot has an eligible result or a mark.</Empty>
        ) : (
          <>
            <CopyButton text={repair.data.text} label="Copy collection repair list" />
            <table>
              <thead>
                <tr>
                  <th>Producer</th>
                  <th>Slot</th>
                  <th>Reason</th>
                  <th>Recovery</th>
                </tr>
              </thead>
              <tbody>
                {repair.data.groups.flatMap((g) =>
                  g.slots.map((x) => (
                    <tr key={`${g.producer}/${x.slot}`}>
                      <td>{g.producer}</td>
                      <td>
                        {x.slot}
                        {x.required && " (required)"}
                      </td>
                      <td>{x.reason}</td>
                      <td>{x.action}</td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </>
        )}
      </Section>

      <Section title="Slots">
        <table>
          <thead>
            <tr>
              <th>Slot</th>
              <th>Test</th>
              <th>Required</th>
              <th>State</th>
              <th>Attempts</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {r.slots.map((s) => (
              <tr key={s.slot_ref}>
                <td>
                  {s.deciding !== null ? (
                    <Link to={`${page}/s/${enc(s.slot_ref)}/a/${s.deciding}${q}`}>{s.slot_ref}</Link>
                  ) : (
                    s.slot_ref
                  )}
                </td>
                <td>{s.test}</td>
                <td>{s.required ? "yes" : "no"}</td>
                <td>
                  <StateBadge state={s.state} detail={s.detail} />
                </td>
                <td className="num">{s.attempts}</td>
                <td>{s.note ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </>
  );
}
