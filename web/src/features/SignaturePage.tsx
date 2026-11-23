import { useEffect, useState, type FormEvent, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  ApiError,
  api,
  enc,
  type ExceptionImpact,
  type ExceptionRow,
  type Head,
  type SignatureDetail,
  type TriageCase,
} from "../api/client";
import { CopyButton, oneLine } from "../components/CopyButton";
import { Empty, ErrorBox, Loading, Section } from "../components/ui";

/** Bug links are shown only for http(s) URLs and are never fetched by DVIScope. */
export function safeUrl(u: string): string | null {
  try {
    const url = new URL(u);
    return url.protocol === "http:" || url.protocol === "https:"
      ? url.href
      : null;
  } catch {
    return null;
  }
}

function TriageEditor({
  project,
  number,
  branch,
  current,
  onSaved,
}: {
  project: string;
  number: number;
  branch: string;
  current: TriageCase | undefined;
  onSaved: () => Promise<unknown> | void;
}) {
  const [state, setState] = useState(current?.state ?? "open");
  const [owner, setOwner] = useState(current?.owner ?? "");
  const [notes, setNotes] = useState(current?.notes ?? "");
  const [bugs, setBugs] = useState((current?.bug_urls ?? []).join("\n"));
  // After a conflict the latest revision is read again, and the user's edits are kept
  // (never replaced by it silently) until they save again or load the other version.
  const [keepDraft, setKeepDraft] = useState(false);
  const keep = useRef(false);
  keep.current = keepDraft;
  // After a save the draft is kept too, and replaced by what is read only while it is still
  // exactly what was saved: edits typed after a failed re-read survive every later read.
  const draft = useRef<Draft>({ state, owner, notes, bugs });
  draft.current = { state, owner, notes, bugs };
  const saved = useRef<Draft | null>(null);
  const load = (c: TriageCase | undefined) => {
    setState(c?.state ?? "open");
    setOwner(c?.owner ?? "");
    setNotes(c?.notes ?? "");
    setBugs((c?.bug_urls ?? []).join("\n"));
  };
  useEffect(() => {
    if (!keep.current) {
      load(current);
      return;
    }
    const s = saved.current;
    if (s && sameDraft(s, draft.current)) {
      saved.current = null;
      setKeepDraft(false);
      load(current);
    }
  }, [current]);
  const save = useMutation({
    mutationFn: (_sent: Draft) =>
      api<Head>(
        `/api/v1/projects/${enc(project)}/triage/${number}?branch=${enc(branch)}`,
        {
          method: "PUT",
          ifMatch: current?.revision,
          body: {
            state,
            owner: owner.trim() ? owner.trim() : null,
            notes,
            bug_urls: bugs
              .split("\n")
              .map((s) => s.trim())
              .filter(Boolean),
          },
        },
      ),
    // The save stays pending (fields frozen) until the saved revision is read back: nothing
    // typed meanwhile can be replaced by it.
    onSuccess: (_head, sent) => {
      saved.current = sent;
      setKeepDraft(true);
      return onSaved();
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 412) {
        saved.current = null;
        setKeepDraft(true);
        onSaved();
      }
    },
  });
  const conflict = save.error instanceof ApiError && save.error.status === 412;
  // Fields are frozen while saving: nothing typed meanwhile can be lost when the saved
  // revision is read back.
  const busy = save.isPending;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate({ ...draft.current });
  };
  return (
    <form className="editor" onSubmit={submit}>
      <h3>Triage on {branch}</h3>
      {current && (
        <p className="muted">
          Revision {current.revision} by {current.by} at {current.at}
        </p>
      )}
      <label>
        State
        <select value={state} disabled={busy} onChange={(e) => setState(e.target.value)}>
          <option value="open">open</option>
          <option value="closed">closed</option>
        </select>
      </label>
      <label>
        Owner
        <input
          value={owner}
          maxLength={64}
          disabled={busy}
          onChange={(e) => setOwner(e.target.value)}
        />
      </label>
      <label>
        Notes
        <textarea
          rows={4}
          value={notes}
          disabled={busy}
          onChange={(e) => setNotes(e.target.value)}
        />
      </label>
      <label>
        Bug URLs (one per line)
        <textarea
          rows={2}
          value={bugs}
          disabled={busy}
          onChange={(e) => setBugs(e.target.value)}
        />
      </label>
      <p className="muted">
        Closing a case records a decision; it does not certify a fix.
      </p>
      <button type="submit" disabled={save.isPending}>
        Save triage
      </button>
      {conflict ? (
        <div className="error" role="alert" data-testid="triage-conflict">
          <p>
            Someone else changed this case
            {current
              ? ` (revision ${current.revision} by ${current.by}: ${current.state}, owner ${
                  current.owner ?? "none"
                })`
              : ""}
            . Your edits are kept: save again to replace that version, or load it instead.
          </p>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              saved.current = null;
              setKeepDraft(false);
              load(current);
              save.reset();
            }}
          >
            Load their version
          </button>
        </div>
      ) : (
        <ErrorBox error={save.error} />
      )}
    </form>
  );
}

type Draft = { state: string; owner: string; notes: string; bugs: string };

function sameDraft(a: Draft, b: Draft): boolean {
  return a.state === b.state && a.owner === b.owner && a.notes === b.notes && a.bugs === b.bugs;
}

/** Public-safe issue summary: version, codes, counts and IDs only (no log text, paths,
 * hosts or tokens; the identity template is log-derived and left out). */
export function publicSummary(
  s: SignatureDetail,
  project: string,
  branch: string | null,
): string {
  const regressions = new Set(s.occurrences.map((o) => o.regression));
  const slots = new Set(s.occurrences.map((o) => `${o.regression}/${o.slot}`));
  const sims = new Set(
    s.occurrences
      .map((o) => o.simulator)
      .filter(Boolean)
      .map(oneLine),
  );
  const triage = branch ? s.triage.find((t) => t.branch === branch) : undefined;
  // Each interpolated value is one line: the summary's lines are only its own.
  return [
    `DVIScope signature #${s.number} (project ${oneLine(project)})`,
    `Diagnostic: ${oneLine(s.diag_id)} (${oneLine(s.family_kind)})`,
    `Seen in ${slots.size} slot(s) across ${regressions.size} regression(s); simulators: ${[...sims].join(", ") || "unknown"}`,
    branch
      ? `Branch ${oneLine(branch)}: triage ${triage ? `${oneLine(triage.state)}, revision ${triage.revision}` : "none"}`
      : "",
    `Active exceptions: ${s.exceptions.filter((x) => !x.expired).length}`,
  ]
    .filter(Boolean)
    .join("\n");
}

function ImpactPreview({
  project,
  regression,
  producer,
  number,
  expiresAt,
}: {
  project: string;
  regression: string;
  producer: string | null;
  number: number;
  expiresAt: string;
}) {
  const q = useQuery({
    queryKey: ["preview", project, regression, producer, number, expiresAt],
    queryFn: () =>
      api<ExceptionImpact>(
        `/api/v1/projects/${enc(project)}/regressions/${enc(regression)}/readiness/preview` +
          `?signature=${number}&expires_at=${enc(expiresAt)}` +
          (producer ? `&producer=${enc(producer)}` : ""),
      ),
  });
  if (q.isPending) return <p className="muted">Computing impact…</p>;
  if (q.error) return <ErrorBox error={q.error} />;
  const i = q.data;
  const n = (k: number, what: string) => `${k} ${what}${k === 1 ? "" : "s"}`;
  return (
    <p className="impact" data-testid="impact">
      {i.not_exceptable &&
        "An exception cannot cover this signature's blockers here (not a functional failure). "}
      Would cover {n(i.covers_slots.length, "failing slot")};{" "}
      {n(i.stay_blocked_slots.length, "slot")} stay blocked by other groups;
      simulators: {i.simulators.join(", ") || "—"}; scope: branch{" "}
      {i.scope.branch} / suite {i.scope.suite}; expires {i.expires_at}. Verdict
      of {regression}: {i.verdict_before} → {i.verdict_after}.
    </p>
  );
}

function ExceptionEditor({
  project,
  number,
  branch,
  suite,
  regression,
  producer,
  current,
  onSaved,
}: {
  project: string;
  number: number;
  branch: string;
  suite: string;
  regression: string | null;
  producer: string | null;
  /** The live exception of this scope, if any (its revision is sent as If-Match). */
  current: ExceptionRow | undefined;
  onSaved: () => void;
}) {
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const create = useMutation({
    mutationFn: () =>
      api<Head>(`/api/v1/projects/${enc(project)}/exceptions`, {
        method: "POST",
        ifMatch: current?.revision,
        body: {
          signature: number,
          branch,
          suite,
          reason,
          expires_at: `${until}T23:59:59Z`,
        },
      }),
    onSuccess: () => {
      setReason("");
      onSaved();
    },
  });
  return (
    <form
      className="editor"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <h3>
        {current
          ? `Replace exception (revision ${current.revision})`
          : "New exception"}{" "}
        for {suite} on {branch}
      </h3>
      <p className="muted">
        An exception lets readiness accept this functional failure until it
        expires (at most 180 days). It replaces any active exception for the
        same scope.
      </p>
      <label>
        Reason
        <textarea
          rows={2}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
        />
      </label>
      <label>
        Expires (end of day, UTC)
        <input
          type="date"
          value={until}
          onChange={(e) => setUntil(e.target.value)}
          required
        />
      </label>
      {regression && until && (
        <ImpactPreview
          project={project}
          regression={regression}
          producer={producer}
          number={number}
          expiresAt={`${until}T23:59:59Z`}
        />
      )}
      <button type="submit" disabled={create.isPending}>
        Create exception
      </button>
      <ErrorBox error={create.error} />
    </form>
  );
}

export function SignaturePage() {
  const { project = "", number: numberParam = "" } = useParams();
  const number = Number(numberParam);
  const [params] = useSearchParams();
  const branch = params.get("branch");
  const suite = params.get("suite");
  const regression = params.get("regression");
  const producer = params.get("producer");
  const qc = useQueryClient();
  const key = ["signature", project, number];
  const q = useQuery({
    queryKey: key,
    queryFn: () =>
      api<SignatureDetail>(
        `/api/v1/projects/${enc(project)}/signatures/${number}`,
      ),
  });
  const refresh = () => qc.invalidateQueries({ queryKey: key });
  const revoke = useMutation({
    mutationFn: (id: number) =>
      api<void>(`/api/v1/projects/${enc(project)}/exceptions/${id}`, {
        method: "DELETE",
      }),
    onSuccess: refresh,
  });
  if (q.isPending) return <Loading what="signature" />;
  // A failed re-read keeps what is shown (and an editor's draft) and says it failed; only
  // a first read that fails replaces the page.
  if (q.error && !q.data) return <ErrorBox error={q.error} />;
  const s = q.data;
  const current = branch
    ? s.triage.find((t) => t.branch === branch)
    : undefined;
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> /{" "}
        <Link to={`/p/${enc(project)}`}>{project}</Link> / signature #{s.number}
      </p>
      {q.error && <ErrorBox error={q.error} />}
      <h1>
        Signature #{s.number} <code>{s.diag_id}</code>
      </h1>
      <p className="muted">
        {s.family_kind}: <code>{s.identity_template}</code>
      </p>
      <p className="note">{s.note}</p>
      <CopyButton
        text={publicSummary(s, project, branch)}
        label="Copy public-safe issue summary"
      />

      <Section title="Triage">
        {s.triage.length === 0 ? (
          <Empty>No triage yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Branch</th>
                <th>State</th>
                <th>Owner</th>
                <th>Notes</th>
                <th>Bugs</th>
                <th>Last change</th>
              </tr>
            </thead>
            <tbody>
              {s.triage.map((t) => (
                <tr key={t.id}>
                  <td>{t.branch}</td>
                  <td>{t.state}</td>
                  <td>{t.owner ?? "Unassigned"}</td>
                  <td className="notes">{t.notes}</td>
                  <td>
                    {t.bug_urls.map((u) => {
                      const href = safeUrl(u);
                      return href ? (
                        <a
                          key={u}
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {u}
                        </a>
                      ) : (
                        <span key={u}>{u}</span>
                      );
                    })}
                  </td>
                  <td>
                    r{t.revision} by {t.by} at {t.at}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {branch ? (
          <TriageEditor
            project={project}
            number={number}
            branch={branch}
            current={current}
            onSaved={refresh}
          />
        ) : (
          <p className="muted">
            Open this signature from a regression to edit its triage.
          </p>
        )}
      </Section>

      <Section title="Exceptions">
        {s.exceptions.length === 0 ? (
          <Empty>No exceptions.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Branch</th>
                <th>Suite</th>
                <th>Reason</th>
                <th>Expires</th>
                <th>By</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {s.exceptions.map((x) => (
                <tr key={x.id}>
                  <td>{x.branch}</td>
                  <td>{x.suite}</td>
                  <td className="notes">{x.reason}</td>
                  <td>
                    {x.expires_at}
                    {x.expired && <strong> (expired: covers nothing)</strong>}
                  </td>
                  <td>{x.by}</td>
                  <td>
                    <button
                      type="button"
                      onClick={() => revoke.mutate(x.id)}
                      disabled={revoke.isPending}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <ErrorBox error={revoke.error} />
        {branch && suite && (
          <ExceptionEditor
            project={project}
            number={number}
            branch={branch}
            suite={suite}
            regression={regression}
            producer={producer}
            current={s.exceptions.find(
              (x) => x.branch === branch && x.suite === suite,
            )}
            onSaved={refresh}
          />
        )}
      </Section>

      <Section title="Occurrences">
        <table>
          <thead>
            <tr>
              <th>Regression</th>
              <th>Slot</th>
              <th>Attempt</th>
              <th>Count</th>
              <th>Severity</th>
              <th>Simulator</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {s.occurrences.map((o, i) => (
              <tr key={i}>
                <td>
                  <Link
                    to={`/p/${enc(project)}/r/${enc(o.regression)}?producer=${enc(o.producer)}`}
                  >
                    {o.regression}
                  </Link>
                </td>
                <td>{o.slot}</td>
                <td>
                  <Link
                    to={`/p/${enc(project)}/r/${enc(o.regression)}/s/${enc(o.slot)}/a/${o.attempt_seq}?producer=${enc(o.producer)}`}
                  >
                    #{o.attempt_seq} r{o.report_revision}
                  </Link>
                </td>
                <td className="num">{o.count}</td>
                <td>{o.severity}</td>
                <td>{o.simulator}</td>
                <td>{o.effective}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </>
  );
}
