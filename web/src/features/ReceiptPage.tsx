import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, enc } from "../api/client";
import { ErrorBox, Loading, Section, VerdictBadge } from "../components/ui";

interface Summary {
  verdict: string;
  evaluated_at: string;
  valid_until: string | null;
  digest: string;
  regression: string;
  suite: string;
  counts: Record<string, number>;
  blockers: { kind: { kind: string; reason?: string }; slots: number; signatures: number[] }[];
  exceptions_used: { signature: number | null; expires_at: string }[];
}

export interface ReceiptRead {
  receipt: {
    digest: string;
    summary: Summary;
    regression: string | null;
    target: { repository: string | null; commit: string | null; context: string | null };
    status: { state: string | null; description: string };
    published_at: string;
    valid_until: string | null;
    monitor_until: string | null;
    posted_at: string | null;
    last_refresh_at: string | null;
    retired_at: string | null;
    retired_reason: string | null;
  };
  current: { summary: Summary; digest: string } | { error: { code: string; message: string } } | null;
}

/** The page a commit status links to: what was published, next to what holds now. */
export function ReceiptPage() {
  const { project = "", digest = "" } = useParams();
  const q = useQuery({
    queryKey: ["receipt", project, digest],
    queryFn: () =>
      api<ReceiptRead>(`/api/v1/projects/${enc(project)}/readiness/receipts/${enc(digest)}`),
  });
  if (q.isPending) return <Loading what="receipt" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const { receipt: r, current } = q.data;
  const s = r.summary;
  const changed = current && "summary" in current && current.digest !== r.digest;
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> / receipt
      </p>
      <h1>Published readiness</h1>
      <p data-testid="published">
        Published at {r.published_at} (digest <code>{r.digest}</code>):{" "}
        <VerdictBadge verdict={s.verdict} />
      </p>
      {current && "summary" in current && (
        <p data-testid="current" className={changed ? "warning" : undefined}>
          Current evaluation at {current.summary.evaluated_at} (digest{" "}
          <code>{current.digest}</code>): <VerdictBadge verdict={current.summary.verdict} />
        </p>
      )}
      {current && "error" in current && (
        <p className="warning">
          No current evaluation: {current.error.code}: {current.error.message}
        </p>
      )}
      <p className="muted">
        A status is an advisory snapshot; the merge gate is a live <code>dviscope verdict</code>{" "}
        run.
      </p>
      <Section title="Status">
        <table>
          <tbody>
            <tr>
              <th>Target</th>
              <td>
                {r.target.repository}@{r.target.commit?.slice(0, 12)} ({r.target.context})
              </td>
            </tr>
            <tr>
              <th>Status</th>
              <td>
                {r.status.state}: {r.status.description}
              </td>
            </tr>
            <tr>
              <th>Valid until</th>
              <td>{r.valid_until ?? "—"}</td>
            </tr>
            <tr>
              <th>Monitored until</th>
              <td>{r.monitor_until ?? "—"}</td>
            </tr>
            <tr>
              <th>Accepted by the code host</th>
              <td>{r.posted_at ?? "not yet"}</td>
            </tr>
            <tr>
              <th>Last successful refresh</th>
              <td>{r.last_refresh_at ?? "—"}</td>
            </tr>
            <tr>
              <th>Retired</th>
              <td>{r.retired_at ? `${r.retired_at} (${r.retired_reason ?? ""})` : "—"}</td>
            </tr>
          </tbody>
        </table>
      </Section>
      <Section title="Published summary">
        <p>
          Regression {s.regression}, suite {s.suite}, evaluated {s.evaluated_at}
          {s.valid_until && `, valid until ${s.valid_until}`}.
        </p>
        <p className="counts">
          {Object.entries(s.counts)
            .map(([k, n]) => `${n} ${k}`)
            .join(" · ")}
        </p>
        <ul>
          {s.blockers.map((b, i) => (
            <li key={i}>
              {b.kind.kind.replace(/_/g, " ")}
              {b.kind.reason && ` (${b.kind.reason})`}: {b.slots} slot{b.slots === 1 ? "" : "s"}
              {b.signatures.length > 0 && `, signatures ${b.signatures.map((n) => `#${n}`).join(", ")}`}
            </li>
          ))}
          {s.exceptions_used.map((e, i) => (
            <li key={`e${i}`}>
              exception for #{e.signature ?? "?"} until {e.expires_at}
            </li>
          ))}
        </ul>
      </Section>
    </>
  );
}
