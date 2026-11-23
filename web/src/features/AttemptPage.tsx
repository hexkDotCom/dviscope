import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, enc, type AttemptDetail } from "../api/client";
import { Empty, ErrorBox, Loading, Section } from "../components/ui";

export function AttemptPage() {
  const { project = "", regression = "", slot = "", seq = "" } = useParams();
  const producer = useSearchParams()[0].get("producer");
  const q = useQuery({
    queryKey: ["attempt", project, regression, slot, seq, producer],
    queryFn: () =>
      api<AttemptDetail>(
        `/api/v1/projects/${enc(project)}/regressions/${enc(regression)}/slots/${enc(slot)}/attempts/${enc(seq)}` +
          (producer ? `?producer=${enc(producer)}` : ""),
      ),
  });
  if (q.isPending) return <Loading what="attempt" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const a = q.data;
  const ev = a.evidence;
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /{" "}
        <Link
          to={`/p/${enc(project)}/r/${enc(regression)}${producer ? `?producer=${enc(producer)}` : ""}`}
        >
          {regression}
        </Link>{" "}
        / {slot} / attempt{" "}
        {a.attempt_seq}
      </p>
      <h1>
        {slot}, attempt {a.attempt_seq}
      </h1>
      <p className="muted">
        Attempt <code>{a.attempt_ref}</code>, head revision {a.head_revision ?? "—"}
      </p>

      <Section title="Report revisions">
        <table>
          <thead>
            <tr>
              <th>Revision</th>
              <th>Outcome</th>
              <th>Result</th>
              <th>Assessment</th>
              <th>Completion</th>
              <th>Termination</th>
              <th>Pipeline</th>
              <th>Simulator</th>
              <th>Received</th>
            </tr>
          </thead>
          <tbody>
            {a.revisions.map((r) => (
              <tr key={r.report_revision}>
                <td className="num">{r.report_revision}</td>
                <td>{r.outcome}</td>
                <td>
                  {r.effective}
                  {r.contradiction && <span className="warning"> contradiction</span>}
                </td>
                <td>{r.assessment}</td>
                <td>{r.completion}</td>
                <td>{r.termination}</td>
                <td>{r.pipeline_status}</td>
                <td>{r.simulator}</td>
                <td>{r.received_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Diagnostics">
        {a.buckets.length === 0 ? (
          <Empty>No diagnostics in the head revision.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Diagnostic</th>
                <th>Count</th>
                <th>Observed</th>
                <th>Effective</th>
                <th>Fails run</th>
                <th>Provenance</th>
                <th>Signature</th>
              </tr>
            </thead>
            <tbody>
              {a.buckets.map((b) => (
                <tr key={b.idx}>
                  <td>
                    <code>{b.diag_id}</code>
                  </td>
                  <td className="num">{b.count}</td>
                  <td>{b.observed_severity}</td>
                  <td>{b.effective_severity}</td>
                  <td>{b.fails_run ? "yes" : "no"}</td>
                  <td>{b.provenance}</td>
                  <td>
                    <Link to={`/p/${enc(project)}/signatures/${b.signature}`}>#{b.signature}</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Evidence">
        {a.evidence_note && <p className="muted">{a.evidence_note}</p>}
        {ev && (
          <>
            <p>
              Completion profile <code>{ev.completion.profile}</code>: {ev.completion.state}
              {ev.completion.reasons.length > 0 && ` (${ev.completion.reasons.join("; ")})`}
            </p>
            {ev.verdict_sources.length > 0 && (
              <ul>
                {ev.verdict_sources.map((v, i) => (
                  <li key={i}>
                    {v.source}: {v.value}
                  </li>
                ))}
              </ul>
            )}
            {ev.counters.length > 0 && (
              <table>
                <thead>
                  <tr>
                    <th>Counter</th>
                    <th>Value</th>
                    <th>Role</th>
                  </tr>
                </thead>
                <tbody>
                  {ev.counters.map((c, i) => (
                    <tr key={i}>
                      <td>
                        {c.domain}.{c.key}
                      </td>
                      <td className="num">{c.value}</td>
                      <td>{c.role}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <h3>Excerpt</h3>
            {ev.excerpt.segments.length === 0 ? (
              <Empty>No excerpt.</Empty>
            ) : (
              ev.excerpt.segments.map((seg, i) => (
                <pre key={i} className="excerpt" data-kind={seg.kind}>
                  {seg.lines.map((l, j) => `${String(seg.first_line + j).padStart(6)}  ${l}`).join("\n")}
                </pre>
              ))
            )}
            {ev.excerpt.truncated && <p className="muted">Excerpt truncated.</p>}
          </>
        )}
      </Section>
    </>
  );
}
