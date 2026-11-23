import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, enc, type BlockerKind, type ProofRow, type Readiness } from "../api/client";
import { Empty, ErrorBox, Loading, Section, VerdictBadge } from "../components/ui";
import { StaleBanner, useStale } from "../components/stale";

export function kindLabel(k: BlockerKind): string {
  const base = k.kind.replace(/_/g, " ");
  if (k.reason) return `${base} (${k.reason.replace(/_/g, " ")})`;
  if (k.by) return `${base} by ${k.by}`;
  return base;
}

function stateOf(p: ProofRow): string {
  return typeof p.state === "string" ? p.state : p.state.state;
}

/** For every accepted required slot: its accepting attempt, builds, and what contributed. */
export function ProofCard({
  proof,
  sigLink,
}: {
  proof: ProofRow[];
  sigLink: (n: number) => string;
}) {
  if (proof.length === 0) return <Empty>No required slot is accepted yet.</Empty>;
  return (
    <table className="proof">
      <thead>
        <tr>
          <th>Slot</th>
          <th>State</th>
          <th>Accepting attempt</th>
          <th>Builds</th>
          <th>Contributed</th>
        </tr>
      </thead>
      <tbody>
        {proof.map((p) => {
          const why = [
            p.expectation_met && "expected failure met",
            p.retry && "accepted retry",
          ].filter(Boolean);
          return (
            <tr key={p.slot}>
              <td>{p.slot}</td>
              <td>{stateOf(p)}</td>
              <td>{p.attempt_seq !== null ? `#${p.attempt_seq}` : "—"}</td>
              <td>{p.builds.length > 0 ? p.builds.join(", ") : "—"}</td>
              <td>
                {why.join(", ")}
                {p.exceptions.map((n) => (
                  <Link key={n} to={sigLink(n)} className="sig">
                    exception for #{n}
                  </Link>
                ))}
                {why.length === 0 && p.exceptions.length === 0 && "—"}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export function ReadinessPage() {
  const { project = "", regression = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const producer = params.get("producer");
  const expect = params.get("expect_source");
  const [expectInput, setExpectInput] = useState(expect ?? "");
  const query = [
    producer ? `producer=${enc(producer)}` : "",
    expect ? `expect_source=${enc(expect)}` : "",
  ]
    .filter(Boolean)
    .join("&");
  const q = useQuery({
    queryKey: ["readiness", project, regression, producer, expect],
    queryFn: () =>
      api<Readiness>(
        `/api/v1/projects/${enc(project)}/regressions/${enc(regression)}/readiness?${query}`,
      ),
  });
  const stale = useStale(project, q.data?.change_seq, q.data?.valid_until);
  const bind = (e: FormEvent) => {
    e.preventDefault();
    const next = new URLSearchParams(params);
    if (expectInput.trim()) next.set("expect_source", expectInput.trim());
    else next.delete("expect_source");
    setParams(next);
  };
  const regPage = `/p/${enc(project)}/r/${enc(regression)}${producer ? `?producer=${enc(producer)}` : ""}`;
  if (q.isPending) return <Loading what="readiness" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const r = q.data;
  const branch = `${r.regression.branch.repository}/${r.regression.branch.name}`;
  const sigLink = (n: number) =>
    `/p/${enc(project)}/signatures/${n}?branch=${enc(branch)}&suite=${enc(r.summary.suite)}` +
    `&regression=${enc(regression)}${producer ? `&producer=${enc(producer)}` : ""}`;
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /{" "}
        <Link to={regPage}>{regression}</Link> / readiness
      </p>
      <h1 className={stale ? "is-stale" : undefined}>
        Readiness: <VerdictBadge verdict={r.verdict} />
        {stale && " (stale)"}
      </h1>
      <StaleBanner reason={stale} onRefresh={() => void q.refetch()} />
      <p className="muted">
        Policy {r.summary.policy}, suite {r.summary.suite}, evaluated {r.evaluated_at}
        {r.valid_until && `, valid until ${r.valid_until}`}. Digest <code>{r.digest}</code>
      </p>
      {r.warnings.map((w) => (
        <p key={w} className="warning">
          {w}
        </p>
      ))}
      <form className="inline" onSubmit={bind}>
        <label>
          Expected source digest{" "}
          <input
            value={expectInput}
            onChange={(e) => setExpectInput(e.target.value)}
            placeholder="sha256:…"
          />
        </label>
        <button type="submit">Bind candidate</button>
      </form>

      <Section title="Proof">
        <ProofCard proof={r.proof} sigLink={sigLink} />
      </Section>

      <Section title="Blockers">
        {r.summary.blockers.length === 0 ? (
          <Empty>No blockers.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Blocker</th>
                <th>Slots</th>
                <th>Signatures</th>
                <th>Owner</th>
                <th>To clear</th>
              </tr>
            </thead>
            <tbody>
              {r.summary.blockers.map((b, i) => (
                <tr key={i}>
                  <td>{kindLabel(b.kind)}</td>
                  <td className="num">{b.slots}</td>
                  <td>
                    {b.signatures.map((n) => (
                      <Link key={n} to={sigLink(n)} className="sig">
                        #{n}
                      </Link>
                    ))}
                  </td>
                  <td>{b.owner}</td>
                  <td>
                    {b.clearing_action}
                    {b.exceptable && " (an exception can cover this)"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {r.blockers.length > 0 && (
        <Section title="Blocked slots">
          <table>
            <thead>
              <tr>
                <th>Slot</th>
                <th>Blocker</th>
                <th>Signatures</th>
              </tr>
            </thead>
            <tbody>
              {r.blockers.map((b, i) => (
                <tr key={i}>
                  <td>{b.slot ?? "(regression)"}</td>
                  <td>{kindLabel(b.kind)}</td>
                  <td>
                    {b.signatures.map((n) => (
                      <Link key={n} to={sigLink(n)} className="sig">
                        #{n}
                      </Link>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      <Section title="Exceptions used">
        {r.summary.exceptions_used.length === 0 ? (
          <Empty>None.</Empty>
        ) : (
          <ul>
            {r.summary.exceptions_used.map((e, i) => (
              <li key={i}>
                {e.signature !== null ? (
                  <Link to={sigLink(e.signature)}>#{e.signature}</Link>
                ) : (
                  "signature"
                )}{" "}
                until {e.expires_at}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Counts">
        <p className="counts">
          {Object.entries(r.summary.counts)
            .map(([k, n]) => `${n} ${k}`)
            .join(" · ")}
        </p>
      </Section>
    </>
  );
}
