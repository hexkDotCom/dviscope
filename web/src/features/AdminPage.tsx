import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, enc } from "../api/client";
import { Empty, ErrorBox, Loading, Section } from "../components/ui";

export interface AdminOverview {
  project: string;
  policy: string;
  members: { username: string; role: string; disabled: boolean }[];
  tokens: {
    id: number;
    producer: string;
    label: string;
    scopes: string[];
    created_at: string;
    expires_at: string;
    revoked_at: string | null;
    quarantined_since: string | null;
    state: string;
  }[];
  producers: {
    name: string;
    retired_at: string | null;
    retired_reason: string | null;
    assurance: string[];
  }[];
  pipelines: { digest: string; state: string; changed_at: string }[];
}

/** The project's rules status (`GET .../rules`). */
export interface RulesStatus {
  active_pipeline: string;
  default_packs: boolean;
  packs: string[];
  sample: { digest: string; cases: number; bytes: number } | null;
  activations: {
    id: string;
    old_pipeline: string;
    new_pipeline: string;
    sample: string;
    actor: string;
    activated_at: string;
    cases: number | null;
  }[];
}

/** Active pipeline, activation sample and recent activations (read-only; activate with
 * `dviscope rules import`). */
function RulesSection({ project }: { project: string }) {
  const q = useQuery({
    queryKey: ["rules", project],
    queryFn: () => api<RulesStatus>(`/api/v1/projects/${enc(project)}/rules`),
  });
  if (q.isPending) return <Loading what="rules" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const r = q.data;
  const packs = [r.default_packs ? "shipped packs" : null, ...r.packs].filter(
    Boolean,
  );
  return (
    <Section title="Rules activation">
      <p>
        Active pipeline <code>{r.active_pipeline}</code> (
        {packs.join(", ") || "no packs"}).
      </p>
      <p>
        {r.sample
          ? `Activation sample: ${r.sample.cases} cases, ${r.sample.bytes} bytes (${r.sample.digest}).`
          : "No activation sample: activation is blocked until one is uploaded (dviscope sample upload)."}
      </p>
      {r.activations.length === 0 ? (
        <Empty>No activation yet.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Activated</th>
              <th>New pipeline</th>
              <th>Replaced</th>
              <th>Cases checked</th>
            </tr>
          </thead>
          <tbody>
            {r.activations.map((x) => (
              <tr key={x.id}>
                <td>{x.activated_at}</td>
                <td>
                  <code>{x.new_pipeline}</code>
                </td>
                <td>
                  <code>{x.old_pipeline}</code>
                </td>
                <td>{x.cases ?? "?"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Section>
  );
}

/** The project's retention preview (`GET .../admin/retention`). */
export interface RetentionPreview {
  project: string;
  as_of: string;
  policy_days: {
    pass_payload: number;
    pass_facts: number;
    fail_payload: number;
    fail_facts: number;
    receipts: number;
  };
  report: {
    payloads: number;
    regressions: number;
    builds: number;
    receipts: number;
    items: {
      project: string;
      regression: string;
      cohort: string;
      ended_at: string;
      action: string;
      payloads: number;
    }[];
    items_truncated: boolean;
    candidates: {
      project: string;
      branch: string;
      test: string;
      regression: string;
    }[];
    publications: {
      project: string;
      digest: string;
      regression: string;
      target: string | null;
    }[];
    impact_truncated: boolean;
  };
}

/** What the next retention run would expire in this project (read-only). */
function RetentionSection({ project }: { project: string }) {
  const q = useQuery({
    queryKey: ["retention", project],
    queryFn: () =>
      api<RetentionPreview>(`/api/v1/projects/${enc(project)}/admin/retention`),
  });
  if (q.isPending) return <Loading what="retention preview" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const r = q.data;
  const d = r.policy_days;
  return (
    <Section title="Retention preview">
      <p className="muted">
        As of {r.as_of}. Payloads expire after {d.pass_payload} days (all-pass)
        or {d.fail_payload} (with failures); regressions after {d.pass_facts} or{" "}
        {d.fail_facts} days; receipts after {d.receipts}.
      </p>
      <p>
        Next run: {r.report.regressions} regression(s) removed,{" "}
        {r.report.payloads} payload(s) expired, {r.report.builds} build(s) and{" "}
        {r.report.receipts} receipt(s) removed.
      </p>
      {r.report.items.length === 0 ? (
        <Empty>Nothing expires in this project.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Regression</th>
              <th>Ended</th>
              <th>Cohort</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {r.report.items.map((x) => (
              <tr key={x.regression}>
                <td>{x.regression}</td>
                <td>{x.ended_at}</td>
                <td>
                  {x.cohort === "all_pass" ? "all pass" : "with failures"}
                </td>
                <td>
                  {x.action === "remove"
                    ? "removed"
                    : `${x.payloads} payload(s) expired`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {r.report.items_truncated && (
        <p className="muted">More regressions than shown.</p>
      )}
      {r.report.candidates.length > 0 && (
        <>
          <h3>Feature readiness affected</h3>
          <ul>
            {r.report.candidates.map((c) => (
              <li key={`${c.branch}|${c.test}|${c.regression}`}>
                {c.branch} / {c.test}: newest evidence {c.regression} expires
              </li>
            ))}
          </ul>
        </>
      )}
      {r.report.publications.length > 0 && (
        <>
          <h3>Monitored publications affected</h3>
          <ul>
            {r.report.publications.map((x) => (
              <li key={x.digest}>
                {x.regression}
                {x.target ? ` (${x.target})` : ""}: <code>{x.digest}</code>
              </li>
            ))}
          </ul>
        </>
      )}
      {r.report.impact_truncated && (
        <p className="muted">More affected items than shown.</p>
      )}
    </Section>
  );
}

/** Read-only administration overview; changes are made with `dviscope-server admin`. */
export function AdminPage() {
  const project = useParams().project ?? "";
  const q = useQuery({
    queryKey: ["admin", project],
    queryFn: () => api<AdminOverview>(`/api/v1/projects/${enc(project)}/admin`),
  });
  if (q.isPending) return <Loading what="administration" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const a = q.data;
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> /{" "}
        <Link to={`/p/${enc(project)}`}>{project}</Link> / admin
      </p>
      <h1>Administration</h1>
      <p className="muted">
        Policy {a.policy}. Read-only: change members, tokens, quarantines and
        pipelines with <code>dviscope-server admin</code>.
      </p>

      <Section title="Producers">
        {a.producers.length === 0 ? (
          <Empty>No producers.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Producer</th>
                <th>Integration assurance</th>
                <th>Retired</th>
              </tr>
            </thead>
            <tbody>
              {a.producers.map((p) => (
                <tr key={p.name}>
                  <td>{p.name}</td>
                  <td>{p.assurance.join("; ")}</td>
                  <td>
                    {p.retired_at
                      ? `${p.retired_at} (${p.retired_reason ?? ""})`
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Collector tokens">
        {a.tokens.length === 0 ? (
          <Empty>No collector tokens.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Producer</th>
                <th>Label</th>
                <th>Scopes</th>
                <th>State</th>
                <th>Expires</th>
              </tr>
            </thead>
            <tbody>
              {a.tokens.map((t) => (
                <tr key={t.id}>
                  <td className="num">{t.id}</td>
                  <td>{t.producer}</td>
                  <td>{t.label}</td>
                  <td>{t.scopes.join(", ")}</td>
                  <td>
                    {t.state}
                    {t.quarantined_since && ` since ${t.quarantined_since}`}
                  </td>
                  <td>{t.expires_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Members">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            {a.members.map((m) => (
              <tr key={m.username}>
                <td>
                  {m.username}
                  {m.disabled && " (disabled)"}
                </td>
                <td>{m.role}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Rules pipelines">
        {a.pipelines.length === 0 ? (
          <Empty>No pipeline accepted: no result is eligible yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Digest</th>
                <th>State</th>
                <th>Changed</th>
              </tr>
            </thead>
            <tbody>
              {a.pipelines.map((p) => (
                <tr key={p.digest}>
                  <td>
                    <code>{p.digest}</code>
                  </td>
                  <td>{p.state}</td>
                  <td>{p.changed_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
      <RulesSection project={project} />
      <RetentionSection project={project} />
    </>
  );
}
