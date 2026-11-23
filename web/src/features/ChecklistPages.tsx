import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, enc } from "../api/client";
import { Empty, ErrorBox, Loading, Section } from "../components/ui";
import { StaleBanner, useStale } from "../components/stale";

export interface ChecklistList {
  checklists: {
    checklist_id: string;
    latest_version: string;
    title: string | null;
    feature: string | null;
    imported_at: string;
    versions: number;
  }[];
}

export interface PairView {
  test: string;
  simulator: string;
  regression: string;
  started_at: number;
  time_uncertain: boolean;
  passing_seeds: number;
  required_seeds: number;
  state: string;
  reasons: string[];
}

export interface ItemView {
  item_id: string;
  title: string;
  revision: number;
  owner: string;
  applicable: boolean;
  state: string;
  reasons?: string[];
  requires?: { tests: string[]; configs?: string[]; min_passing_seeds?: number };
  freshness_days?: number;
  pairs?: PairView[];
  seeds_by_simulator?: { simulator: string; achieved: number; required: number }[];
  evidence?: { name: string; digest: string; uri_hint?: string }[];
  evidence_digest?: string | null;
  attestation?: number | null;
  valid_until?: string | null;
  next_action?: string;
}

export interface FeatureEvaluation {
  checklist: { checklist_id: string; version: string; title: string; feature: string; owner: string };
  branch: string;
  evaluated_at: string;
  valid_until: string | null;
  change_seq: number;
  digest: string;
  ready: boolean;
  result: string;
  items: ItemView[];
}

const STATE_LABEL: Record<string, string> = {
  satisfied: "satisfied",
  failed: "failed",
  missing: "missing",
  insufficient: "insufficient",
  outdated: "outdated",
  unreviewed: "unreviewed",
  not_applicable: "not applicable",
};

export function ChecklistsPage() {
  const project = useParams().project ?? "";
  const q = useQuery({
    queryKey: ["checklists", project],
    queryFn: () => api<ChecklistList>(`/api/v1/projects/${enc(project)}/checklists`),
  });
  if (q.isPending) return <Loading what="checklists" />;
  if (q.error) return <ErrorBox error={q.error} />;
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /
        checklists
      </p>
      <h1>Feature checklists</h1>
      {q.data.checklists.length === 0 ? (
        <Empty>
          No checklists. Import one with <code>dviscope checklist import</code>.
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Checklist</th>
              <th>Feature</th>
              <th>Latest version</th>
              <th>Imported</th>
            </tr>
          </thead>
          <tbody>
            {q.data.checklists.map((c) => (
              <tr key={c.checklist_id}>
                <td>
                  <Link to={`/p/${enc(project)}/checklists/${enc(c.checklist_id)}`}>
                    {c.title ?? c.checklist_id}
                  </Link>
                </td>
                <td>{c.feature}</td>
                <td>
                  {c.latest_version} ({c.versions} version{c.versions === 1 ? "" : "s"})
                </td>
                <td>{c.imported_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** Shows exactly what is attested before confirming. */
function Attest({
  project,
  checklist,
  version,
  item,
  onDone,
}: {
  project: string;
  checklist: string;
  version: string;
  item: ItemView;
  onDone: () => void;
}) {
  const [open, setOpen] = useState(false);
  const m = useMutation({
    mutationFn: () =>
      api(`/api/v1/projects/${enc(project)}/checklists/${enc(checklist)}/attestations`, {
        method: "POST",
        body: {
          version,
          item_id: item.item_id,
          item_revision: item.revision,
          evidence_digest: item.evidence_digest,
        },
      }),
    onSuccess: () => {
      setOpen(false);
      onDone();
    },
  });
  if (!item.evidence_digest || item.attestation) return null;
  if (!open)
    return (
      <button type="button" onClick={() => setOpen(true)}>
        Review evidence…
      </button>
    );
  return (
    <div className="card" data-testid="attest">
      <p>
        Attest item <b>{item.item_id}</b> revision {item.revision} of version {version}, evidence
        digest <code>{item.evidence_digest}</code>:
      </p>
      <ul>
        {(item.evidence ?? []).map((e) => (
          <li key={e.name}>
            {e.name}: <code>{e.digest}</code>
            {e.uri_hint && ` (${e.uri_hint})`}
          </li>
        ))}
      </ul>
      <p className="muted">The digest is declared by the checklist, not verified by DVIScope.</p>
      <button type="button" onClick={() => m.mutate()} disabled={m.isPending}>
        Attest exactly this
      </button>{" "}
      <button type="button" onClick={() => setOpen(false)}>
        Cancel
      </button>
      <ErrorBox error={m.error} />
    </div>
  );
}

export function FeaturePage() {
  const { project = "", checklist = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const branch = params.get("branch");
  const version = params.get("version");
  const [branchInput, setBranchInput] = useState(branch ?? "");
  const qc = useQueryClient();
  const key = ["feature", project, checklist, branch, version];
  const q = useQuery({
    queryKey: key,
    enabled: !!branch,
    queryFn: () =>
      api<FeatureEvaluation>(
        `/api/v1/projects/${enc(project)}/checklists/${enc(checklist)}/evaluation?branch=${enc(branch ?? "")}` +
          (version ? `&version=${enc(version)}` : ""),
      ),
  });
  const stale = useStale(project, q.data?.change_seq, q.data?.valid_until);
  const choose = (e: FormEvent) => {
    e.preventDefault();
    const next = new URLSearchParams(params);
    next.set("branch", branchInput.trim());
    setParams(next);
  };
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /{" "}
        <Link to={`/p/${enc(project)}/checklists`}>checklists</Link> / {checklist}
      </p>
      <form className="inline" onSubmit={choose}>
        <label>
          Branch{" "}
          <input
            value={branchInput}
            onChange={(e) => setBranchInput(e.target.value)}
            placeholder="repo/name"
            required
          />
        </label>
        <button type="submit">Evaluate</button>
      </form>
      {!branch ? (
        <Empty>Choose a repository-qualified branch to evaluate.</Empty>
      ) : q.isPending ? (
        <Loading what="evaluation" />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : (
        <>
          <h1>
            {q.data.checklist.title} (version {q.data.checklist.version}):{" "}
            <span className={q.data.ready ? "verdict verdict-pass" : "verdict verdict-fail"}>
              {q.data.ready ? "Ready for sign-off review" : "Not ready"}
            </span>
            {stale && " (stale)"}
          </h1>
          <StaleBanner reason={stale} onRefresh={() => void q.refetch()} />
          <p className="muted">
            Feature {q.data.checklist.feature} on {q.data.branch}, evaluated {q.data.evaluated_at}
            {q.data.valid_until && `, valid until ${q.data.valid_until}`}. Digest{" "}
            <code>{q.data.digest}</code>
          </p>
          <Section title="Requirements">
            <table>
              <thead>
                <tr>
                  <th>Requirement</th>
                  <th>State</th>
                  <th>Owner</th>
                  <th>Required tests / configs</th>
                  <th>Seeds</th>
                  <th>Evidence</th>
                  <th>Next action</th>
                </tr>
              </thead>
              <tbody>
                {q.data.items.map((it) => (
                  <tr key={it.item_id}>
                    <td>
                      {it.title}
                      <div className="muted">{it.item_id}</div>
                    </td>
                    <td>
                      <span className={`item item-${it.state}`}>{STATE_LABEL[it.state] ?? it.state}</span>
                      {(it.reasons ?? []).length > 0 && (
                        <details>
                          <summary>{it.reasons?.length} reason(s)</summary>
                          <ul>
                            {it.reasons?.map((r, i) => (
                              <li key={i}>{r}</li>
                            ))}
                          </ul>
                        </details>
                      )}
                    </td>
                    <td>{it.owner}</td>
                    <td>
                      {it.requires?.tests.join(", ")}
                      {(it.requires?.configs ?? []).length > 0 && ` / ${it.requires?.configs?.join(", ")}`}
                    </td>
                    <td>
                      {(it.seeds_by_simulator ?? []).map((s) => (
                        <div key={s.simulator}>
                          {s.simulator || "simulator?"} {s.achieved}/{s.required}
                        </div>
                      ))}
                    </td>
                    <td>
                      {[...new Set((it.pairs ?? []).map((p) => p.regression))].join(", ")}
                      {it.evidence_digest && (
                        <div>
                          {it.attestation ? "attested" : "not attested"}
                          <Attest
                            project={project}
                            checklist={checklist}
                            version={q.data.checklist.version}
                            item={it}
                            onDone={() => qc.invalidateQueries({ queryKey: key })}
                          />
                        </div>
                      )}
                    </td>
                    <td>{it.next_action ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
        </>
      )}
    </>
  );
}
