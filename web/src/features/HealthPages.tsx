import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router-dom";
import {
  ApiError,
  api,
  enc,
  type HealthGrowth,
  type HealthHistory,
  type HierarchyRead,
  type HealthPage as Page,
  type HealthStreamRow,
  type NodeHealth,
} from "../api/client";
import { StaleBanner, useStale } from "../components/stale";
import { Empty, ErrorBox, Loading } from "../components/ui";

// Regression health dashboard: a project, node (subsystem, block…) or stream page. Every
// value comes from the server; colour never stands alone (each badge says its state).

const TREND_LABEL: Record<string, string> = {
  green: "clean",
  yellow: "no worse",
  red: "worse",
  running: "running",
  no_data: "no data",
  no_baseline: "no baseline",
  not_comparable: "not comparable",
};
const VERDICT_LABEL: Record<string, string> = {
  pass: "pass",
  accepted_with_exceptions: "accepted with exceptions",
  fail: "fail",
  insufficient_evidence: "insufficient evidence",
};
const VERDICT_COLOUR: Record<string, string> = {
  pass: "green",
  accepted_with_exceptions: "yellow",
  fail: "red",
  insufficient_evidence: "grey",
};
const GREY_LABEL: Record<string, string> = {
  no_data: "no data",
  running: "running",
  no_baseline: "no baseline",
  not_comparable: "not comparable",
  insufficient_evidence: "insufficient evidence",
  overdue: "overdue",
};

function Badge({ colour, label }: { colour: string; label: string }) {
  return <span className={`hb hb-${colour}`}>{label}</span>;
}

function TrendBadge({ trend }: { trend: string | null }) {
  if (!trend) return <Badge colour="grey" label="—" />;
  const colour = ["green", "yellow", "red"].includes(trend) ? trend : "grey";
  return <Badge colour={colour} label={TREND_LABEL[trend] ?? trend} />;
}

function VerdictBadge({ verdict }: { verdict: string | null }) {
  if (!verdict) return <Badge colour="grey" label="—" />;
  return <Badge colour={VERDICT_COLOUR[verdict] ?? "grey"} label={VERDICT_LABEL[verdict] ?? verdict} />;
}

/** The grey counts of a roll-up ("2 no data, 1 running"), empty when none. */
function greyText(grey: Record<string, number>, only?: string[]): string {
  return Object.entries(grey)
    .filter(([k, n]) => n > 0 && (!only || only.includes(k)))
    .map(([k, n]) => `${n} ${GREY_LABEL[k] ?? k}`)
    .join(", ");
}

const TREND_GREY = ["no_data", "running", "no_baseline", "not_comparable", "overdue"];

/** A node's worst trend colour, always with the streams that have none beside it. */
function NodeBadge({ colour, grey }: { colour: string | null; grey: Record<string, number> }) {
  const g = greyText(grey, TREND_GREY);
  if (!colour) return <Badge colour="grey" label={g || "—"} />;
  const label = { green: "clean", yellow: "no worse", red: "worse" }[colour] ?? colour;
  return (
    <>
      <Badge colour={colour} label={label} />
      {g ? <span className="sub">and {g}</span> : null}
    </>
  );
}

function NodeReadiness({ colour, grey }: { colour: string | null; grey: Record<string, number> }) {
  const g = greyText(grey, ["insufficient_evidence", "no_data"]);
  if (!colour) return <Badge colour="grey" label={g || "—"} />;
  const label = { green: "pass", yellow: "with exceptions", red: "fail" }[colour] ?? colour;
  return (
    <>
      <Badge colour={colour} label={label} />
      {g ? <span className="sub">and {g}</span> : null}
    </>
  );
}

function pct(x: number | null | undefined): string {
  return x === null || x === undefined ? "N/A" : `${x.toFixed(1)}%`;
}

function signed(x: number | null | undefined, unit = ""): string {
  if (x === null || x === undefined) return "N/A";
  const r = Math.round(x * 10) / 10;
  if (r === 0) return "same";
  return `${r > 0 ? "+" : ""}${r}${unit}`;
}

function Delta({ now, before, worseWhenUp = true }: { now: number; before?: number | null; worseWhenUp?: boolean }) {
  if (before === null || before === undefined) return <span className="delta muted">N/A vs last</span>;
  const d = now - before;
  const cls = d === 0 ? "muted" : (d > 0) === worseWhenUp ? "delta-bad" : "delta-good";
  return <span className={`delta ${cls}`}>{d === 0 ? "same" : `${d > 0 ? "+" : ""}${d}`} vs last</span>;
}

function minutesDelta(s: number | null | undefined): string {
  return s === null || s === undefined ? "N/A" : signed(s / 60, " min");
}

function hours(s: number | null | undefined): string {
  if (s === null || s === undefined) return "N/A";
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

/** The node path of the current route (`/p/:project/health/<path>`). */
function useAreaPath(): string {
  const loc = useLocation();
  const project = useParams().project ?? "";
  const prefix = `/p/${enc(project)}/health/`;
  const p = loc.pathname.startsWith(prefix) ? loc.pathname.slice(prefix.length) : "";
  return decodeURIComponent(p);
}

function nodeLink(project: string, path: string): string {
  return path ? `/p/${enc(project)}/health/${path.split("/").map(enc).join("/")}` : `/p/${enc(project)}/health`;
}

function streamLink(project: string, s: { producer: string; suite: string; branch: string }): string {
  return `/p/${enc(project)}/health-stream?producer=${enc(s.producer)}&suite=${enc(s.suite)}&branch=${enc(s.branch)}`;
}

/** Refetch when the project changes past the page's watermark or its validity ends. */
function useFreshness(project: string, watermark: number | undefined, validUntil: string | null | undefined, keys: unknown[][]) {
  const qc = useQueryClient();
  const stale = useStale(project, watermark, validUntil);
  const refresh = () => keys.forEach((k) => void qc.invalidateQueries({ queryKey: k }));
  useEffect(() => {
    if (stale) refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stale]);
  return { stale, refresh };
}

function Kpis({ k }: { k: NodeHealth }) {
  const overdue = k.grey.overdue ?? 0;
  return (
    <div className="kpis">
      <div>
        <span className="kpi-label">Readiness</span>
        <NodeReadiness colour={k.readiness} grey={k.grey} />
      </div>
      <div>
        <span className="kpi-label">Trend</span>
        <NodeBadge colour={k.trend} grey={k.grey} />
      </div>
      <div>
        <span className="kpi-label">Pass rate</span>
        <b>{pct(k.pass_rate)}</b>
        <span className="delta">
          {signed(k.pass_rate_delta_pts, " pts")} vs last
          {k.compared_streams < k.streams ? ` (over ${k.compared_streams} of ${k.streams} streams)` : ""}
        </span>
        {k.worst_rate !== null && k.worst_rate !== k.pass_rate ? (
          <span className="sub">worst stream {pct(k.worst_rate)}</span>
        ) : null}
      </div>
      <div>
        <span className="kpi-label">Tests (required runs)</span>
        <b>{k.counts.required}</b>
        <Delta
          now={k.compared_counts.required}
          before={k.compared_streams ? k.compared_baseline_counts.required : null}
          worseWhenUp={false}
        />
        {k.compared_streams < k.streams ? (
          <span className="sub">change over {k.compared_streams} of {k.streams} streams</span>
        ) : null}
        {k.zero_test_streams ? (
          <span className="sub">
            <Badge colour="red" label={`${k.zero_test_streams} stream${k.zero_test_streams === 1 ? "" : "s"} with 0 tests`} />
          </span>
        ) : null}
      </div>
      <div>
        <span className="kpi-label">New signatures</span>
        <b>{k.signatures.new}</b>
      </div>
      <div>
        <span className="kpi-label">Undecided</span>
        <b>{k.signatures.undecided ?? "N/A"}</b>
      </div>
      <div>
        <span className="kpi-label">Overdue regressions</span>
        <b>
          {overdue} of {k.streams}
        </b>
      </div>
    </div>
  );
}

/** One column of a health table: the first (the name) is always shown. */
type Column<T> = { key: string; label: string; num?: boolean; cell: (row: T) => ReactNode };

/** Columns a viewer hid on this browser (per table); a store that fails shows every column. */
function useHidden(table: string): [Set<string>, (key: string, hide: boolean) => void] {
  const storeKey = `dviscope.health.hidden.${table}`;
  const [hidden, setHidden] = useState<Set<string>>(() => {
    try {
      const v: unknown = JSON.parse(localStorage.getItem(storeKey) ?? "[]");
      return new Set(Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
    } catch {
      return new Set();
    }
  });
  const set = (key: string, hide: boolean) =>
    setHidden((prev) => {
      const next = new Set(prev);
      if (hide) next.add(key);
      else next.delete(key);
      try {
        localStorage.setItem(storeKey, JSON.stringify([...next]));
      } catch {
        // Not remembered (private window, blocked storage): this page still applies it.
      }
      return next;
    });
  return [hidden, set];
}

function HealthTable<T>({
  table,
  first,
  firstCell,
  columns,
  rows,
  rowKey,
}: {
  table: string;
  first: string;
  firstCell: (row: T) => ReactNode;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
}) {
  const [hidden, setHidden] = useHidden(table);
  const shown = columns.filter((c) => !hidden.has(c.key));
  return (
    <>
      <details className="columns">
        <summary>Columns{hidden.size > 0 ? ` (${columns.length - shown.length} hidden)` : ""}</summary>
        {columns.map((c) => (
          <label key={c.key}>
            <input type="checkbox" checked={!hidden.has(c.key)} onChange={(e) => setHidden(c.key, !e.target.checked)} />{" "}
            {c.label}
          </label>
        ))}
      </details>
      <table className="health">
        <thead>
          <tr>
            <th>{first}</th>
            {shown.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={rowKey(r)}>
              <td>{firstCell(r)}</td>
              {shown.map((c) => (
                <td key={c.key} className={c.num ? "num" : undefined}>
                  {c.cell(r)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

/** Required runs with the change since the predecessor: fewer is the bad direction, and 0
 * is called out (an emptied or broken run list). */
function Tests({ now, before, zero }: { now: number; before?: number | null; zero: boolean }) {
  return (
    <>
      {zero ? <Badge colour="red" label="0 tests" /> : now}
      <Delta now={now} before={before} worseWhenUp={false} />
    </>
  );
}

function StreamTable({ project, rows }: { project: string; rows: HealthStreamRow[] }) {
  const regLink = (r: HealthStreamRow) =>
    r.latest ? `/p/${enc(project)}/r/${enc(r.latest.ref)}?producer=${enc(r.stream!.producer)}` : null;
  const columns: Column<HealthStreamRow>[] = [
    {
      key: "readiness",
      label: "Readiness",
      cell: (r) =>
        r.latest ? (
          <Link to={`/p/${enc(project)}/r/${enc(r.latest.ref)}/readiness?producer=${enc(r.stream!.producer)}`}>
            <VerdictBadge verdict={r.verdict} />
          </Link>
        ) : (
          <VerdictBadge verdict={null} />
        ),
    },
    { key: "trend", label: "Trend", cell: (r) => <TrendBadge trend={r.trend} /> },
    {
      key: "pass_rate",
      label: "Pass rate",
      cell: (r) => (
        <>
          {pct(r.pass_rate)}
          <span className="delta">{signed(r.pass_rate_delta_pts, " pts")} vs last</span>
        </>
      ),
    },
    {
      key: "tests",
      label: "Tests",
      num: true,
      cell: (r) => <Tests now={r.counts.required} before={r.baseline_counts?.required} zero={!!r.latest && r.counts.required === 0} />,
    },
    {
      key: "failed",
      label: "Failed",
      num: true,
      cell: (r) => (
        <>
          {r.counts.failed}
          <Delta now={r.counts.failed} before={r.baseline_counts?.failed} />
        </>
      ),
    },
    {
      key: "blocked",
      label: "Blocked",
      num: true,
      cell: (r) => (
        <>
          {r.counts.blocked}
          <Delta now={r.counts.blocked} before={r.baseline_counts?.blocked} />
        </>
      ),
    },
    {
      key: "missing",
      label: "Missing",
      num: true,
      cell: (r) => (
        <>
          {r.counts.missing}
          <Delta now={r.counts.missing} before={r.baseline_counts?.missing} />
        </>
      ),
    },
    {
      key: "new_signatures",
      label: "New signatures",
      num: true,
      cell: (r) => {
        const l = regLink(r);
        return (
          <>
            {l ? <Link to={l}>{r.signatures.new}</Link> : r.signatures.new}
            <span className="delta muted">{r.signatures.undecided ?? 0} undecided</span>
          </>
        );
      },
    },
    {
      key: "elapsed",
      label: "Elapsed",
      cell: (r) => (
        <>
          {hours(r.cost.elapsed_s)}
          {r.cost.last_end_partial ? <span className="delta muted">partial</span> : null}
        </>
      ),
    },
  ];
  return (
    <HealthTable
      table="streams"
      first="Stream"
      rows={rows}
      rowKey={(r) => `${r.stream!.producer}/${r.stream!.suite}/${r.stream!.branch}`}
      columns={columns}
      firstCell={(r) => {
        const st = r.stream!;
        return (
          <>
            <Link to={streamLink(project, st)}>{st.suite}</Link>
            <span className="sub">
              {st.producer} · {st.branch}
              {r.shared_from ? ` · shared from ${r.shared_from}` : ""}
              {r.overdue ? " · overdue" : ""}
            </span>
          </>
        );
      }}
    />
  );
}

function ChildTable({ project, rows }: { project: string; rows: Page["children"] }) {
  type Row = Page["children"][number];
  const before = (h: Row["health"], n: number) => (h.compared_streams ? n : null);
  const columns: Column<Row>[] = [
    {
      key: "readiness",
      label: "Readiness",
      cell: (c) => (
        <Link to={nodeLink(project, c.path)} className="badge-link">
          <NodeReadiness colour={c.health.readiness} grey={c.health.grey} />
        </Link>
      ),
    },
    {
      key: "trend",
      label: "Trend",
      cell: (c) => (
        <Link to={nodeLink(project, c.path)} className="badge-link">
          <NodeBadge colour={c.health.trend} grey={c.health.grey} />
        </Link>
      ),
    },
    {
      key: "pass_rate",
      label: "Pass rate",
      cell: (c) => (
        <>
          {pct(c.health.pass_rate)}
          <span className="delta">{signed(c.health.pass_rate_delta_pts, " pts")} vs last</span>
        </>
      ),
    },
    {
      key: "tests",
      label: "Tests",
      num: true,
      cell: (c) => (
        <>
          {c.health.counts.required}
          <Delta
            now={c.health.compared_counts.required}
            before={before(c.health, c.health.compared_baseline_counts.required)}
            worseWhenUp={false}
          />
          {c.health.zero_test_streams ? (
            <span className="sub">
              <Badge colour="red" label={`${c.health.zero_test_streams} with 0 tests`} />
            </span>
          ) : null}
        </>
      ),
    },
    {
      key: "failed",
      label: "Failed",
      num: true,
      cell: (c) => (
        <>
          {c.health.counts.failed}
          <Delta now={c.health.compared_counts.failed} before={before(c.health, c.health.compared_baseline_counts.failed)} />
        </>
      ),
    },
    {
      key: "blocked",
      label: "Blocked",
      num: true,
      cell: (c) => (
        <>
          {c.health.counts.blocked}
          <Delta now={c.health.compared_counts.blocked} before={before(c.health, c.health.compared_baseline_counts.blocked)} />
        </>
      ),
    },
    {
      key: "new_signatures",
      label: "New signatures",
      num: true,
      cell: (c) => (
        <>
          {c.health.signatures.new}
          <span className="delta muted">{c.health.signatures.undecided ?? 0} undecided</span>
        </>
      ),
    },
    {
      key: "slowest",
      label: "Slowest",
      cell: (c) => (
        <>
          {hours(c.health.elapsed_s)}
          {c.health.elapsed_partial ? <span className="delta muted">partial</span> : null}
        </>
      ),
    },
  ];
  return (
    <HealthTable
      table="children"
      first="Name"
      rows={rows}
      rowKey={(c) => c.path}
      columns={columns}
      firstCell={(c) => {
        const h = c.health;
        return (
          <>
            <Link to={nodeLink(project, c.path)}>{c.title}</Link>
            <span className="sub">
              {h.streams} stream{h.streams === 1 ? "" : "s"}
              {c.children ? ` · ${c.children} below` : ""}
              {h.compared_streams < h.streams
                ? ` · changes over ${h.compared_streams} of ${h.streams} (others have no predecessor)`
                : ""}
              {h.worst_rate !== null && h.worst_rate !== h.pass_rate ? ` · worst ${pct(h.worst_rate)}` : ""}
            </span>
          </>
        );
      }}
    />
  );
}

/** Lines, oldest left, drawn at a fixed size (wide periods scroll sideways, text never
 * shrinks), with the y maximum and the first and last day named; each series has its own
 * colour and stroke; the same values as a table below. */
function Lines({
  title,
  rows,
  series,
}: {
  title: string;
  rows: { label: string; values: Record<string, number> }[];
  series: readonly { key: string; label: string; colour: string; dash?: string }[];
}) {
  const max = Math.max(1, ...rows.flatMap((r) => series.map((s) => r.values[s.key] ?? 0)));
  const h = 140;
  const left = 44;
  const step = rows.length > 1 ? Math.max(4, Math.min(24, 600 / (rows.length - 1))) : 0;
  const width = Math.max(320, left + step * Math.max(0, rows.length - 1) + 80);
  const y = (v: number) => h - (v / max) * h;
  return (
    <figure className="chart">
      <figcaption>
        {title}{" "}
        {series.map((s) => (
          <span key={s.key} className="legend">
            <svg aria-hidden="true" width="22" height="10" className="legend-line">
              <line x1="1" y1="5" x2="21" y2="5" stroke={s.colour} strokeWidth="2" strokeDasharray={s.dash} />
            </svg>{" "}
            {s.label}
          </span>
        ))}
      </figcaption>
      <div className="chart-scroll">
        <svg aria-hidden="true" viewBox={`0 0 ${width} ${h + 22}`} width={width} height={h + 22}>
          <line x1={left - 2} y1={0} x2={left - 2} y2={h} className="axis" />
          <line x1={left - 2} y1={h} x2={width} y2={h} className="axis" />
          <text x={left - 6} y={10} textAnchor="end" className="tick">
            {max}
          </text>
          <text x={left - 6} y={h} textAnchor="end" className="tick">
            0
          </text>
          {series.map((s) => (
            <polyline
              key={s.key}
              fill="none"
              stroke={s.colour}
              strokeWidth={2}
              strokeDasharray={s.dash}
              points={rows.map((r, i) => `${left + i * step},${y(r.values[s.key] ?? 0)}`).join(" ")}
            />
          ))}
          {rows.length > 0 && (
            <text x={left} y={h + 16} className="tick">
              {rows[0]!.label}
            </text>
          )}
          {rows.length > 1 && (
            <text x={left + step * (rows.length - 1)} y={h + 16} textAnchor="end" className="tick">
              {rows[rows.length - 1]!.label}
            </text>
          )}
        </svg>
      </div>
      <details>
        <summary>Values</summary>
        <table>
          <caption className="sr-only">{title}</caption>
          <thead>
            <tr>
              <th scope="col">Day</th>
              {series.map((s) => (
                <th scope="col" key={s.key}>
                  {s.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.label}>
                <th scope="row">{r.label}</th>
                {series.map((s) => (
                  <td className="num" key={s.key}>
                    {r.values[s.key] ?? 0}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

const GROWTH = [
  { key: "required_runs", label: "Required runs", colour: "#2a78d6" },
  { key: "tests", label: "Distinct tests", colour: "#6250d6", dash: "6 3" },
] as const;

/** Milliseconds from `now` to the next UTC midnight (at least 1). */
export function msUntilUtcMidnight(now: number): number {
  const d = new Date(now);
  const next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
  return Math.max(1, next - now);
}

/** Today's UTC date, changing at UTC midnight (the growth days end today). */
function useUtcDay(): string {
  const [day, setDay] = useState(() => new Date().toISOString().slice(0, 10));
  useEffect(() => {
    const t = setTimeout(() => setDay(new Date().toISOString().slice(0, 10)), msUntilUtcMidnight(Date.now()) + 1000);
    return () => clearTimeout(t);
  }, [day]);
  return day;
}

/** How the node's test inventory grew, day by day (loaded apart from the page). */
function Growth({ project, area, watermark }: { project: string; area: string; watermark: number }) {
  const [days, setDays] = useState(90);
  const today = useUtcDay();
  const q = useQuery({
    queryKey: ["health-growth", project, area, days, watermark, today],
    queryFn: () =>
      api<HealthGrowth>(
        `/api/v1/projects/${enc(project)}/health/growth?days=${days}${area ? `&area=${enc(area)}` : ""}`,
      ),
  });
  const periods = [365, 180, 90, 30, 7];
  const tooLarge = q.error instanceof ApiError && q.error.body.code === "E_TOO_LARGE";
  const shorter = periods.find((n) => n < days);
  return (
    <section>
      <h2>Test growth</h2>
      <label className="history-length">
        Period:{" "}
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {periods.map((n) => (
            <option key={n} value={n}>
              last {n} days
            </option>
          ))}
        </select>
      </label>
      {q.isPending ? (
        <Loading what="test growth" />
      ) : q.error ? (
        <>
          <ErrorBox error={q.error} />
          {tooLarge && shorter !== undefined && (
            <p>
              <button type="button" onClick={() => setDays(shorter)}>
                Show the last {shorter} days
              </button>
            </p>
          )}
        </>
      ) : (
        <Lines
          title="Tests per day (each stream's latest regression by that day)"
          rows={q.data.days.map((d) => ({ label: d.date, values: { required_runs: d.required_runs, tests: d.tests } }))}
          series={GROWTH}
        />
      )}
    </section>
  );
}

export function HealthPage() {
  const project = useParams().project ?? "";
  const area = useAreaPath();
  const key = ["health", project, area];
  const q = useQuery({
    queryKey: key,
    queryFn: () =>
      api<Page>(`/api/v1/projects/${enc(project)}/health${area ? `?area=${enc(area)}` : ""}`),
  });
  const { stale, refresh } = useFreshness(project, q.data?.watermark, q.data?.valid_until, [key]);
  // A refused page (too much work) keeps its navigation: the hierarchy names the nodes below.
  const refused = q.error instanceof ApiError && q.error.body.code === "E_TOO_LARGE";
  const tree = useQuery({
    queryKey: ["hierarchy", project],
    enabled: refused,
    queryFn: () => api<HierarchyRead>(`/api/v1/projects/${enc(project)}/hierarchy`),
  });
  if (q.isPending) return <Loading what="health" />;
  if (q.error) {
    const nodes = tree.data?.hierarchy?.nodes ?? [];
    const below = nodes.filter((n) => {
      const cut = n.path.lastIndexOf("/");
      const parent = cut < 0 ? "" : n.path.slice(0, cut);
      return parent === area;
    });
    return (
      <>
        <p className="crumbs">
          <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /{" "}
          <Link to={nodeLink(project, "")}>health</Link>
          {area ? ` / ${area}` : ""}
        </p>
        <ErrorBox error={q.error} />
        {refused && below.length > 0 && (
          <section>
            <h2>Open a lower node</h2>
            <ul>
              {below.map((n) => (
                <li key={n.path}>
                  <Link to={nodeLink(project, n.path)}>{n.title ?? n.path}</Link>
                </li>
              ))}
              {area === "" && (
                <li>
                  <Link to={nodeLink(project, "~unassigned")}>Unassigned</Link>
                </li>
              )}
            </ul>
          </section>
        )}
      </>
    );
  }
  const p = q.data;
  const kind = p.node.kind;
  const childLabel = kind === "project" ? "Areas" : "Below";
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /{" "}
        {kind === "project" ? (
          "health"
        ) : (
          <>
            <Link to={nodeLink(project, "")}>health</Link>
            {p.node.breadcrumb.map((b) => (
              <span key={b.path}>
                {" / "}
                <Link to={nodeLink(project, b.path)}>{b.title ?? b.path}</Link>
              </span>
            ))}{" "}
            / {p.node.title}
          </>
        )}
      </p>
      <h1>{kind === "project" ? `Health of ${project}` : p.node.title}</h1>
      <StaleBanner reason={stale} onRefresh={refresh} />
      <Kpis k={p.kpi} />
      {p.own.length > 0 && (
        <section>
          <h2>{kind === "project" ? "Regressions" : `Regressions of ${p.node.title}`}</h2>
          <StreamTable project={project} rows={p.own} />
        </section>
      )}
      {p.children.length > 0 && (
        <section>
          <h2>{childLabel}</h2>
          <ChildTable project={project} rows={p.children} />
        </section>
      )}
      {p.own.length === 0 && p.children.length === 0 && (
        <Empty>Nothing here yet: attach regression streams to this node in the hierarchy file.</Empty>
      )}
      {p.hierarchy_revision === null && kind === "project" && (
        <p className="muted">
          No hierarchy yet: every regression stream is listed here. Import one with{" "}
          <code>dviscope hierarchy import</code> to group them by subsystem and block.
        </p>
      )}
      {(p.own.length > 0 || p.children.length > 0) && (
        <Growth project={project} area={area} watermark={p.watermark} />
      )}
      <p className="muted">Evaluated {p.evaluated_at}.</p>
    </>
  );
}

const OUTCOME = [
  { key: "failed", label: "Failed", colour: "var(--fail)" },
  { key: "blocked", label: "Blocked", colour: "#c4622d" },
  { key: "missing", label: "Missing", colour: "var(--muted)" },
  { key: "running", label: "Running", colour: "#2a78d6" },
  { key: "cancelled", label: "Cancelled", colour: "#8a5a00" },
  { key: "skipped", label: "Skipped", colour: "#9085e9" },
] as const;
const TURNOVER = [
  { key: "new", label: "New", colour: "var(--fail)" },
  { key: "persistent", label: "Persistent", colour: "#6250d6" },
  { key: "no_longer_observed", label: "No longer seen", colour: "var(--pass)" },
] as const;

/** Stacked bars, oldest left, with the y maximum and the first and last regression named;
 * the same values as a table below (for screen readers and exact numbers). */
function Bars({
  title,
  rows,
  series,
}: {
  title: string;
  rows: { label: string; values: Record<string, number> }[];
  series: readonly { key: string; label: string; colour: string }[];
}) {
  const max = Math.max(1, ...rows.map((r) => series.reduce((a, s) => a + (r.values[s.key] ?? 0), 0)));
  const w = 24;
  const h = 140;
  const left = 28;
  const width = left + rows.length * w + 8;
  return (
    <figure className="chart">
      <figcaption>
        {title}{" "}
        {series.map((s) => (
          <span key={s.key} className="legend">
            <i style={{ background: s.colour }} aria-hidden="true" /> {s.label}
          </span>
        ))}
      </figcaption>
      <svg aria-hidden="true" viewBox={`0 0 ${width} ${h + 22}`} width="100%" height={h + 22}>
        <line x1={left - 2} y1={0} x2={left - 2} y2={h} className="axis" />
        <line x1={left - 2} y1={h} x2={width} y2={h} className="axis" />
        <text x={left - 6} y={10} textAnchor="end" className="tick">
          {max}
        </text>
        <text x={left - 6} y={h} textAnchor="end" className="tick">
          0
        </text>
        {rows.map((r, i) => {
          let y = h;
          return (
            <g key={r.label}>
              {series.map((s) => {
                const v = r.values[s.key] ?? 0;
                const bh = (v / max) * h;
                y -= bh;
                return v > 0 ? (
                  <rect key={s.key} x={left + i * w} y={y} width={w - 6} height={bh} fill={s.colour} rx={2} />
                ) : null;
              })}
            </g>
          );
        })}
        {rows.length > 0 && (
          <text x={left} y={h + 16} className="tick">
            {rows[0]!.label}
          </text>
        )}
        {rows.length > 1 && (
          <text x={width - 4} y={h + 16} textAnchor="end" className="tick">
            {rows[rows.length - 1]!.label}
          </text>
        )}
      </svg>
      <details>
        <summary>Values</summary>
        <table>
          <caption className="sr-only">{title}</caption>
          <thead>
            <tr>
              <th scope="col">Regression</th>
              {series.map((s) => (
                <th scope="col" key={s.key}>
                  {s.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.label}>
                <th scope="row">{r.label}</th>
                {series.map((s) => (
                  <td className="num" key={s.key}>
                    {r.values[s.key] ?? 0}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

export function HealthStreamPage() {
  const project = useParams().project ?? "";
  const [sp] = useSearchParams();
  const producer = sp.get("producer") ?? "";
  const suite = sp.get("suite") ?? "";
  const branch = sp.get("branch") ?? "";
  const [limit, setLimit] = useState(30);
  const key = ["health-history", project, producer, suite, branch, limit];
  const q = useQuery({
    queryKey: key,
    queryFn: () =>
      api<HealthHistory>(
        `/api/v1/projects/${enc(project)}/health/history?producer=${enc(producer)}&suite=${enc(suite)}&branch=${enc(branch)}&limit=${limit}`,
      ),
  });
  const { stale, refresh } = useFreshness(project, q.data?.watermark, q.data?.valid_until, [key]);
  const lengths = [30, 10, 5, 2, 1];
  const selector = (
    <label className="history-length">
      History:{" "}
      <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
        {lengths.map((n) => (
          <option key={n} value={n}>
            {n === 1 ? "latest regression only" : `last ${n} regressions`}
          </option>
        ))}
      </select>
    </label>
  );
  if (q.isPending) return <Loading what="history" />;
  if (q.error) {
    // Too much work for one read: offer a shorter history instead of a dead end.
    const tooLarge = q.error instanceof ApiError && q.error.body.code === "E_TOO_LARGE";
    const shorter = lengths.find((n) => n < limit);
    return (
      <>
        <ErrorBox error={q.error} />
        {tooLarge && shorter !== undefined && (
          <p>
            <button type="button" onClick={() => setLimit(shorter)}>
              {shorter === 1 ? "Show the latest regression only" : `Show the last ${shorter} regressions`}
            </button>
          </p>
        )}
        {selector}
      </>
    );
  }
  const rows = q.data.regressions;
  const latest = rows[0];
  const oldestFirst = [...rows].reverse();
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / <Link to={`/p/${enc(project)}`}>{project}</Link> /{" "}
        <Link to={nodeLink(project, "")}>health</Link>
        {q.data.home ? (
          <>
            {" / "}
            <Link to={nodeLink(project, q.data.home)}>{q.data.home}</Link>
          </>
        ) : null}{" "}
        / {suite}
      </p>
      <h1>
        {suite} <span className="muted">{producer} · {branch}</span>
      </h1>
      <StaleBanner reason={stale} onRefresh={refresh} />
      {latest?.overdue ? (
        <p className="stale" role="alert">
          Overdue: no regression of this stream started within its cadence (
          {q.data.cadence_hours} h plus grace).
        </p>
      ) : null}
      {selector}
      {!latest || !latest.latest ? (
        <Empty>No regression of this stream yet.</Empty>
      ) : (
        <>
          <table className="facts">
            <tbody>
              <tr>
                <th>Latest</th>
                <td>
                  <Link to={`/p/${enc(project)}/r/${enc(latest.latest.ref)}?producer=${enc(producer)}`}>
                    {latest.latest.ref}
                  </Link>{" "}
                  ({latest.latest.state}) vs {latest.baseline ?? "no predecessor"}
                </td>
              </tr>
              <tr>
                <th>Readiness</th>
                <td>
                  <Link to={`/p/${enc(project)}/r/${enc(latest.latest.ref)}/readiness?producer=${enc(producer)}`}>
                    <VerdictBadge verdict={latest.verdict} />
                  </Link>{" "}
                  (before: {latest.baseline_verdict ? VERDICT_LABEL[latest.baseline_verdict] : "N/A"})
                </td>
              </tr>
              <tr>
                <th>Trend</th>
                <td>
                  <TrendBadge trend={latest.trend} />
                  {latest.worse && latest.worse.length > 0 ? ` (${latest.worse.join(", ").replace(/_/g, " ")})` : ""}
                  {" · "}
                  {latest.signatures.new} new, {latest.signatures.undecided ?? 0} undecided signatures
                </td>
              </tr>
              <tr>
                <th>Cadence</th>
                <td>
                  {q.data.cadence_hours ? `every ${q.data.cadence_hours} h` : "none set"}
                  {latest.overdue_at ? ` · overdue after ${latest.overdue_at}` : ""}
                  {latest.overdue ? " · overdue" : ""}
                </td>
              </tr>
              <tr>
                <th>Started</th>
                <td>{latest.latest.started_at}</td>
              </tr>
              <tr>
                <th>Latest observed end</th>
                <td>
                  {latest.cost.last_end ?? "N/A"}
                  {latest.cost.last_end_partial ? " (partial: an end was not reported)" : ""}
                </td>
              </tr>
              <tr>
                <th>Elapsed</th>
                <td>
                  {hours(latest.cost.elapsed_s)} ({minutesDelta(latest.deltas?.elapsed_s)} vs last)
                </td>
              </tr>
              <tr>
                <th>Machine time</th>
                <td>
                  {hours(latest.cost.machine_s)}
                  {latest.cost.machine_partial ? " (partial: a run did not report its wall time)" : ""} (
                  {minutesDelta(latest.deltas?.machine_s)} vs last)
                </td>
              </tr>
              <tr>
                <th>CPU</th>
                <td>
                  {hours(latest.cost.cpu_s)} · measured {latest.cost.cpu_measured} of {latest.cost.cpu_slots}
                  {latest.cost.cpu_scope ? ` (${latest.cost.cpu_scope})` : " (scope mixed or unknown)"} (
                  {latest.deltas?.cpu_s === null || latest.deltas?.cpu_s === undefined
                    ? "not comparable"
                    : `${minutesDelta(latest.deltas.cpu_s)} vs last`}
                  )
                </td>
              </tr>
              <tr>
                <th>Tests (required)</th>
                <td>
                  {latest.counts.required} planned · {latest.counts.passed} passed · {latest.counts.failed} failed
                  {latest.counts.of_which_timeout ? ` (${latest.counts.of_which_timeout} timeouts)` : ""} ·{" "}
                  {latest.counts.blocked} blocked · {latest.counts.missing} missing
                  {latest.counts.running ? ` · ${latest.counts.running} running` : ""}
                  {latest.counts.cancelled ? ` · ${latest.counts.cancelled} cancelled` : ""}
                  {latest.counts.skipped ? ` · ${latest.counts.skipped} skipped` : ""}
                  {latest.counts.optional ? ` · ${latest.counts.optional} optional` : ""}
                </td>
              </tr>
              <tr>
                <th>Configurations</th>
                <td>
                  {latest.configs_added} added · {latest.configs_removed} removed vs the predecessor
                </td>
              </tr>
            </tbody>
          </table>
          <Bars
            title="Tests per regression (required runs)"
            rows={oldestFirst.map((r) => ({ label: r.latest?.ref ?? "", values: { required: r.counts.required } }))}
            series={[{ key: "required", label: "Required runs", colour: "#2a78d6" }]}
          />
          <Bars
            title="Outcome history (required slots)"
            rows={oldestFirst.map((r) => ({
              label: r.latest?.ref ?? "",
              values: {
                failed: r.counts.failed,
                blocked: r.counts.blocked,
                missing: r.counts.missing,
                running: r.counts.running,
                cancelled: r.counts.cancelled,
                skipped: r.counts.skipped,
              },
            }))}
            series={OUTCOME}
          />
          <Bars
            title="Signature turnover"
            rows={oldestFirst.map((r) => ({
              label: r.latest?.ref ?? "",
              values: {
                new: r.signatures.new,
                persistent: r.signatures.persistent,
                no_longer_observed: r.signatures.no_longer_observed,
              },
            }))}
            series={TURNOVER}
          />
        </>
      )}
    </>
  );
}
