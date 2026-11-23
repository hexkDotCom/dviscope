import { useInfiniteQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, enc, type RegressionPage } from "../api/client";
import { Empty, ErrorBox, Loading, StateBadge } from "../components/ui";

export function RegressionsPage() {
  const project = useParams().project ?? "";
  const q = useInfiniteQuery({
    queryKey: ["regressions", project],
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) =>
      api<RegressionPage>(
        `/api/v1/projects/${enc(project)}/regressions?limit=50` +
          (pageParam === null ? "" : `&before=${enc(pageParam)}`),
      ),
    getNextPageParam: (last) => last.next,
  });
  if (q.isPending) return <Loading what="regressions" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const rows = q.data.pages.flatMap((p) => p.regressions);
  return (
    <>
      <p className="crumbs">
        <Link to="/">Projects</Link> / {project}
      </p>
      <h1>Regressions</h1>
      <p>
        <Link to={`/p/${enc(project)}/health`}>Health</Link> ·{" "}
        <Link to={`/p/${enc(project)}/checklists`}>Feature checklists</Link> ·{" "}
        <Link to={`/p/${enc(project)}/admin`}>Administration</Link>
      </p>
      {rows.length === 0 ? (
        <Empty>No regressions yet.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Regression</th>
              <th>Suite</th>
              <th>Branch</th>
              <th>Producer</th>
              <th>State</th>
              <th>Planned</th>
              <th>Started</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const base = `/p/${enc(project)}/r/${enc(r.ref)}`;
              const prod = `?producer=${enc(r.producer)}`;
              return (
                <tr key={`${r.producer}/${r.ref}`}>
                  <td>
                    <Link to={base + prod}>{r.ref}</Link>
                  </td>
                  <td>{r.suite}</td>
                  <td>{r.branch}</td>
                  <td>{r.producer}</td>
                  <td>
                    <StateBadge state={r.state} />
                  </td>
                  <td className="num">{r.planned}</td>
                  <td>{r.started_at}</td>
                  <td>
                    <Link to={`${base}/readiness${prod}`}>Readiness</Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {q.hasNextPage && (
        <button type="button" onClick={() => q.fetchNextPage()} disabled={q.isFetchingNextPage}>
          Older regressions
        </button>
      )}
    </>
  );
}
