import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, enc, type ProjectList } from "../api/client";
import { Empty, ErrorBox, Loading } from "../components/ui";

export function ProjectsPage() {
  const q = useQuery({
    queryKey: ["projects"],
    queryFn: () => api<ProjectList>("/api/v1/projects"),
  });
  if (q.isPending) return <Loading what="projects" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const projects = q.data.projects;
  return (
    <>
      <h1>Projects</h1>
      {projects.length === 0 ? (
        <Empty>No projects you can read.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Project</th>
              <th>Policy</th>
              <th>Your role</th>
            </tr>
          </thead>
          <tbody>
            {projects.map((p) => (
              <tr key={p.name}>
                <td>
                  <Link to={`/p/${enc(p.name)}`}>{p.name}</Link>
                </td>
                <td>{p.policy}</td>
                <td>{p.role ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
