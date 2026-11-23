import type { ReactNode } from "react";
import { ApiError } from "../api/client";

export function StateBadge({ state, detail }: { state: string; detail?: string | null }) {
  return (
    <span className={`badge badge-${state}`}>
      {state}
      {detail ? ` (${detail})` : ""}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  const label: Record<string, string> = {
    pass: "Pass",
    accepted_with_exceptions: "Accepted with exceptions",
    fail: "Fail",
    insufficient_evidence: "Insufficient evidence",
  };
  return <span className={`verdict verdict-${verdict}`}>{label[verdict] ?? verdict}</span>;
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg =
    error instanceof ApiError ? `${error.body.code}: ${error.body.message}` : String(error);
  return (
    <p className="error" role="alert">
      {msg}
    </p>
  );
}

export function Loading({ what }: { what: string }) {
  return <p className="muted">Loading {what}…</p>;
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="muted">{children}</p>;
}
