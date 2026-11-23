// API client: same-origin requests with the session cookie; every state-changing request
// carries the CSRF token received at login (X-DVIScope-CSRF). Errors are the server's
// error-registry bodies. Verdicts, eligibility and previews always come from the server.

export interface ApiErrorBody {
  code: string;
  message: string;
  field?: string;
  correlation_id?: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public body: ApiErrorBody,
  ) {
    super(body.message);
  }
}

const CSRF_KEY = "dviscope.csrf";

// The session's CSRF token, shared by every tab of this origin (a tab opened later has the
// session cookie too, and must be able to sign out).
function csrf(): string | null {
  try {
    return localStorage.getItem(CSRF_KEY);
  } catch {
    return null;
  }
}

export async function api<T>(
  path: string,
  init: { method?: string; body?: unknown; ifMatch?: number } = {},
): Promise<T> {
  const method = init.method ?? "GET";
  const headers: Record<string, string> = {};
  if (init.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const t = csrf();
    if (t) headers["X-DVIScope-CSRF"] = t;
  }
  if (init.ifMatch !== undefined) headers["If-Match"] = `"${init.ifMatch}"`;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  if (!res.ok) {
    const body = (json as ApiErrorBody | null) ?? {
      code: "E_INTERNAL",
      message: res.statusText,
    };
    if (res.status === 401) unauthenticated();
    throw new ApiError(res.status, body);
  }
  return json as T;
}

let onUnauthenticated: () => void = () => {};

/** Registers what to do when the session is missing or expired (the app shows sign-in). */
/** Window event: the session of this tab changed (signed in, out, or ended). */
export const SESSION_EVENT = "dviscope:session";

/** Announces a session change: the app mounts every page anew. */
export function sessionChanged() {
  window.dispatchEvent(new Event(SESSION_EVENT));
}

export function setUnauthenticatedHandler(f: () => void): void {
  onUnauthenticated = f;
}

function unauthenticated(): void {
  onUnauthenticated();
}

export async function login(username: string, password: string): Promise<void> {
  const res = await fetch("/api/v1/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password }),
  });
  if (res.status !== 204) {
    const body = (await res.json().catch(() => null)) ?? {
      code: "E_INTERNAL",
      message: res.statusText,
    };
    throw new ApiError(res.status, body);
  }
  const token = res.headers.get("X-DVIScope-CSRF");
  if (token) {
    try {
      localStorage.setItem(CSRF_KEY, token);
    } catch {
      /* storage unavailable: state-changing requests will ask to sign in again */
    }
  }
}

function forgetCsrf(): void {
  try {
    localStorage.removeItem(CSRF_KEY);
  } catch {
    /* nothing stored */
  }
}

/** Ends the session. Resolves when the server ended it, or when there was none (401);
 * rejects otherwise: the session may still be active and the caller must say so. */
export async function logout(): Promise<void> {
  try {
    await api("/api/v1/session", { method: "DELETE" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 401)) throw e;
  }
  forgetCsrf();
}

export const enc = encodeURIComponent;

// ---- Response types (the server's JSON) ----

export interface Project {
  name: string;
  policy: string;
  role: string | null;
}

export interface ProjectList {
  projects: Project[];
}

export interface RegressionPage {
  regressions: RegressionRow[];
  /** Opaque cursor (start and id) of the next page. */
  next: string | null;
}

export interface RegressionRow {
  ref: string;
  producer: string;
  suite: string;
  branch: string;
  state: string;
  started_at: string;
  finished_at: string | null;
  change_seq: number;
  planned: number;
}

export interface Header {
  planned: number;
  passed: number;
  failed: number;
  blocked: number;
  missing: number;
  running: number;
  cancelled: number;
  skipped: number;
  signatures: number;
  slots_with_signatures: number;
}

export interface SlotRow {
  slot_ref: string;
  test: string;
  required: boolean;
  state: string;
  detail?: string;
  note: string | null;
  deciding: number | null;
  attempts: number;
}

export interface RegressionRead {
  regression: {
    ref: string;
    producer: string;
    suite: string;
    branch: { repository: string; name: string };
    state: string;
    started_at: string;
  };
  header: Header;
  slots: SlotRow[];
}

export interface ComparisonRow {
  signature: string;
  /** `build` or `elaboration`: blocked slots without any signature. */
  group?: "build" | "elaboration";
  /** The project's signature number (for links); null if not numbered yet. */
  number: number | null;
  failed_slots: number;
  failing_attempts: number;
  diagnostics: number;
  baseline_slots: number;
  baseline: string;
  simulators: string[];
  preview: string[];
  /** Diagnostic ID and identity template of the signature (variable parts as placeholders). */
  diag_id?: string | null;
  identity_template?: string | null;
  triage_state?: string | null;
  /** Head revision of the branch's triage case (the base of an edit). */
  triage_revision?: number | null;
  owner?: string | null;
  latest_note?: string | null;
  bug_url?: string | null;
  exception?: { id: number; expires_at: string } | null;
  disposition?: "needs_decision" | "assigned" | "covered";
  next_action?: string;
}

export interface BulkTriageResult {
  cases: { signature: number; id: number; revision: number }[];
}

export interface FinishCard {
  merge_blockers: number;
  merge_blocker_kinds: Record<string, number>;
  merge_verdict: string;
  groups: number;
  needs_decision: number;
  assigned: number;
  covered: number;
  blocking_groups: number;
  missing_results: number;
  partly_covered_slots: boolean;
}

export interface Comparison {
  regression: RegressionRead["regression"];
  comparison: { header: Header; rows: ComparisonRow[] };
  finish: FinishCard;
  baseline: {
    ref: string | null;
    reason: string;
    /** Simulators each side's slots name; `baseline` null without a baseline. */
    simulators?: { current: string[]; baseline: string[] | null };
    /** Both sides name simulators and the sets differ. */
    simulators_differ?: boolean;
  };
}

export interface RepairList {
  regression: string;
  groups: {
    producer: string;
    slots: {
      slot: string;
      test: string;
      required: boolean;
      reason: string;
      action: string;
    }[];
  }[];
  text: string;
}

export interface ProofRow {
  slot: string;
  state: string | { state: string };
  attempt_seq: number | null;
  builds: string[];
  retry: boolean;
  expectation_met: boolean;
  exceptions: number[];
}

export interface ExceptionImpact {
  signature: number;
  scope: { branch: string; suite: string };
  expires_at: string;
  covers_slots: string[];
  stay_blocked_slots: string[];
  not_exceptable: boolean;
  simulators: string[];
  verdict_before: string;
  verdict_after: string;
}

export interface Changes {
  change_seq: number;
  changes: { seq: number; at: string | null; kind: string; object: string }[];
}

export interface BlockerKind {
  kind: string;
  reason?: string;
  by?: string;
}

export interface Blocker {
  kind: BlockerKind;
  slot: string | null;
  signatures: number[];
  exceptable: boolean;
  clearing_action: string;
}

export interface Readiness {
  verdict: string;
  digest: string;
  evaluated_at: string;
  valid_until: string | null;
  change_seq: number;
  regression: RegressionRead["regression"];
  blockers: Blocker[];
  warnings: string[];
  proof: ProofRow[];
  summary: {
    candidate: {
      repository: string | null;
      revision: string | null;
      source_digest: string;
    };
    suite: string;
    policy: string;
    counts: Record<string, number>;
    blockers: {
      kind: BlockerKind;
      slots: number;
      signatures: number[];
      owner: string;
      clearing_action: string;
      exceptable: boolean;
    }[];
    exceptions_used: { signature: number | null; expires_at: string }[];
  };
}

export interface TriageCase {
  id: number;
  branch: string;
  revision: number;
  state: string;
  owner: string | null;
  notes: string;
  bug_urls: string[];
  by: string;
  at: string;
}

export interface Head {
  id: number;
  revision: number;
}

export interface ExceptionRow {
  id: number;
  revision: number;
  branch: string;
  suite: string;
  reason: string;
  expires_at: string;
  by: string;
  /** Past `expires_at`: it covers nothing any more. */
  expired: boolean;
}

export interface SignatureDetail {
  number: number;
  diag_id: string;
  family_kind: string;
  identity_template: string;
  note: string;
  occurrences: {
    regression: string;
    /** The regression's producer (references are per producer). */
    producer: string;
    slot: string;
    attempt_seq: number;
    report_revision: number;
    count: string;
    severity: string;
    simulator: string;
    effective: string;
  }[];
  triage: TriageCase[];
  exceptions: ExceptionRow[];
}

export interface AttemptDetail {
  regression: string;
  slot: string;
  attempt_seq: number;
  attempt_ref: string;
  head_revision: number | null;
  revisions: {
    report_revision: number;
    outcome: string;
    effective: string;
    assessment: string;
    completion: string;
    termination: string;
    pipeline_status: string;
    contradiction: boolean;
    primary: string | null;
    simulator: string;
    received_at: string;
  }[];
  buckets: {
    idx: number;
    diag_id: string;
    observed_severity: string;
    effective_severity: string;
    provenance: string;
    fails_run: boolean;
    count: string;
    signature: number;
  }[];
  evidence: {
    completion: {
      profile: string;
      state: string;
      reasons: string[];
      sections_seen?: string[];
    };
    verdict_sources: { source: string; value: string }[];
    counters: { domain: string; key: string; value: string; role: string }[];
    excerpt: {
      segments: { kind: string; first_line: number; lines: string[] }[];
      truncated: boolean;
    };
  } | null;
  evidence_note: string | null;
}

// Health dashboard (`GET /api/v1/projects/{p}/health`, `.../health/history`).
export interface HealthCounts {
  required: number;
  passed: number;
  failed: number;
  of_which_timeout: number;
  blocked: number;
  missing: number;
  running: number;
  cancelled: number;
  skipped: number;
  optional: number;
}

export interface HealthSignatureCounts {
  all: number;
  new: number;
  unknown: number;
  persistent: number;
  no_longer_observed: number;
  config_not_run: number;
  undecided: number | null;
}

export interface HealthCost {
  last_end: string | null;
  last_end_partial: boolean;
  times_inconsistent: boolean;
  elapsed_s: number | null;
  longest_run_s: number | null;
  machine_s: number | null;
  machine_partial: boolean;
  cpu_s: number | null;
  cpu_slots: number;
  cpu_measured: number;
  cpu_scope: string | null;
}

export interface HealthStreamRow {
  stream?: { producer: string; suite: string; branch: string };
  home?: boolean;
  shared_from?: string | null;
  cadence_hours?: number | null;
  latest: { ref: string; state: string; started_at: string } | null;
  baseline: string | null;
  verdict: string | null;
  baseline_verdict: string | null;
  trend: string | null;
  worse: string[] | null;
  counts: HealthCounts;
  baseline_counts: HealthCounts | null;
  pass_rate: number | null;
  baseline_pass_rate: number | null;
  pass_rate_delta_pts: number | null;
  configs_added: number;
  configs_removed: number;
  signatures: HealthSignatureCounts;
  cost: HealthCost;
  baseline_cost: HealthCost | null;
  deltas: { elapsed_s: number | null; machine_s: number | null; cpu_s: number | null } | null;
  overdue: boolean;
  overdue_at: string | null;
}

export interface HealthGrowth {
  schema: string;
  area: string;
  days: { date: string; required_runs: number; tests: number; streams: number }[];
  streams: number;
  watermark: number;
  evaluated_at: string;
}

export interface NodeHealth {
  streams: number;
  /** Streams whose latest regression has no required test. */
  zero_test_streams?: number;
  counts: HealthCounts;
  compared_streams: number;
  compared_counts: HealthCounts;
  compared_baseline_counts: HealthCounts;
  pass_rate: number | null;
  pass_rate_delta_pts: number | null;
  worst_rate: number | null;
  signatures: HealthSignatureCounts;
  trend: "green" | "yellow" | "red" | null;
  readiness: "green" | "yellow" | "red" | null;
  grey: Record<string, number>;
  elapsed_s: number | null;
  elapsed_partial: boolean;
  cpu_s: number | null;
  cpu_slots: number;
  cpu_measured: number;
  cpu_complete: boolean;
  cpu_scope: string | null;
  cpu_delta_s: number | null;
}

export interface HealthPage {
  project: string;
  hierarchy_revision: number | null;
  watermark: number;
  evaluated_at: string;
  valid_until: string | null;
  node: { kind: string; path: string; title: string; breadcrumb: { path: string; title: string | null }[] };
  kpi: NodeHealth;
  own: HealthStreamRow[];
  children: { path: string; title: string; own_streams: number; children: number; health: NodeHealth }[];
}

export interface HealthHistory {
  stream: { producer: string; suite: string; branch: string };
  watermark: number;
  evaluated_at: string;
  valid_until: string | null;
  cadence_hours: number | null;
  home: string | null;
  regressions: HealthStreamRow[];
}

export interface HierarchyRead {
  revision: number | null;
  hierarchy: { nodes: { path: string; title?: string | null }[] } | null;
}
