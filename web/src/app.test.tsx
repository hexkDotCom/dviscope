import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClientProvider, onlineManager } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App, makeQueryClient } from "./App";
import { safeNext } from "./features/LoginPage";
import { publicSummary, safeUrl } from "./features/SignaturePage";
import { msUntilUtcMidnight } from "./features/HealthPages";
import { plainText } from "./components/CopyButton";

// All fixtures are synthetic.
type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;
let calls: { url: string; init: RequestInit }[] = [];

function json(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function mockFetch(h: Handler) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ url, init });
      return h(url, init);
    }),
  );
}

function renderAt(path: string) {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const header = {
  planned: 3,
  passed: 1,
  failed: 1,
  blocked: 0,
  missing: 1,
  running: 0,
  cancelled: 0,
  skipped: 0,
  signatures: 1,
  slots_with_signatures: 1,
};
const regHeader = {
  ref: "nightly-7",
  producer: "ci",
  suite: "smoke",
  branch: { repository: "core", name: "main" },
  state: "finished",
  started_at: "2026-11-01T02:00:00Z",
};

beforeEach(() => {
  calls = [];
  localStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("helpers", () => {
  it("follows only same-app paths after sign-in", () => {
    expect(safeNext("/p/x")).toBe("/p/x");
    expect(safeNext("//evil.example/")).toBe("/");
    expect(safeNext("/\\evil.example")).toBe("/");
    expect(safeNext("https://evil.example/")).toBe("/");
    expect(safeNext(null)).toBe("/");
  });
  it("links only http(s) bug URLs", () => {
    expect(safeUrl("https://bugs.example/1")).toBe("https://bugs.example/1");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("not a url")).toBeNull();
  });
});

describe("public-safe issue summary", () => {
  it("carries codes, counts and IDs, never the log-derived template or notes", () => {
    const text = publicSummary(
      {
        number: 12,
        diag_id: "UVM_ERROR",
        family_kind: "uvm",
        identity_template: "SECRET_LOG_TEXT at /home/x/run.log",
        note: "",
        occurrences: [
          {
            regression: "n7",
            producer: "ci",
            slot: "t1",
            attempt_seq: 1,
            report_revision: 1,
            count: "2",
            severity: "error",
            simulator: "sim-a",
            effective: "failed",
          },
          {
            regression: "n8",
            producer: "ci",
            slot: "t1",
            attempt_seq: 1,
            report_revision: 1,
            count: "1",
            severity: "error",
            simulator: "sim-b",
            effective: "failed",
          },
        ],
        triage: [
          {
            id: 1,
            branch: "core/main",
            revision: 3,
            state: "open",
            owner: "ann",
            notes: "PRIVATE NOTE",
            bug_urls: ["https://bugs.example/9"],
            by: "ann",
            at: "x",
          },
        ],
        exceptions: [],
      },
      "alpha",
      "core/main",
    );
    expect(text).toContain("signature #12");
    expect(text).toContain("UVM_ERROR");
    expect(text).toContain("2 slot(s) across 2 regression(s)");
    expect(text).toContain("triage open, revision 3");
    for (const bad of [
      "SECRET_LOG_TEXT",
      "/home/",
      "PRIVATE NOTE",
      "bugs.example",
      "ann",
    ]) {
      expect(text).not.toContain(bad);
    }
  });
});

describe("session", () => {
  it("redirects to sign-in on 401 and returns after login with the CSRF token kept", async () => {
    let signedIn = false;
    mockFetch((url, init) => {
      if (url === "/api/v1/session" && init.method === "POST") {
        signedIn = true;
        return new Response(null, {
          status: 204,
          headers: { "X-DVIScope-CSRF": "csrf-1" },
        });
      }
      if (url === "/api/v1/projects") {
        return signedIn
          ? json({
              projects: [
                { name: "alpha", policy: "first-attempt", role: "viewer" },
              ],
            })
          : json({ code: "E_UNAUTHENTICATED", message: "sign in" }, 401);
      }
      return json({ code: "E_NOT_FOUND", message: url }, 404);
    });
    renderAt("/");
    await screen.findByRole("heading", { name: "Sign in" });
    fireEvent.change(screen.getByLabelText("User"), {
      target: { value: "ann" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "pw" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText("alpha");
    expect(localStorage.getItem("dviscope.csrf")).toBe("csrf-1");
    const post = calls.find((c) => c.init.method === "POST");
    expect(post?.init.credentials).toBe("same-origin");
  });

  it("shows the server's error code on a failed login", async () => {
    mockFetch(() =>
      json(
        { code: "E_UNAUTHENTICATED", message: "wrong user or password" },
        401,
      ),
    );
    renderAt("/login");
    fireEvent.change(screen.getByLabelText("User"), {
      target: { value: "ann" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "bad" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "E_UNAUTHENTICATED",
    );
  });
});

describe("regression page", () => {
  it("shows counts, a numbered signature link with its branch, and slot links", async () => {
    mockFetch((url) => {
      if (url.includes("/repair-list")) {
        return json({
          regression: "nightly-7",
          groups: [
            {
              producer: "ci",
              slots: [
                {
                  slot: "t2:seed=1",
                  test: "t2",
                  required: true,
                  reason: "No report received",
                  action: "re-run the slot",
                },
              ],
            },
          ],
          text: "Collection repair list: regression nightly-7 (producer ci), 1 slot\n",
        });
      }
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        return json({
          regression: regHeader,
          comparison: {
            header,
            rows: [
              {
                signature: "sha256:" + "a".repeat(64),
                number: 12,
                failed_slots: 1,
                failing_attempts: 1,
                diagnostics: 2,
                baseline_slots: 0,
                baseline: "absent_from_baseline",
                simulators: ["sim-a"],
                preview: ["t1:seed=1"],
                triage_state: "open",
                owner: "Ana",
                latest_note: "scoreboard model gap",
                bug_url: null,
                exception: null,
                disposition: "assigned",
                next_action: "owner investigates",
              },
            ],
          },
          baseline: {
            ref: "nightly-6",
            reason: "selected",
            simulators: { current: ["sim-a"], baseline: ["sim-b"] },
            simulators_differ: true,
          },
          finish: {
            merge_blockers: 2,
            merge_blocker_kinds: { failed: 1, missing: 1 },
            merge_verdict: "fail",
            groups: 1,
            needs_decision: 0,
            assigned: 1,
            covered: 0,
            blocking_groups: 1,
            missing_results: 1,
            partly_covered_slots: false,
          },
        });
      }
      return json({
        regression: regHeader,
        header,
        slots: [
          {
            slot_ref: "t1:seed=1",
            test: "t1",
            required: true,
            state: "failed",
            detail: "functional",
            note: null,
            deciding: 1,
            attempts: 1,
          },
          {
            slot_ref: "t2:seed=1",
            test: "t2",
            required: true,
            state: "missing",
            note: null,
            deciding: null,
            attempts: 0,
          },
        ],
      });
    });
    renderAt("/p/alpha/r/nightly-7?producer=ci&baseline=nightly-6");
    await screen.findByText(/3 planned · 1 passed · 1 failed · 1 missing/);
    const sig = await screen.findByRole("link", { name: "#12" });
    expect(sig.getAttribute("href")).toBe(
      "/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke&regression=nightly-7&producer=ci",
    );
    expect((await screen.findByTestId("baseline")).textContent).toBe(
      "Baseline: nightly-6 (selected)",
    );
    expect(screen.getByTestId("baseline-simulators").textContent).toMatch(
      /baseline is on sim-b, this\s+regression on sim-a/,
    );
    const card = await screen.findByTestId("finish-card");
    expect(card.textContent).toContain("Triage accounted for: 1/1 groups");
    expect(card.textContent).toContain(
      "blocked by 2 blockers (1 failed, 1 missing)",
    );
    expect(screen.getByText("assigned")).toBeTruthy();
    expect(screen.getByText("scoreboard model gap")).toBeTruthy();
    await screen.findByText("No report received");
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Copy collection repair list" }),
    );
    await screen.findByText("Copied.");
    expect(writeText).toHaveBeenCalledWith(
      "Collection repair list: regression nightly-7 (producer ci), 1 slot\n",
    );
    expect(screen.getByText("new")).toBeTruthy();
    const slot = screen.getByRole("link", { name: "t1:seed=1" });
    expect(slot.getAttribute("href")).toBe(
      "/p/alpha/r/nightly-7/s/t1%3Aseed%3D1/a/1?producer=ci",
    );
    const cmp = calls.find((c) => c.url.includes("/comparison"));
    // The change feed is polled, never used to reorder rows.
    expect(
      calls.some((c) => c.url === "/api/v1/projects/alpha/changes?since=0"),
    ).toBe(true);
    expect(cmp?.url).toBe(
      "/api/v1/projects/alpha/regressions/nightly-7/comparison?producer=ci&baseline=nightly-6",
    );
  });

  it("triages the selected signatures in one request and explains a 412", async () => {
    localStorage.setItem("dviscope.csrf", "csrf-9");
    const row = (n: number, diag: string, rev: number | null, disposition: string) => ({
      signature: "sha256:" + String(n).repeat(64).slice(0, 64),
      number: n,
      failed_slots: 1,
      failing_attempts: 1,
      diagnostics: 1,
      baseline_slots: 0,
      baseline: "absent_from_baseline",
      simulators: ["sim-a"],
      preview: ["t1:seed=1"],
      diag_id: diag,
      identity_template: "regs.mem_<N>: read <SV:h>",
      triage_state: rev === null ? null : "open",
      triage_revision: rev,
      owner: rev === null ? null : "Bo",
      latest_note: null,
      bug_url: null,
      exception: null,
      disposition,
      next_action: "assign an owner",
    });
    let posts = 0;
    mockFetch((url, init) => {
      if (init.method === "POST") {
        posts += 1;
        return posts === 1
          ? json({ code: "E_PRECONDITION_FAILED", message: "signature #13: revision 3 by bob" }, 412)
          : json({ cases: [] });
      }
      if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        return json({
          regression: regHeader,
          comparison: {
            header,
            rows: [
              row(12, "uvm:MEM_STROBE", null, "needs_decision"),
              row(13, "uvm:MEM_STROBE", 2, "needs_decision"),
              row(14, "uvm:OTHER", 1, "assigned"),
              { ...row(15, "", null, "needs_decision"), number: null, group: "build", diag_id: null },
            ],
          },
          baseline: {
            ref: null,
            reason: "none",
            simulators: { current: ["sim-a"], baseline: null },
            simulators_differ: false,
          },
          finish: {
            merge_blockers: 1,
            merge_blocker_kinds: { failed: 1 },
            merge_verdict: "fail",
            groups: 4,
            needs_decision: 3,
            assigned: 1,
            covered: 0,
            blocking_groups: 4,
            missing_results: 0,
            partly_covered_slots: false,
          },
        });
      }
      return json({ regression: regHeader, header, slots: [] });
    });
    renderAt("/p/alpha/r/nightly-7");
    await screen.findByRole("link", { name: "#12" });
    await screen.findByTestId("baseline");
    // Simulators known on one side only: no mismatch warning.
    expect(screen.queryByTestId("baseline-simulators")).toBeNull();
    // The diagnostic is on the row: no click per signature to learn what it is.
    expect(screen.getAllByText("uvm:MEM_STROBE")).toHaveLength(2);
    expect(screen.queryByTestId("bulk-triage")).toBeNull();
    // A group row without a signature number is never selectable.
    expect(screen.queryByRole("checkbox", { name: "Select #15" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Select all needing decision" }));
    const form = await screen.findByTestId("bulk-triage");
    expect(form.textContent).toContain("Triage 2 selected signatures on core/main");
    expect(form.textContent).toContain("1 of them already has a triage case");
    expect((screen.getByRole("checkbox", { name: "Select #14" }) as HTMLInputElement).checked).toBe(false);
    fireEvent.change(screen.getByLabelText("Owner", { selector: "[data-testid=bulk-triage] input" }), {
      target: { value: " Ana " },
    });
    fireEvent.change(screen.getByLabelText("Notes", { selector: "[data-testid=bulk-triage] textarea" }), {
      target: { value: "strobe lanes" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save triage for 2" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Nothing was saved");
    const post = calls.find((c) => c.init.method === "POST");
    expect(post?.url).toBe("/api/v1/projects/alpha/triage?branch=core%2Fmain");
    expect((post?.init.headers as Record<string, string>)["X-DVIScope-CSRF"]).toBe("csrf-9");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      signatures: [{ number: 12 }, { number: 13, if_match: 2 }],
      state: "open",
      owner: "Ana",
      notes: "strobe lanes",
      bug_urls: [],
    });
    // Selecting by diagnostic adds every row with that ID; a success clears the selection.
    fireEvent.click(screen.getByRole("button", { name: "Clear selection (2)" }));
    expect(screen.queryByTestId("bulk-triage")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "select all uvm:OTHER" }));
    expect((await screen.findByTestId("bulk-triage")).textContent).toContain("Triage 1 selected signature on");
    fireEvent.click(screen.getByRole("button", { name: "Save triage for 1" }));
    await waitFor(() => expect(screen.queryByTestId("bulk-triage")).toBeNull());
    expect(JSON.parse(String(calls.filter((c) => c.init.method === "POST")[1]?.init.body)).signatures).toEqual([
      { number: 14, if_match: 1 },
    ]);
  });

  it("keeps the bulk draft when the selection changes, freezes it while saving, and caps it at 500", async () => {
    localStorage.setItem("dviscope.csrf", "csrf-9");
    const rows = Array.from({ length: 501 }, (_, i) => ({
      signature: "sha256:" + String(i).padStart(64, "0"),
      number: 100 + i,
      failed_slots: 1,
      failing_attempts: 1,
      diagnostics: 1,
      baseline_slots: 0,
      baseline: "absent_from_baseline",
      simulators: ["sim-a"],
      preview: ["t1:seed=1"],
      diag_id: i < 2 ? "uvm:FEW" : "uvm:MANY",
      identity_template: "x",
      triage_state: null,
      triage_revision: null,
      owner: null,
      latest_note: null,
      bug_url: null,
      exception: null,
      disposition: "needs_decision",
      next_action: "assign an owner",
    }));
    let release: (r: Response) => void = () => {};
    mockFetch((url, init) => {
      if (init.method === "POST") return new Promise<Response>((r) => (release = r));
      if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        return json({
          regression: regHeader,
          comparison: { header, rows },
          baseline: {
            ref: null,
            reason: "none",
            simulators: { current: ["sim-a"], baseline: null },
            simulators_differ: false,
          },
          finish: {
            merge_blockers: 0, merge_blocker_kinds: {}, merge_verdict: "fail", groups: 501,
            needs_decision: 501, assigned: 0, covered: 0, blocking_groups: 501, missing_results: 0,
            partly_covered_slots: false,
          },
        });
      }
      return json({ regression: regHeader, header, slots: [] });
    });
    renderAt("/p/alpha/r/nightly-7");
    await screen.findByRole("link", { name: "#100" });
    fireEvent.click(screen.getByRole("checkbox", { name: "Select #100" }));
    const owner = () => screen.getByLabelText("Owner", { selector: "[data-testid=bulk-triage] input" }) as HTMLInputElement;
    fireEvent.change(owner(), { target: { value: "Ana" } });
    // Adding a signature keeps what was typed.
    fireEvent.click(screen.getByRole("checkbox", { name: "Select #101" }));
    expect(screen.getByTestId("bulk-triage").textContent).toContain("Triage 2 selected signatures");
    expect(owner().value).toBe("Ana");
    // More than 500: explained, not sent.
    fireEvent.click(screen.getByRole("button", { name: "Select all needing decision" }));
    expect(screen.getByTestId("bulk-triage").textContent).toContain("At most 500 signatures");
    expect((screen.getByRole("button", { name: "Save triage for 501" }) as HTMLButtonElement).disabled).toBe(true);
    expect(owner().value).toBe("Ana");
    // Through an empty selection too: the draft is the page's, until it is saved.
    fireEvent.click(screen.getByRole("button", { name: "Clear selection (501)" }));
    expect(screen.queryByTestId("bulk-triage")).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: "select all uvm:FEW" })[0]!);
    expect(owner().value).toBe("Ana");
    // While saving, the selection cannot change.
    fireEvent.click(screen.getByRole("button", { name: "Save triage for 2" }));
    await waitFor(() =>
      expect((screen.getByRole("checkbox", { name: "Select #102" }) as HTMLInputElement).disabled).toBe(true),
    );
    expect((screen.getByRole("button", { name: "Select all needing decision" }) as HTMLButtonElement).disabled).toBe(true);
    // Nor the draft: what is being sent stays what is shown.
    expect(owner().disabled).toBe(true);
    expect((screen.getByLabelText("Notes", { selector: "[data-testid=bulk-triage] textarea" }) as HTMLTextAreaElement).disabled).toBe(true);
    expect((screen.getByLabelText("Bug links (one per line)", { selector: "[data-testid=bulk-triage] textarea" }) as HTMLTextAreaElement).disabled).toBe(true);
    expect((screen.getByLabelText("State", { selector: "[data-testid=bulk-triage] select" }) as HTMLSelectElement).disabled).toBe(true);
    // Nor the baseline: the comparison is not reloaded under a pending save.
    expect((screen.getByRole("button", { name: "Compare" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByPlaceholderText("regression reference") as HTMLInputElement).disabled).toBe(true);
    expect(calls.filter((c) => c.init.method === "POST")).toHaveLength(1);
    expect(JSON.parse(String(calls.find((c) => c.init.method === "POST")?.init.body)).owner).toBe("Ana");
    release(json({ cases: [] }));
    await waitFor(() => expect(screen.queryByTestId("bulk-triage")).toBeNull());
    await waitFor(() =>
      expect((screen.getByRole("checkbox", { name: "Select #102" }) as HTMLInputElement).disabled).toBe(false),
    );
    // Saved: the next selection starts from an empty draft.
    fireEvent.click(screen.getByRole("checkbox", { name: "Select #102" }));
    expect(owner().value).toBe("");
  }, 60_000);
});

describe("readiness page", () => {
  it("shows the verdict, grouped blockers with owners and the unbound warning", async () => {
    mockFetch(() =>
      json({
        verdict: "fail",
        digest: "sha256:" + "b".repeat(64),
        evaluated_at: "2026-11-02T08:00:00Z",
        valid_until: null,
        change_seq: 4,
        regression: regHeader,
        blockers: [
          {
            kind: { kind: "failed", reason: "functional" },
            slot: "t1:seed=1",
            signatures: [12],
            exceptable: true,
            clearing_action: "fix or except",
          },
        ],
        exceptions_used: [],
        warnings: ["candidate not bound: no expected source digest given"],
        proof: [
          {
            slot: "t0:seed=1",
            state: "passed",
            attempt_seq: 2,
            builds: ["b1"],
            retry: true,
            expectation_met: false,
            exceptions: [],
          },
        ],
        summary: {
          candidate: {
            repository: "core",
            revision: "abc",
            source_digest: "sha256:c",
          },
          suite: "smoke",
          policy: "first-attempt",
          counts: { planned: 3, passed: 1, failed: 1 },
          blockers: [
            {
              kind: { kind: "failed", reason: "functional" },
              slots: 1,
              signatures: [12],
              owner: "Unassigned",
              clearing_action: "fix or except",
              exceptable: true,
            },
          ],
          exceptions_used: [],
        },
      }),
    );
    renderAt("/p/alpha/r/nightly-7/readiness?producer=ci");
    expect((await screen.findByText("Fail")).className).toContain(
      "verdict-fail",
    );
    expect(screen.getByText(/candidate not bound/)).toBeTruthy();
    expect(screen.getAllByText("failed (functional)").length).toBe(2);
    expect(screen.getByText("Unassigned")).toBeTruthy();
    expect(screen.getByText("accepted retry")).toBeTruthy();
    expect(screen.getByText("#2")).toBeTruthy();
    expect(screen.getByText("b1")).toBeTruthy();
    expect(calls[0]?.url).toBe(
      "/api/v1/projects/alpha/regressions/nightly-7/readiness?producer=ci",
    );
  });
});

describe("signature page", () => {
  const detail = (revision: number, owner: string) => ({
    number: 12,
    diag_id: "UVM_ERROR",
    family_kind: "uvm",
    identity_template: "scoreboard mismatch <n>",
    note: "Same diagnostic pattern; common root cause not established.",
    occurrences: [],
    triage: [
      {
        id: 1,
        branch: "core/main",
        revision,
        state: "open",
        owner,
        notes: "",
        bug_urls: ["javascript:alert(1)"],
        by: "ann",
        at: "2026-11-02T08:00:00Z",
      },
    ],
    exceptions: [],
  });

  it("sends CSRF and If-Match with a triage edit and explains a 412 conflict", async () => {
    localStorage.setItem("dviscope.csrf", "csrf-9");
    let rev = 3;
    mockFetch((url, init) => {
      if (init.method === "PUT") {
        rev = 4;
        return json(
          { code: "E_PRECONDITION_FAILED", message: "revision changed" },
          412,
        );
      }
      return json(detail(rev, rev === 3 ? "ann" : "bob"));
    });
    renderAt("/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke");
    await screen.findByText("Triage on core/main");
    // An unsafe bug URL is shown as text, never as a link.
    expect(
      screen.getByText("javascript:alert(1)", { selector: "td span" }),
    ).toBeTruthy();
    expect(
      screen.queryByRole("link", { name: "javascript:alert(1)" }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "Someone else changed",
    );
    const put = calls.find((c) => c.init.method === "PUT");
    const h = put?.init.headers as Record<string, string>;
    expect(h["X-DVIScope-CSRF"]).toBe("csrf-9");
    expect(h["If-Match"]).toBe('"3"');
    expect(put?.url).toBe(
      "/api/v1/projects/alpha/triage/12?branch=core%2Fmain",
    );
    expect(JSON.parse(String(put?.init.body))).toEqual({
      state: "open",
      owner: "ann",
      notes: "",
      bug_urls: ["javascript:alert(1)"],
    });
  });

  it("creates an exception with an end-of-day UTC expiry", async () => {
    localStorage.setItem("dviscope.csrf", "csrf-9");
    mockFetch((url, init) => {
      if (init.method === "POST") return json({ id: 5, revision: 1 }, 201);
      if (url.includes("/readiness/preview")) {
        return json({
          signature: 12,
          scope: { branch: "core/main", suite: "smoke" },
          expires_at: "2026-12-01T23:59:59Z",
          covers_slots: ["t1:seed=1", "t1:seed=2", "t1:seed=3"],
          stay_blocked_slots: ["t4:seed=1", "t5:seed=1"],
          not_exceptable: false,
          simulators: ["sim-a"],
          verdict_before: "fail",
          verdict_after: "fail",
        });
      }
      return json(detail(1, "ann"));
    });
    renderAt(
      "/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke&regression=nightly-7&producer=ci",
    );
    await screen.findByText(/New exception for smoke on core\/main/);
    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "known, tracked" },
    });
    fireEvent.change(screen.getByLabelText("Expires (end of day, UTC)"), {
      target: { value: "2026-12-01" },
    });
    const impact = await screen.findByTestId("impact");
    expect(impact.textContent).toContain(
      "Would cover 3 failing slots; 2 slots stay blocked",
    );
    expect(impact.textContent).toContain(
      "scope: branch core/main / suite smoke",
    );
    const pv = calls.find((c) => c.url.includes("/readiness/preview"));
    expect(pv?.url).toBe(
      "/api/v1/projects/alpha/regressions/nightly-7/readiness/preview?signature=12" +
        "&expires_at=2026-12-01T23%3A59%3A59Z&producer=ci",
    );
    expect(pv?.init.method ?? "GET").toBe("GET");
    fireEvent.click(screen.getByRole("button", { name: "Create exception" }));
    await waitFor(() =>
      expect(calls.some((c) => c.init.method === "POST")).toBe(true),
    );
    const post = calls.find((c) => c.init.method === "POST");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      signature: 12,
      branch: "core/main",
      suite: "smoke",
      reason: "known, tracked",
      expires_at: "2026-12-01T23:59:59Z",
    });
  });
});

describe("admin page", () => {
  it("shows the assurance profile and token metadata read-only", async () => {
    mockFetch((url) =>
      url.endsWith("/admin/retention")
        ? json({
            project: "alpha",
            as_of: "2026-11-09T00:00:00Z",
            policy_days: {
              pass_payload: 30,
              pass_facts: 90,
              fail_payload: 90,
              fail_facts: 730,
              receipts: 120,
            },
            report: {
              payloads: 4,
              regressions: 1,
              builds: 0,
              receipts: 2,
              dry_run: true,
              items: [
                {
                  project: "alpha",
                  regression: "nightly-old",
                  cohort: "all_pass",
                  ended_at: "2026-07-01T00:00:00Z",
                  action: "remove",
                  payloads: 0,
                },
                {
                  project: "alpha",
                  regression: "nightly-<b>x</b>",
                  cohort: "with_failures",
                  ended_at: "2026-08-01T00:00:00Z",
                  action: "expire_payloads",
                  payloads: 4,
                },
              ],
              items_truncated: false,
              candidates: [
                {
                  project: "alpha",
                  branch: "rtl/main",
                  test: "uart_tx",
                  regression: "nightly-old",
                },
              ],
              publications: [
                {
                  project: "alpha",
                  digest: "sha256:pub1",
                  regression: "nightly-old",
                  target: "rtl@abc",
                },
              ],
              impact_truncated: false,
            },
          })
        : url.endsWith("/rules")
          ? json({
              active_pipeline: "sha256:new",
              default_packs: true,
              packs: ["proj.yaml"],
              sample: { digest: "sha256:smp", cases: 12, bytes: 4096 },
              activations: [
                {
                  id: "1",
                  old_pipeline: "sha256:old",
                  new_pipeline: "sha256:new",
                  sample: "sha256:smp",
                  actor: "1",
                  activated_at: "2026-11-08T10:00:00Z",
                  cases: 12,
                },
              ],
            })
          : json({
              project: "alpha",
              policy: "strict",
              members: [{ username: "ada", role: "admin", disabled: false }],
              tokens: [
                {
                  id: 3,
                  producer: "ci",
                  label: "nightly",
                  scopes: ["ingest:submit"],
                  created_at: "2026-11-01T00:00:00Z",
                  expires_at: "2027-11-01T00:00:00Z",
                  revoked_at: null,
                  quarantined_since: "2026-11-05T00:00:00Z",
                  state: "quarantined",
                },
              ],
              producers: [
                {
                  name: "ci",
                  retired_at: null,
                  retired_reason: null,
                  assurance: [
                    "Counting available (sealed expected sets)",
                    "Build provenance missing (no build attempts)",
                  ],
                },
              ],
              pipelines: [],
            }),
    );
    renderAt("/p/alpha/admin");
    await screen.findByText(/Build provenance missing/);
    await screen.findByText(/Activation sample: 12 cases/);
    expect(screen.getByText(/shipped packs, proj.yaml/)).toBeTruthy();
    expect(screen.getByText(/quarantined since 2026-11-05/)).toBeTruthy();
    expect(screen.getByText(/no result is eligible yet/)).toBeTruthy();
    expect(screen.queryAllByRole("button").map((b) => b.textContent)).toEqual([
      "Sign out",
    ]);
    expect(calls[0]?.url).toBe("/api/v1/projects/alpha/admin");
    await screen.findByText(
      /1 regression\(s\) removed, 4 payload\(s\) expired/,
    );
    expect(screen.getByText("nightly-old")).toBeTruthy();
    // Hostile names render as text.
    expect(screen.getByText("nightly-<b>x</b>")).toBeTruthy();
    expect(screen.getByText("4 payload(s) expired")).toBeTruthy();
    expect(screen.getByText(/Payloads expire after 30 days/)).toBeTruthy();
    expect(
      screen.getByText(
        /rtl\/main \/ uart_tx: newest evidence nightly-old expires/,
      ),
    ).toBeTruthy();
    expect(screen.getByText("sha256:pub1")).toBeTruthy();
  });
});

describe("receipt page", () => {
  it("shows the published verdict next to the current evaluation", async () => {
    const summary = (verdict: string, at: string) => ({
      verdict,
      evaluated_at: at,
      valid_until: null,
      digest: "x",
      regression: "nightly-7",
      suite: "smoke",
      counts: { planned: 3, passed: 2, failed: 1 },
      blockers: [],
      exceptions_used: [{ signature: 12, expires_at: "2026-11-28T23:59:59Z" }],
    });
    mockFetch(() =>
      json({
        receipt: {
          digest: "sha256:aaa",
          summary: summary("accepted_with_exceptions", "2026-11-08T07:05:00Z"),
          regression: "nightly-7",
          target: {
            repository: "o/r",
            commit: "a".repeat(40),
            context: "dviscope/merge",
          },
          status: {
            state: "success",
            description: "Accepted with exceptions as of ...",
          },
          published_at: "2026-11-08T07:05:00Z",
          valid_until: "2026-11-28T23:59:59Z",
          monitor_until: "2026-11-28T23:59:59Z",
          posted_at: "2026-11-08T07:06:00Z",
          last_refresh_at: "2026-11-08T08:06:00Z",
          retired_at: null,
          retired_reason: null,
        },
        current: {
          digest: "sha256:bbb",
          summary: summary("fail", "2026-11-29T08:20:00Z"),
        },
      }),
    );
    renderAt("/p/alpha/receipts/sha256%3Aaaa");
    const published = await screen.findByTestId("published");
    expect(published.textContent).toContain(
      "Published at 2026-11-08T07:05:00Z",
    );
    expect(published.textContent).toContain("Accepted with exceptions");
    const current = screen.getByTestId("current");
    expect(current.textContent).toContain("Fail");
    expect(current.className).toContain("warning");
    expect(screen.getByText("2026-11-08T08:06:00Z")).toBeTruthy();
    expect(calls[0]?.url).toBe(
      "/api/v1/projects/alpha/readiness/receipts/sha256%3Aaaa",
    );
  });
});

describe("feature page", () => {
  it("shows all six states, seeds per simulator and attests exactly what was shown", async () => {
    localStorage.setItem("dviscope.csrf", "csrf-1");
    const item = (id: string, state: string, extra: object = {}) => ({
      item_id: id,
      title: `${id} works`,
      revision: 2,
      owner: "Ana",
      applicable: true,
      state,
      reasons: state === "satisfied" ? [] : [`${id}: because`],
      requires: { tests: ["uart_*"] },
      pairs: [],
      seeds_by_simulator: [],
      next_action: "x",
      ...extra,
    });
    mockFetch((url, init) => {
      if (init.method === "POST") return json({ id: 9 }, 201);
      return json({
        checklist: {
          checklist_id: "uart-fs",
          version: "3",
          title: "UART",
          feature: "uart",
          owner: "Ana",
        },
        branch: "rtl/main",
        evaluated_at: "2026-11-08T08:00:00Z",
        valid_until: null,
        digest: "sha256:d",
        ready: false,
        result: "not ready",
        items: [
          item("a", "satisfied", {
            seeds_by_simulator: [
              { simulator: "questa", achieved: 3, required: 5 },
            ],
          }),
          item("b", "failed"),
          item("c", "missing"),
          item("d", "insufficient"),
          item("e", "outdated"),
          item("f", "unreviewed", {
            evidence: [{ name: "coverage", digest: "sha256:ev" }],
            evidence_digest: "sha256:combined",
            attestation: null,
          }),
        ],
      });
    });
    renderAt("/p/alpha/checklists/uart-fs?branch=rtl%2Fmain");
    await screen.findByText("Not ready");
    for (const s of [
      "satisfied",
      "failed",
      "missing",
      "insufficient",
      "outdated",
      "unreviewed",
    ]) {
      expect(screen.getAllByText(s).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("questa 3/5")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Review evidence…" }));
    const box = await screen.findByTestId("attest");
    expect(box.textContent).toContain("revision 2 of version 3");
    expect(box.textContent).toContain("sha256:combined");
    fireEvent.click(
      screen.getByRole("button", { name: "Attest exactly this" }),
    );
    await waitFor(() =>
      expect(calls.some((c) => c.init.method === "POST")).toBe(true),
    );
    const post = calls.find((c) => c.init.method === "POST");
    expect(post?.url).toBe(
      "/api/v1/projects/alpha/checklists/uart-fs/attestations",
    );
    expect(JSON.parse(String(post?.init.body))).toEqual({
      version: "3",
      item_id: "f",
      item_revision: 2,
      evidence_digest: "sha256:combined",
    });
    expect(calls[0]?.url).toBe(
      "/api/v1/projects/alpha/checklists/uart-fs/evaluation?branch=rtl%2Fmain",
    );
  });
});

describe("exception replacement", () => {
  it("sends the live exception's revision as If-Match", async () => {
    localStorage.setItem("dviscope.csrf", "csrf-9");
    mockFetch((url, init) => {
      if (init.method === "POST") return json({ id: 6, revision: 4 }, 201);
      if (url.includes("/readiness/preview"))
        return json({ code: "E_INVALID", message: "x" }, 400);
      return json({
        number: 12,
        diag_id: "UVM_ERROR",
        family_kind: "uvm",
        identity_template: "t",
        note: "",
        occurrences: [],
        triage: [],
        exceptions: [
          {
            id: 5,
            revision: 3,
            branch: "core/main",
            suite: "smoke",
            reason: "r",
            expires_at: "2026-11-20T00:00:00Z",
            by: "ada",
            expired: false,
          },
        ],
      });
    });
    renderAt("/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke");
    await screen.findByText(/Replace exception \(revision 3\)/);
    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "extend" },
    });
    fireEvent.change(screen.getByLabelText("Expires (end of day, UTC)"), {
      target: { value: "2026-12-01" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create exception" }));
    await waitFor(() =>
      expect(calls.some((c) => c.init.method === "POST")).toBe(true),
    );
    const post = calls.find((c) => c.init.method === "POST");
    expect((post?.init.headers as Record<string, string>)["If-Match"]).toBe(
      '"3"',
    );
  });
});

describe("expired exceptions", () => {
  it("are shown as expired, not as cover", async () => {
    mockFetch(() =>
      json({
        number: 3,
        diag_id: "uvm:WATCHDOG",
        family_kind: "uvm-app",
        identity_template: "t",
        note: "",
        occurrences: [],
        triage: [],
        exceptions: [
          {
            id: 1,
            revision: 1,
            branch: "demo-rtl/main",
            suite: "nightly",
            reason: "watchdog too tight",
            expires_at: "2026-11-02T00:00:00Z",
            by: "demo",
            expired: true,
          },
        ],
      }),
    );
    renderAt("/p/demo/signatures/3");
    await screen.findByText(/watchdog too tight/);
    expect(screen.getByText(/expired: covers nothing/)).toBeTruthy();
  });
});

describe("stale evaluations", () => {
  it("marks a readiness result stale after a change or at valid_until", async () => {
    let changes: unknown[] = [];
    const ready = (validUntil: string | null) => ({
      verdict: "accepted_with_exceptions",
      digest: "sha256:d",
      evaluated_at: "2026-11-08T08:00:00Z",
      valid_until: validUntil,
      change_seq: 4,
      regression: regHeader,
      blockers: [],
      exceptions_used: [],
      warnings: [],
      proof: [],
      summary: {
        candidate: {
          repository: "core",
          revision: "abc",
          source_digest: "sha256:c",
        },
        suite: "smoke",
        policy: "strict",
        counts: { planned: 1, passed: 1 },
        blockers: [],
        exceptions_used: [],
      },
    });
    mockFetch((url) => {
      if (url.includes("/changes?since=4"))
        return json({ change_seq: 4 + changes.length, changes });
      return json(ready(null));
    });
    renderAt("/p/alpha/r/nightly-7/readiness");
    await screen.findByText("Accepted with exceptions");
    expect(screen.queryByText(/Stale:/)).toBeNull();
    // A later change: the next poll (forced here by a new render) marks it stale.
    changes = [{ seq: 5, at: null, kind: "exception", object: "x" }];
    cleanup();
    renderAt("/p/alpha/r/nightly-7/readiness");
    expect((await screen.findByRole("alert")).textContent).toContain(
      "1 change(s) since it was evaluated",
    );
    // Already past valid_until: stale at once.
    cleanup();
    changes = [];
    mockFetch((url) => {
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      return json(ready("2020-01-01T00:00:00Z"));
    });
    renderAt("/p/alpha/r/nightly-7/readiness");
    expect((await screen.findByRole("alert")).textContent).toContain(
      "validity ended",
    );
  });
});

describe("freshness checks", () => {
  it("says freshness is unknown when the change feed fails", async () => {
    mockFetch((url) => {
      if (url.includes("/changes"))
        return json({ code: "E_INTERNAL", message: "down" }, 500);
      return json({
        verdict: "pass",
        digest: "sha256:d",
        evaluated_at: "2026-11-08T08:00:00Z",
        valid_until: null,
        change_seq: 4,
        regression: regHeader,
        blockers: [],
        exceptions_used: [],
        warnings: [],
        proof: [],
        summary: {
          candidate: {
            repository: "core",
            revision: "abc",
            source_digest: "sha256:c",
          },
          suite: "smoke",
          policy: "strict",
          counts: {},
          blockers: [],
          exceptions_used: [],
        },
      });
    });
    renderAt("/p/alpha/r/nightly-7/readiness");
    expect(
      (await screen.findByRole("alert", {}, { timeout: 4000 })).textContent,
    ).toContain("freshness cannot be checked");
  });
});

describe("long validity", () => {
  it("does not expire when the capped timer fires early", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const in90days = new Date(Date.now() + 90 * 86_400_000).toISOString();
      mockFetch((url) => {
        if (url.includes("/changes"))
          return json({ change_seq: 4, changes: [] });
        return json({
          verdict: "accepted_with_exceptions",
          digest: "sha256:d",
          evaluated_at: "2026-11-08T08:00:00Z",
          valid_until: in90days,
          change_seq: 4,
          regression: regHeader,
          blockers: [],
          exceptions_used: [],
          warnings: [],
          proof: [],
          summary: {
            candidate: {
              repository: "core",
              revision: "abc",
              source_digest: "sha256:c",
            },
            suite: "smoke",
            policy: "strict",
            counts: {},
            blockers: [],
            exceptions_used: [],
          },
        });
      });
      renderAt("/p/alpha/r/nightly-7/readiness");
      await screen.findByText("Accepted with exceptions");
      // 30 days later (past the capped timer): still valid.
      await vi.advanceTimersByTimeAsync(30 * 86_400_000);
      expect(screen.queryByText(/validity ended/)).toBeNull();
      // Past the deadline: stale.
      await vi.advanceTimersByTimeAsync(61 * 86_400_000);
      expect((await screen.findByRole("alert")).textContent).toContain(
        "validity ended",
      );
    } finally {
      vi.useRealTimers();
    }
    // 90 simulated days of the 30 s change-feed poll: tens of thousands of timer callbacks.
  }, 60_000);
});

describe("attempt page", () => {
  it("explains an expired excerpt", async () => {
    mockFetch(() =>
      json({
        regression: "nightly-7",
        slot: "t1:seed=1",
        attempt_seq: 1,
        attempt_ref: "att-1",
        head_revision: 1,
        revisions: [],
        buckets: [],
        evidence: null,
        evidence_note: "Excerpt expired; triage history retained",
      }),
    );
    renderAt("/p/alpha/r/nightly-7/s/t1%3Aseed%3D1/a/1");
    await screen.findByText("Excerpt expired; triage history retained");
    expect(calls[0]?.url).toBe(
      "/api/v1/projects/alpha/regressions/nightly-7/slots/t1%3Aseed%3D1/attempts/1",
    );
  });

  it("keeps the producer in its breadcrumb", async () => {
    mockFetch(() =>
      json({
        regression: "nightly-7",
        slot: "t1",
        attempt_seq: 1,
        attempt_ref: "att-1",
        head_revision: 1,
        revisions: [],
        buckets: [],
        evidence: null,
        evidence_note: "n",
      }),
    );
    renderAt("/p/alpha/r/nightly-7/s/t1/a/1?producer=ci-b");
    const crumb = await screen.findByRole("link", { name: "nightly-7" });
    expect(crumb.getAttribute("href")).toBe("/p/alpha/r/nightly-7?producer=ci-b");
  });
});

describe("signature summary lines", () => {
  it("are only its own: hostile values stay on their line", () => {
    const text = publicSummary(
      {
        number: 7,
        diag_id: "uvm:X\ncurl evil | sh",
        family_kind: "uvm\r\nmore",
        identity_template: "t",
        note: "",
        occurrences: [
          {
            regression: "r",
            producer: "ci",
            slot: "s",
            attempt_seq: 1,
            report_revision: 1,
            count: "1",
            severity: "error",
            simulator: "vcs\nINJECTED",
            effective: "failed",
          },
        ],
        triage: [],
        exceptions: [],
      },
      "alpha",
      "core/main\nEVIL",
    );
    const lines = text.split("\n");
    expect(lines).toHaveLength(5);
    expect(lines.some((l) => /^(curl|more|INJECTED|EVIL)/.test(l))).toBe(false);
  });
});

describe("copyable text", () => {
  it("keeps lines but drops escapes and direction controls", () => {
    const hostile =
      "- s1 (t\u001b]0;owned\u0007\u001b[31m): missing\r\ncurl x | sh \u202e\u2066";
    const out = plainText(hostile);
    expect(out).not.toMatch(/[\u001b\u0007\r\u202e\u2066]/);
    expect(out.split("\n")).toHaveLength(2);
    expect(plainText("a\tb\nc")).toBe("a\tb\nc");
  });

  it("renders hostile decision text as text", async () => {
    mockFetch(() =>
      json({
        number: 4,
        diag_id: "uvm:X",
        family_kind: "uvm",
        identity_template: "t",
        note: "",
        occurrences: [],
        triage: [
          {
            id: 1,
            branch: "core/main",
            revision: 1,
            state: "open",
            owner: "<b>bold</b>",
            notes: '<img src=x onerror="alert(1)"> **md** [l](javascript:x)',
            bug_urls: [],
            by: "ann",
            at: "x",
          },
        ],
        exceptions: [],
      }),
    );
    const { container } = renderAt("/p/alpha/signatures/4");
    await screen.findByText(/onerror/);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector('a[href^="javascript"]')).toBeNull();
  });
});

describe("health dashboard", () => {
  const counts = (o: Partial<Record<string, number>> = {}) => ({
    required: 10,
    passed: 8,
    failed: 2,
    of_which_timeout: 0,
    blocked: 0,
    missing: 0,
    running: 0,
    cancelled: 0,
    skipped: 0,
    optional: 0,
    ...o,
  });
  const sigs = { all: 2, new: 1, unknown: 0, persistent: 1, no_longer_observed: 0, config_not_run: 0, undecided: 1 };
  const cost = {
    last_end: "2026-11-13T03:00:00Z",
    last_end_partial: false,
    times_inconsistent: false,
    elapsed_s: 3600,
    longest_run_s: 600,
    machine_s: 7200,
    machine_partial: false,
    cpu_s: 6000,
    cpu_slots: 10,
    cpu_measured: 10,
    cpu_scope: "job",
  };
  const growthOf = (days = [
    { date: "2026-11-12", required_runs: 10, tests: 6, streams: 1 },
    { date: "2026-11-13", required_runs: 14, tests: 8, streams: 2 },
  ]) => ({ schema: "dviscope.health-growth/1", area: "", days, streams: 2, watermark: 5, evaluated_at: "x" });
  const node = (o: Record<string, unknown> = {}) => ({
    streams: 2,
    counts: counts(),
    compared_streams: 1,
    compared_counts: counts(),
    compared_baseline_counts: counts({ failed: 1, passed: 9 }),
    pass_rate: 80,
    pass_rate_delta_pts: -10,
    worst_rate: 80,
    signatures: sigs,
    trend: "red",
    readiness: "red",
    grey: {},
    elapsed_s: 3600,
    elapsed_partial: false,
    cpu_s: 6000,
    cpu_slots: 10,
    cpu_measured: 10,
    cpu_complete: true,
    cpu_scope: "job",
    cpu_delta_s: 60,
    ...o,
  });
  const stream = (o: Record<string, unknown> = {}) => ({
    stream: { producer: "ci", suite: "dma", branch: "core/main" },
    home: true,
    shared_from: null,
    cadence_hours: 24,
    latest: { ref: "dma-7", state: "finished", started_at: "2026-11-13T02:00:00Z" },
    baseline: "dma-6",
    verdict: "accepted_with_exceptions",
    baseline_verdict: "pass",
    trend: "yellow",
    worse: [],
    counts: counts(),
    baseline_counts: counts(),
    pass_rate: 80,
    baseline_pass_rate: 80,
    pass_rate_delta_pts: 0,
    configs_added: 0,
    configs_removed: 0,
    signatures: sigs,
    cost,
    baseline_cost: cost,
    deltas: { elapsed_s: 0, machine_s: 0, cpu_s: null },
    overdue: false,
    overdue_at: null,
    ...o,
  });
  const page = (o: Record<string, unknown> = {}) => ({
    project: "alpha",
    hierarchy_revision: 2,
    watermark: 5,
    evaluated_at: "2026-11-13T08:00:00Z",
    valid_until: null,
    node: { kind: "project", path: "", title: "alpha", breadcrumb: [] },
    kpi: node(),
    own: [],
    children: [],
    ...o,
  });

  it("shows the project level: KPIs and one row per area, badges with text", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      return json(
        page({
          children: [
            { path: "soc", title: "Demo SoC", own_streams: 0, children: 2, health: node() },
            {
              path: "~unassigned",
              title: "Unassigned",
              own_streams: 1,
              children: 0,
              health: node({ trend: null, readiness: null, grey: { no_data: 1 } }),
            },
          ],
        }),
      );
    });
    renderAt("/p/alpha/health");
    await screen.findByText("Health of alpha");
    expect(screen.getByRole("link", { name: "Demo SoC" }).getAttribute("href")).toBe("/p/alpha/health/soc");
    // Colour is never alone: the badges say their state.
    expect(screen.getAllByText("worse").length).toBeGreaterThan(0);
    expect(screen.getAllByText("1 no data").length).toBe(2);
    expect(screen.getByText("Overdue regressions")).toBeTruthy();
    expect(screen.getAllByText("-10 pts vs last").length).toBeGreaterThan(0);
    expect(calls[0]?.url).toBe("/api/v1/projects/alpha/health");
  });

  it("shows a subsystem with its own regressions, a shared block and children", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      return json(
        page({
          node: { kind: "node", path: "soc/cpu_ss", title: "cpu_ss", breadcrumb: [{ path: "soc", title: "Demo SoC" }] },
          own: [stream({ shared_from: "soc/io_ss/dma", home: false })],
          children: [{ path: "soc/cpu_ss/core", title: "core", own_streams: 2, children: 0, health: node() }],
        }),
      );
    });
    renderAt("/p/alpha/health/soc/cpu_ss");
    await screen.findByText("Regressions of cpu_ss");
    expect(calls[0]?.url).toBe("/api/v1/projects/alpha/health?area=soc%2Fcpu_ss");
    expect(screen.getByText(/shared from soc\/io_ss\/dma/)).toBeTruthy();
    // An exception never reads as green.
    const v = screen.getByText("accepted with exceptions");
    expect(v.className).toContain("hb-yellow");
    expect(screen.getByRole("link", { name: "dma" }).getAttribute("href")).toBe(
      "/p/alpha/health-stream?producer=ci&suite=dma&branch=core%2Fmain",
    );
    expect(screen.getByText("Below")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Demo SoC" }).getAttribute("href")).toBe("/p/alpha/health/soc");
  });

  it("refetches when the project changed past the page's watermark", async () => {
    let n = 0;
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 6, changes: [{ seq: 6, kind: "regression" }] });
      n += 1;
      return json(page({ watermark: 5 + n }));
    });
    renderAt("/p/alpha/health");
    await screen.findByText("Health of alpha");
    await waitFor(() => expect(n).toBeGreaterThan(1));
  });

  it("shows a stream's history with charts and N/A for a CPU delta that is not comparable", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      return json({
        stream: { producer: "ci", suite: "dma", branch: "core/main" },
        watermark: 5,
        evaluated_at: "x",
        regressions: [stream(), stream({ latest: { ref: "dma-6", state: "finished", started_at: "y" }, baseline: "dma-5" })],
      });
    });
    renderAt("/p/alpha/health-stream?producer=ci&suite=dma&branch=core%2Fmain");
    await screen.findAllByText("Outcome history (required slots)");
    expect(screen.getAllByText("Signature turnover").length).toBeGreaterThan(0);
    expect(screen.getByText(/not comparable/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "dma-7" }).getAttribute("href")).toBe("/p/alpha/r/dma-7?producer=ci");
    expect(calls[0]?.url).toContain("/health/history?producer=ci&suite=dma&branch=core%2Fmain&limit=30");
    // Each chart has its values as a table (the drawing itself is hidden from readers).
    expect(document.querySelectorAll("figure.chart svg[aria-hidden=true]").length).toBe(3);
    const tables = document.querySelectorAll("figure.chart details table");
    expect(tables.length).toBe(3);
    expect(tables[0]?.textContent).toContain("Required runs");
    expect(tables[1]?.textContent).toContain("Cancelled");
    expect(tables[1]?.querySelectorAll("tbody tr").length).toBe(2);
    // Readiness and trend of the latest regression are on the stream page.
    expect(screen.getByText("accepted with exceptions").className).toContain("hb-yellow");
    expect(screen.getAllByText("no worse").length).toBeGreaterThan(0);
  });

  it("explains an empty project without a hierarchy", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      return json(page({ hierarchy_revision: null, kpi: node({ streams: 0, trend: null, readiness: null }) }));
    });
    renderAt("/p/alpha/health");
    await screen.findByText(/dviscope hierarchy import/);
  });

  it("never hides grey streams behind a coloured roll-up, and keeps KPI badge colours", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      return json(
        page({
          kpi: node({ trend: "green", readiness: "green", grey: { insufficient_evidence: 1, no_data: 2, running: 1 } }),
          children: [
            {
              path: "soc",
              title: "Demo SoC",
              own_streams: 1,
              children: 0,
              health: node({ trend: "green", readiness: "green", grey: { no_data: 1 } }),
            },
          ],
        }),
      );
    });
    renderAt("/p/alpha/health");
    await screen.findByText("Health of alpha");
    // The clean colour comes with what it does not cover.
    expect(screen.getByText("and 2 no data, 1 running")).toBeTruthy();
    expect(screen.getByText("and 1 insufficient evidence, 2 no data")).toBeTruthy();
    expect(screen.getAllByText("and 1 no data").length).toBe(2);
    // KPI labels do not recolour the badges.
    const kpiBadges = document.querySelectorAll(".kpis .hb");
    expect(Array.from(kpiBadges).map((b) => b.className)).toEqual(["hb hb-green", "hb hb-green"]);
    // A child's badges lead to its page.
    const links = Array.from(document.querySelectorAll("a.badge-link")).map((a) => a.getAttribute("href"));
    expect(links).toEqual(["/p/alpha/health/soc", "/p/alpha/health/soc"]);
  });

  it("refreshes the stream page when its validity ends", async () => {
    let n = 0;
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      n += 1;
      return json({
        stream: { producer: "ci", suite: "dma", branch: "core/main" },
        watermark: 5,
        evaluated_at: "x",
        // Already past: the page is stale at once and is fetched again.
        valid_until: n === 1 ? "2000-01-01T00:00:00Z" : null,
        regressions: [stream()],
      });
    });
    renderAt("/p/alpha/health-stream?producer=ci&suite=dma&branch=core%2Fmain");
    await screen.findAllByText("Outcome history (required slots)");
    await waitFor(() => expect(n).toBeGreaterThan(1));
  });

  it("offers a shorter history when the read is too large, and shows overdue streams", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      if (url.includes("limit=30"))
        return json({ code: "E_TOO_LARGE", message: "this read needs 150000 slots (at most 100000)" }, 413);
      return json({
        stream: { producer: "ci", suite: "dma", branch: "core/main" },
        watermark: 5,
        evaluated_at: "x",
        valid_until: null,
        cadence_hours: 24,
        home: "soc/cpu_ss/dma",
        regressions: [stream({ overdue: true })],
      });
    });
    renderAt("/p/alpha/health-stream?producer=ci&suite=dma&branch=core%2Fmain");
    const more = await screen.findByRole("button", { name: "Show the last 10 regressions" });
    fireEvent.click(more);
    await screen.findAllByText("Outcome history (required slots)");
    expect(calls.some((c) => c.url.includes("limit=10"))).toBe(true);
    expect(screen.getByText(/Overdue: no regression of this stream started/)).toBeTruthy();
    expect(screen.getByText(/every 24 h/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "soc/cpu_ss/dma" }).getAttribute("href")).toBe(
      "/p/alpha/health/soc/cpu_ss/dma",
    );
  });


  it("steps the history down to the latest regression only when every longer one is too large", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      if (!url.includes("limit=1&") && !url.endsWith("limit=1"))
        return json({ code: "E_TOO_LARGE", message: "this read needs 120000 slots (at most 50000)" }, 413);
      return json({
        stream: { producer: "ci", suite: "dma", branch: "core/main" },
        watermark: 5,
        evaluated_at: "x",
        valid_until: null,
        cadence_hours: null,
        home: null,
        regressions: [stream()],
      });
    });
    renderAt("/p/alpha/health-stream?producer=ci&suite=dma&branch=core%2Fmain");
    for (const label of [
      "Show the last 10 regressions",
      "Show the last 5 regressions",
      "Show the last 2 regressions",
      "Show the latest regression only",
    ]) {
      fireEvent.click(await screen.findByRole("button", { name: label }));
    }
    await screen.findAllByText("Outcome history (required slots)");
    expect(calls.some((c) => c.url.endsWith("limit=1"))).toBe(true);
  });

  it("keeps the way down when a page is too large: the hierarchy lists the lower nodes", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      if (url.endsWith("/hierarchy"))
        return json({
          revision: 1,
          hierarchy: { nodes: [{ path: "soc", title: "Demo SoC" }, { path: "soc/cpu_ss" }, { path: "soc/dsp_ss" }] },
        });
      if (url.endsWith("/health") || url.includes("area=soc&") || url.endsWith("area=soc"))
        return json({ code: "E_TOO_LARGE", message: "this read needs 64000 slots (at most 32000)" }, 413);
      return json(page({ node: { kind: "node", path: "soc/cpu_ss", title: "cpu_ss", breadcrumb: [] } }));
    });
    renderAt("/p/alpha/health");
    fireEvent.click(await screen.findByRole("link", { name: "Demo SoC" }));
    fireEvent.click(await screen.findByRole("link", { name: "soc/cpu_ss" }));
    await screen.findByRole("heading", { name: "cpu_ss" });
    expect(calls.some((c) => c.url.endsWith("area=soc%2Fcpu_ss"))).toBe(true);
  });

  it("shows tests with their change and 0 called out, hides columns per browser, and draws test growth", async () => {
    localStorage.clear();
    let growthCalls = 0;
    mockFetch((url) => {
      if (url.includes("/health/growth")) {
        growthCalls += 1;
        if (url.includes("days=90")) {
          return json({ code: "E_TOO_LARGE", message: "this period has 30000 regressions" }, 413);
        }
        return json(
          growthOf([
            { date: "2026-11-12", required_runs: 10, tests: 6, streams: 1 },
            { date: "2026-11-13", required_runs: 4, tests: 3, streams: 2 },
          ]),
        );
      }
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      return json(
        page({
          kpi: node({ zero_test_streams: 1, compared_counts: counts({ required: 6 }), compared_baseline_counts: counts({ required: 10 }) }),
          own: [
            stream({ counts: counts({ required: 6 }), baseline_counts: counts({ required: 10 }) }),
            stream({
              stream: { producer: "ci", suite: "io", branch: "core/main" },
              counts: counts({ required: 0, passed: 0, failed: 0 }),
              baseline_counts: counts({ required: 4 }),
            }),
          ],
          children: [{ path: "soc", title: "Demo SoC", own_streams: 0, children: 0, health: node({ zero_test_streams: 1 }) }],
        }),
      );
    });
    const view = renderAt("/p/alpha/health");
    await screen.findByText("Tests (required runs)");
    // Fewer tests is the bad direction; a stream at 0 and the nodes holding one say so.
    const drops = screen.getAllByText("-4 vs last");
    expect(drops.length).toBeGreaterThan(0);
    expect(drops.every((d) => d.className.includes("delta-bad"))).toBe(true);
    expect(screen.getByText("0 tests").className).toContain("hb-red");
    expect(screen.getByText("1 stream with 0 tests").className).toContain("hb-red");
    expect(screen.getByText("1 with 0 tests").className).toContain("hb-red");
    // Hide a column of the stream table: gone from that table only, remembered by the browser.
    const streams = document.querySelectorAll("table.health")[0]!;
    expect(streams.textContent).toContain("Elapsed");
    const pickers = document.querySelectorAll("details.columns");
    const elapsed = [...pickers[0]!.querySelectorAll("label")].find((l) => l.textContent?.includes("Elapsed"));
    fireEvent.click(elapsed!.querySelector("input")!);
    expect(document.querySelectorAll("table.health")[0]!.querySelector("thead")!.textContent).not.toContain("Elapsed");
    expect(pickers[0]!.querySelector("summary")!.textContent).toBe("Columns (1 hidden)");
    expect(document.querySelectorAll("table.health")[1]!.querySelector("thead")!.textContent).toContain("Slowest");
    expect(JSON.parse(localStorage.getItem("dviscope.health.hidden.streams") ?? "[]")).toEqual(["elapsed"]);
    view.unmount();
    renderAt("/p/alpha/health");
    await screen.findByText("Tests (required runs)");
    expect(document.querySelectorAll("table.health")[0]!.querySelector("thead")!.textContent).not.toContain("Elapsed");
    // Test growth: too large for 90 days offers 30; then the values are drawn and tabled.
    fireEvent.click(await screen.findByRole("button", { name: "Show the last 30 days" }));
    await screen.findAllByText("Tests per day (each stream's latest regression by that day)");
    const growth = [...document.querySelectorAll("figure.chart")].find((f) => f.textContent?.includes("Tests per day"))!;
    const rows = growth.querySelectorAll("details tbody tr");
    expect([...rows].map((r) => r.textContent)).toEqual(["2026-11-12106", "2026-11-1343"]);
    expect(growth.querySelectorAll("polyline").length).toBe(2);
    // The series differ by stroke as well as colour.
    expect(growth.querySelectorAll("polyline")[1]!.getAttribute("stroke-dasharray")).toBe("6 3");
    expect(growth.querySelectorAll("polyline")[0]!.getAttribute("stroke-dasharray")).toBeNull();
    expect(calls.some((c) => c.url === "/api/v1/projects/alpha/health/growth?days=30")).toBe(true);
    expect(growthCalls).toBeGreaterThan(1);
    localStorage.clear();
  });

  it("shows every column and still hides one when the browser blocks storage", async () => {
    const get = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    try {
      mockFetch((url) => {
        if (url.includes("/health/growth")) return json(growthOf());
        if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
        return json(page({ own: [stream()] }));
      });
      renderAt("/p/alpha/health");
      await screen.findByText("Tests (required runs)");
      const head = () => document.querySelectorAll("table.health")[0]!.querySelector("thead")!.textContent;
      expect(head()).toContain("Elapsed");
      const picker = document.querySelector("details.columns")!;
      const elapsed = [...picker.querySelectorAll("label")].find((l) => l.textContent?.includes("Elapsed"))!;
      fireEvent.click(elapsed.querySelector("input")!);
      expect(head()).not.toContain("Elapsed");
      expect(set).toHaveBeenCalled();
    } finally {
      get.mockRestore();
      set.mockRestore();
    }
  });

  it("counts the time to UTC midnight and reloads the growth days when it passes", async () => {
    expect(msUntilUtcMidnight(Date.parse("2026-11-13T23:59:59.000Z"))).toBe(1000);
    expect(msUntilUtcMidnight(Date.parse("2026-11-13T00:00:00.000Z"))).toBe(86_400_000);
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      vi.setSystemTime(new Date("2026-11-13T23:59:58.000Z"));
      let growthCalls = 0;
      mockFetch((url) => {
        if (url.includes("/health/growth")) {
          growthCalls += 1;
          return json(growthOf());
        }
        if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
        return json(page({ own: [stream()] }));
      });
      renderAt("/p/alpha/health");
      await screen.findAllByText("Tests per day (each stream's latest regression by that day)");
      const before = growthCalls;
      await vi.advanceTimersByTimeAsync(4_000);
      await waitFor(() => expect(growthCalls).toBeGreaterThan(before));
    } finally {
      vi.useRealTimers();
    }
  });

  it("says over how many streams the KPI change is computed", async () => {
    mockFetch((url) => {
      if (url.includes("/health/growth")) return json(growthOf());
      if (url.includes("/changes")) return json({ change_seq: 5, changes: [] });
      return json(page({ kpi: node({ streams: 3, compared_streams: 2, worst_rate: 40 }) }));
    });
    renderAt("/p/alpha/health");
    // Both changes (pass rate and tests) say over which streams they are computed.
    expect((await screen.findAllByText(/over 2 of 3 streams/)).length).toBe(2);
    expect(screen.getByText("worst stream 40.0%")).toBeTruthy();
  });
});

describe("sessions, expiry and drafts", () => {
  it("nothing cached under one session renders for the next", async () => {
    // Ann sees "secret-a"; her session expires; Bob signs in while his list is pending.
    let phase: "ann" | "expired" | "bob" = "ann";
    let release: (r: Response) => void = () => {};
    mockFetch((url, init) => {
      if (url === "/api/v1/session" && init.method === "POST") {
        phase = "bob";
        return new Response(null, { status: 204, headers: { "X-DVIScope-CSRF": "c" } });
      }
      if (phase === "expired") return json({ code: "E_UNAUTHENTICATED", message: "x" }, 401);
      if (url === "/api/v1/projects") {
        if (phase === "ann") {
          return json({ projects: [{ name: "secret-a", policy: "first-attempt", role: "viewer" }] });
        }
        return new Promise<Response>((r) => (release = r));
      }
      return json({ code: "E_NOT_FOUND", message: url }, 404);
    });
    renderAt("/");
    await screen.findByText("secret-a");
    phase = "expired";
    // Any request answered 401 (here opening the project) sends the app to sign-in.
    fireEvent.click(screen.getByRole("link", { name: "secret-a" }));
    await screen.findByRole("heading", { name: "Sign in" });
    // Back to the list without signing in: nothing of Ann's renders meanwhile.
    fireEvent.click(screen.getByRole("link", { name: "DVIScope" }));
    expect(screen.queryByText("secret-a")).toBeNull();
    await screen.findByRole("heading", { name: "Sign in" });
    fireEvent.change(screen.getByLabelText("User"), { target: { value: "bob" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() =>
      expect(screen.queryByRole("heading", { name: "Sign in" })).toBeNull(),
    );
    expect(screen.queryByText("secret-a")).toBeNull();
    release(json({ projects: [] }));
  });

  it("signing in as someone else (no 401 seen) starts from an empty cache", async () => {
    let user = "ann";
    let release: (r: Response) => void = () => {};
    mockFetch((url, init) => {
      if (url === "/api/v1/session" && init.method === "POST") {
        user = "bob";
        return new Response(null, { status: 204, headers: { "X-DVIScope-CSRF": "c" } });
      }
      if (url === "/api/v1/projects") {
        if (user === "ann") {
          return json({ projects: [{ name: "secret-a", policy: "first-attempt", role: "viewer" }] });
        }
        return new Promise<Response>((r) => (release = r));
      }
      return json({ code: "E_NOT_FOUND", message: url }, 404);
    });
    const qc = makeQueryClient();
    const view = (path: string) => (
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[path]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>
    );
    const r = render(view("/"));
    await screen.findByText("secret-a");
    r.unmount();
    render(view("/login"));
    fireEvent.change(screen.getByLabelText("User"), { target: { value: "bob" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() =>
      expect(screen.queryByRole("heading", { name: "Sign in" })).toBeNull(),
    );
    expect(screen.queryByText("secret-a")).toBeNull();
    release(json({ projects: [] }));
  });

  it("a failed sign-out says so and keeps the user signed in; 401 means signed out", async () => {
    localStorage.setItem("dviscope.csrf", "c1");
    let answer = 403;
    mockFetch((url, init) => {
      if (url === "/api/v1/session" && init.method === "DELETE") {
        return answer === 204
          ? new Response(null, { status: 204 })
          : json({ code: "E_FORBIDDEN", message: "csrf" }, answer);
      }
      if (url === "/api/v1/projects") {
        return json({ projects: [{ name: "alpha", policy: "first-attempt", role: "viewer" }] });
      }
      return json({ code: "E_NOT_FOUND", message: url }, 404);
    });
    renderAt("/");
    await screen.findByText("alpha");
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect((await screen.findByTestId("sign-out-error")).textContent).toContain(
      "still signed in",
    );
    expect(screen.queryByRole("heading", { name: "Sign in" })).toBeNull();
    expect(localStorage.getItem("dviscope.csrf")).toBe("c1");
    // Already signed out elsewhere (401): treated as signed out.
    answer = 401;
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByRole("heading", { name: "Sign in" });
    expect(localStorage.getItem("dviscope.csrf")).toBeNull();
  });

  it("a comparison is read again when a covering exception expires", async () => {
    const expires = new Date(Date.now() + 300).toISOString();
    let comparisons = 0;
    mockFetch((url) => {
      if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        comparisons += 1;
        return json({
          regression: regHeader,
          comparison: {
            header,
            rows: [
              {
                signature: "sha256:" + "a".repeat(64),
                number: 12,
                failed_slots: 1,
                failing_attempts: 1,
                diagnostics: 1,
                baseline_slots: 0,
                baseline: "absent_from_baseline",
                simulators: ["sim-a"],
                preview: ["t1:seed=1"],
                triage_state: null,
                owner: null,
                latest_note: null,
                bug_url: null,
                exception: comparisons === 1 ? { id: 3, expires_at: expires } : null,
                disposition: comparisons === 1 ? "covered" : "needs_decision",
                next_action: "triage",
              },
            ],
          },
          baseline: { ref: null, reason: "none" },
          finish: {
            merge_blockers: comparisons === 1 ? 0 : 1,
            merge_blocker_kinds: {},
            merge_verdict: comparisons === 1 ? "accepted_with_exceptions" : "fail",
            groups: 1,
            needs_decision: comparisons === 1 ? 0 : 1,
            assigned: 0,
            covered: comparisons === 1 ? 1 : 0,
            blocking_groups: comparisons === 1 ? 0 : 1,
            missing_results: 0,
            partly_covered_slots: false,
          },
        });
      }
      return json({ regression: regHeader, header, slots: [] });
    });
    renderAt("/p/alpha/r/nightly-7");
    await screen.findByRole("link", { name: "#12" });
    expect(comparisons).toBe(1);
    await waitFor(() => expect(comparisons).toBe(2), { timeout: 4000 });
  });

  it("a triage conflict reloads the case and keeps the edits; fields are frozen while saving", async () => {
    localStorage.setItem("dviscope.csrf", "c");
    let rev = 3;
    let release: (r: Response) => void = () => {};
    let puts = 0;
    const detail = (r: number, by: string) => ({
      number: 12,
      fingerprint: "sha256:" + "f".repeat(64),
      family_kind: "uvm",
      diag_id: "uvm:X",
      identity_template: "t",
      note: "n",
      occurrences: [],
      triage: [{ id: 1, branch: "core/main", revision: r, state: "open", owner: by,
                 notes: `by ${by}`, bug_urls: [], by, at: "2026-11-02T08:00:00Z" }],
      exceptions: [],
    });
    mockFetch((url, init) => {
      if (init.method === "PUT") {
        puts += 1;
        if (puts === 1) {
          rev = 4;
          return json({ code: "E_PRECONDITION_FAILED", message: "changed" }, 412);
        }
        return new Promise<Response>((r) => (release = r));
      }
      return json(detail(rev, rev === 3 ? "ann" : "bob"));
    });
    renderAt("/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke");
    await screen.findByText("Triage on core/main");
    const notes = () => screen.getByLabelText("Notes") as HTMLTextAreaElement;
    fireEvent.change(notes(), { target: { value: "my analysis" } });
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));
    // The conflict names the newer revision; the user's edits are kept.
    const alert = await screen.findByTestId("triage-conflict");
    await waitFor(() => expect(alert.textContent).toContain("revision 4 by bob"));
    expect(notes().value).toBe("my analysis");
    // Saving again uses the newer revision; the fields are frozen meanwhile.
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));
    await waitFor(() => expect(puts).toBe(2));
    const second = calls.filter((c) => c.init.method === "PUT")[1];
    expect((second?.init.headers as Record<string, string>)["If-Match"]).toBe('"4"');
    expect(notes().disabled).toBe(true);
    release(json({ id: 1, revision: 5 }));
    await waitFor(() => expect(notes().disabled).toBe(false));
  });

  it("occurrence links and the attempt breadcrumb carry the producer", async () => {
    mockFetch(() =>
      json({
        number: 12,
        fingerprint: "sha256:" + "f".repeat(64),
        family_kind: "uvm",
        diag_id: "uvm:X",
        identity_template: "t",
        note: "n",
        occurrences: [{ regression: "n7", producer: "ci-b", slot: "t1", attempt_seq: 2,
                        report_revision: 1, count: "1", severity: "error", simulator: "sim-a",
                        effective: "failed" }],
        triage: [],
        exceptions: [],
      }),
    );
    renderAt("/p/alpha/signatures/12");
    const reg = await screen.findByRole("link", { name: "n7" });
    expect(reg.getAttribute("href")).toBe("/p/alpha/r/n7?producer=ci-b");
    const att = screen.getByRole("link", { name: "#2 r1" });
    expect(att.getAttribute("href")).toBe("/p/alpha/r/n7/s/t1/a/2?producer=ci-b");
  });

  it("a sign-in or sign-out in another tab clears this one", async () => {
    let user = "ann";
    let release: (r: Response) => void = () => {};
    mockFetch((url) => {
      if (url === "/api/v1/projects") {
        if (user === "ann") {
          return json({ projects: [{ name: "secret-a", policy: "first-attempt", role: "viewer" }] });
        }
        return new Promise<Response>((r) => (release = r));
      }
      return json({ code: "E_NOT_FOUND", message: url }, 404);
    });
    renderAt("/");
    await screen.findByText("secret-a");
    user = "bob";
    window.dispatchEvent(new StorageEvent("storage", { key: "dviscope.csrf", newValue: "bob-csrf" }));
    await waitFor(() => expect(screen.queryByText("secret-a")).toBeNull());
    release(json({ projects: [] }));
    // Signed out elsewhere: back to sign-in.
    window.dispatchEvent(new StorageEvent("storage", { key: "dviscope.csrf", newValue: null }));
    await screen.findByRole("heading", { name: "Sign in" });
  });

  it("an expired exception marks the verdict out of date even if the re-read fails", async () => {
    const expires = new Date(Date.now() + 200).toISOString();
    let comparisons = 0;
    mockFetch((url) => {
      if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        comparisons += 1;
        if (comparisons > 1) return json({ code: "E_INTERNAL", message: "down" }, 500);
        return json({
          regression: regHeader,
          comparison: {
            header,
            rows: [
              {
                signature: "sha256:" + "a".repeat(64),
                number: 12,
                failed_slots: 1,
                failing_attempts: 1,
                diagnostics: 1,
                baseline_slots: 0,
                baseline: "absent_from_baseline",
                simulators: ["sim-a"],
                preview: ["t1:seed=1"],
                triage_state: null,
                owner: null,
                latest_note: null,
                bug_url: null,
                exception: { id: 3, expires_at: expires },
                disposition: "covered",
                next_action: "none",
              },
            ],
          },
          baseline: { ref: null, reason: "none" },
          finish: {
            merge_blockers: 0,
            merge_blocker_kinds: {},
            merge_verdict: "accepted_with_exceptions",
            groups: 1,
            needs_decision: 0,
            assigned: 0,
            covered: 1,
            blocking_groups: 0,
            missing_results: 0,
            partly_covered_slots: false,
          },
        });
      }
      return json({ regression: regHeader, header, slots: [] });
    });
    renderAt("/p/alpha/r/nightly-7");
    const card = await screen.findByTestId("finish-card");
    expect(card.textContent).toContain("no blockers");
    await screen.findByTestId("exception-expired", {}, { timeout: 4000 });
    await waitFor(() => expect(comparisons).toBeGreaterThan(1), { timeout: 4000 });
    expect(screen.getByTestId("finish-card").textContent).not.toContain("no blockers");
  });

  it("a failed re-read keeps the draft; fields stay frozen until the saved case is read back", async () => {
    localStorage.setItem("dviscope.csrf", "c");
    let rev = 3;
    let gets = 0;
    let failNextGet = false;
    let releaseGet: (r: Response) => void = () => {};
    let delayGet = false;
    const detail = (r: number, by: string) => ({
      number: 12,
      fingerprint: "sha256:" + "f".repeat(64),
      family_kind: "uvm",
      diag_id: "uvm:X",
      identity_template: "t",
      note: "n",
      occurrences: [],
      triage: [{ id: 1, branch: "core/main", revision: r, state: "open", owner: by,
                 notes: `by ${by}`, bug_urls: [], by, at: "2026-11-02T08:00:00Z" }],
      exceptions: [],
    });
    let puts = 0;
    mockFetch((url, init) => {
      if (init.method === "PUT") {
        puts += 1;
        if (puts === 1) {
          rev = 4;
          failNextGet = true;
          return json({ code: "E_PRECONDITION_FAILED", message: "changed" }, 412);
        }
        rev = 5;
        delayGet = true;
        return json({ id: 1, revision: 5 });
      }
      gets += 1;
      if (failNextGet) {
        failNextGet = false;
        // Not retried (a 5xx would be): the re-read fails.
        return json({ code: "E_FORBIDDEN", message: "denied" }, 403);
      }
      if (delayGet) {
        delayGet = false;
        return new Promise<Response>((r) => (releaseGet = r));
      }
      return json(detail(rev, rev === 3 ? "ann" : "bob"));
    });
    renderAt("/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke");
    await screen.findByText("Triage on core/main");
    const notes = () => screen.getByLabelText("Notes") as HTMLTextAreaElement;
    fireEvent.change(notes(), { target: { value: "my analysis" } });
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));
    await screen.findByTestId("triage-conflict");
    await waitFor(() => expect(gets).toBe(2));
    // The re-read failed: the editor and its draft are still there.
    expect(notes().value).toBe("my analysis");
    // Saved: the fields stay frozen until the saved case is read back.
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));
    await waitFor(() => expect(puts).toBe(2));
    await waitFor(() => expect(gets).toBe(3));
    expect(notes().disabled).toBe(true);
    releaseGet(json(detail(5, "ann")));
    await waitFor(() => expect(notes().disabled).toBe(false));
  });
  it("a new session starts every page anew: no draft or selection survives", async () => {
    localStorage.setItem("dviscope.csrf", "ann-csrf");
    const row = (n: number) => ({
      signature: "sha256:" + String(n).repeat(64).slice(0, 64),
      number: n,
      failed_slots: 1,
      failing_attempts: 1,
      diagnostics: 1,
      baseline_slots: 0,
      baseline: "absent_from_baseline",
      simulators: ["sim-a"],
      preview: ["t1:seed=1"],
      diag_id: "uvm:X",
      identity_template: "t",
      triage_state: null,
      triage_revision: null,
      owner: null,
      latest_note: null,
      bug_url: null,
      exception: null,
      disposition: "needs_decision",
      next_action: "assign an owner",
    });
    mockFetch((url) => {
      if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        return json({
          regression: regHeader,
          comparison: { header, rows: [row(12), row(13)] },
          baseline: { ref: null, reason: "none" },
          finish: {
            merge_blockers: 2,
            merge_blocker_kinds: { failed: 2 },
            merge_verdict: "fail",
            groups: 2,
            needs_decision: 2,
            assigned: 0,
            covered: 0,
            blocking_groups: 2,
            missing_results: 0,
            partly_covered_slots: false,
          },
        });
      }
      return json({ regression: regHeader, header, slots: [] });
    });
    renderAt("/p/alpha/r/nightly-7");
    await screen.findByRole("link", { name: "#12" });
    fireEvent.click(screen.getByRole("button", { name: "Select all needing decision" }));
    await screen.findByTestId("bulk-triage");
    fireEvent.change(screen.getByLabelText("Notes", { selector: "[data-testid=bulk-triage] textarea" }), {
      target: { value: "ann's analysis" },
    });
    // Bob signs in in another tab.
    window.dispatchEvent(new StorageEvent("storage", { key: "dviscope.csrf", newValue: "bob-csrf" }));
    await waitFor(() => expect(screen.queryByTestId("bulk-triage")).toBeNull());
    await screen.findByRole("checkbox", { name: "Select #12" });
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByTestId("bulk-triage")).toBeNull();
    expect((screen.getByRole("checkbox", { name: "Select #12" }) as HTMLInputElement).checked).toBe(false);
    fireEvent.click(screen.getByRole("checkbox", { name: "Select #12" }));
    await screen.findByTestId("bulk-triage");
    expect(
      (screen.getByLabelText("Notes", { selector: "[data-testid=bulk-triage] textarea" }) as HTMLTextAreaElement)
        .value,
    ).toBe("");
  });

  it("a cached page shown again after the expiry says the verdict is out of date", async () => {
    const expires = new Date(Date.now() + 300).toISOString();
    let failing = false;
    let comparisons = 0;
    mockFetch((url) => {
      if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        comparisons += 1;
        if (failing) return json({ code: "E_FORBIDDEN", message: "denied" }, 403);
        return json({
          regression: regHeader,
          comparison: {
            header,
            rows: [
              {
                signature: "sha256:" + "a".repeat(64),
                number: 12,
                failed_slots: 1,
                failing_attempts: 1,
                diagnostics: 1,
                baseline_slots: 0,
                baseline: "absent_from_baseline",
                simulators: ["sim-a"],
                preview: ["t1:seed=1"],
                triage_state: null,
                owner: null,
                latest_note: null,
                bug_url: null,
                exception: { id: 3, expires_at: expires },
                disposition: "covered",
                next_action: "none",
              },
            ],
          },
          baseline: { ref: null, reason: "none" },
          finish: {
            merge_blockers: 0,
            merge_blocker_kinds: {},
            merge_verdict: "accepted_with_exceptions",
            groups: 1,
            needs_decision: 0,
            assigned: 0,
            covered: 1,
            blocking_groups: 0,
            missing_results: 0,
            partly_covered_slots: false,
          },
        });
      }
      return json({ regression: regHeader, header, slots: [] });
    });
    const qc = makeQueryClient();
    const page = () => (
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/p/alpha/r/nightly-7"]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>
    );
    const first = render(page());
    expect((await screen.findByTestId("finish-card")).textContent).toContain("no blockers");
    // Left before the expiry; shown again from the cache after it, and the re-read fails.
    first.unmount();
    await new Promise((r) => setTimeout(r, 800));
    failing = true;
    render(page());
    await screen.findByTestId("exception-expired");
    expect(screen.getByTestId("finish-card").textContent).not.toContain("no blockers");
    await waitFor(() => expect(comparisons).toBeGreaterThan(1));
    await new Promise((r) => setTimeout(r, 100));
    expect(screen.getByTestId("exception-expired")).toBeTruthy();
  });

  it("an exception that expires while the answer is in transit is caught", async () => {
    // The server evaluated the comparison with the exception active; it expires 200 ms later
    // and the answer arrives after 600 ms. Every re-read fails.
    const expires = new Date(Date.now() + 200).toISOString();
    let comparisons = 0;
    mockFetch(async (url) => {
      if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
      if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
      if (url.includes("/comparison")) {
        comparisons += 1;
        if (comparisons > 1) return json({ code: "E_FORBIDDEN", message: "denied" }, 403);
        await new Promise((r) => setTimeout(r, 600));
        return json({
          regression: regHeader,
          comparison: {
            header,
            rows: [
              {
                signature: "sha256:" + "a".repeat(64),
                number: 12,
                failed_slots: 1,
                failing_attempts: 1,
                diagnostics: 1,
                baseline_slots: 0,
                baseline: "absent_from_baseline",
                simulators: ["sim-a"],
                preview: ["t1:seed=1"],
                triage_state: null,
                owner: null,
                latest_note: null,
                bug_url: null,
                exception: { id: 3, expires_at: expires },
                disposition: "covered",
                next_action: "none",
              },
            ],
          },
          baseline: { ref: null, reason: "none" },
          finish: {
            merge_blockers: 0,
            merge_blocker_kinds: {},
            merge_verdict: "accepted_with_exceptions",
            groups: 1,
            needs_decision: 0,
            assigned: 0,
            covered: 1,
            blocking_groups: 0,
            missing_results: 0,
            partly_covered_slots: false,
          },
        });
      }
      return json({ regression: regHeader, header, slots: [] });
    });
    renderAt("/p/alpha/r/nightly-7");
    await screen.findByTestId("exception-expired", {}, { timeout: 3000 });
    expect(screen.getByTestId("finish-card").textContent).not.toContain("no blockers");
    await waitFor(() => expect(comparisons).toBeGreaterThan(1));
    await new Promise((r) => setTimeout(r, 100));
    expect(screen.getByTestId("exception-expired")).toBeTruthy();
  });

  it("an exception beyond the longest timer still expires on a page left open", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const day = 86_400_000;
      const expires = new Date(Date.now() + 30 * day).toISOString();
      let comparisons = 0;
      mockFetch((url) => {
        if (url.includes("/repair-list")) return json({ regression: "nightly-7", groups: [], text: "" });
        if (url.includes("/changes")) return json({ change_seq: 4, changes: [] });
        if (url.includes("/comparison")) {
          comparisons += 1;
          if (comparisons > 1) return json({ code: "E_FORBIDDEN", message: "denied" }, 403);
          return json({
            regression: regHeader,
            comparison: {
              header,
              rows: [
                {
                  signature: "sha256:" + "a".repeat(64),
                  number: 12,
                  failed_slots: 1,
                  failing_attempts: 1,
                  diagnostics: 1,
                  baseline_slots: 0,
                  baseline: "absent_from_baseline",
                  simulators: ["sim-a"],
                  preview: ["t1:seed=1"],
                  triage_state: null,
                  owner: null,
                  latest_note: null,
                  bug_url: null,
                  exception: { id: 3, expires_at: expires },
                  disposition: "covered",
                  next_action: "none",
                },
              ],
            },
            baseline: { ref: null, reason: "none" },
            finish: {
              merge_blockers: 0,
              merge_blocker_kinds: {},
              merge_verdict: "accepted_with_exceptions",
              groups: 1,
              needs_decision: 0,
              assigned: 0,
              covered: 1,
              blocking_groups: 0,
              missing_results: 0,
              partly_covered_slots: false,
            },
          });
        }
        return json({ regression: regHeader, header, slots: [] });
      });
      renderAt("/p/alpha/r/nightly-7");
      expect((await screen.findByTestId("finish-card")).textContent).toContain("no blockers");
      // The first timer wakes at its cap (~24.8 days), before the expiry.
      await act(async () => {
        vi.advanceTimersByTime(25 * day);
      });
      expect(screen.queryByTestId("exception-expired")).toBeNull();
      await act(async () => {
        vi.advanceTimersByTime(6 * day);
      });
      await screen.findByTestId("exception-expired");
      expect(screen.getByTestId("finish-card").textContent).not.toContain("no blockers");
      await waitFor(() => expect(comparisons).toBeGreaterThan(1));
    } finally {
      vi.useRealTimers();
    }
  });

  it("edits typed after a failed post-save re-read survive a later read", async () => {
    localStorage.setItem("dviscope.csrf", "c");
    let rev = 3;
    let gets = 0;
    let failNextGet = false;
    const detail = (r: number) => ({
      number: 12,
      fingerprint: "sha256:" + "f".repeat(64),
      family_kind: "uvm",
      diag_id: "uvm:X",
      identity_template: "t",
      note: "n",
      occurrences: [],
      triage: [{ id: 1, branch: "core/main", revision: r, state: "open", owner: "ann",
                 notes: r === 3 ? "first" : "saved analysis", bug_urls: [], by: "ann",
                 at: "2026-11-02T08:00:00Z" }],
      exceptions: [],
    });
    mockFetch((_url, init) => {
      if (init.method === "PUT") {
        rev = 4;
        failNextGet = true;
        return json({ id: 1, revision: 4 });
      }
      gets += 1;
      if (failNextGet) {
        failNextGet = false;
        return json({ code: "E_FORBIDDEN", message: "denied" }, 403);
      }
      return json(detail(rev));
    });
    renderAt("/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke");
    await screen.findByText("Triage on core/main");
    const notes = () => screen.getByLabelText("Notes") as HTMLTextAreaElement;
    fireEvent.change(notes(), { target: { value: "saved analysis" } });
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));
    await waitFor(() => expect(gets).toBe(2));
    await waitFor(() => expect(notes().disabled).toBe(false));
    fireEvent.change(notes(), { target: { value: "saved analysis, and more" } });
    // Reconnecting reads the case again (successfully): the newer edits stay.
    onlineManager.setOnline(false);
    onlineManager.setOnline(true);
    await waitFor(() => expect(gets).toBe(3));
    await screen.findByText(/Revision 4 by ann/);
    expect(notes().value).toBe("saved analysis, and more");
  });

  it("with nothing typed after the save, the saved case is shown as read", async () => {
    localStorage.setItem("dviscope.csrf", "c");
    let rev = 3;
    mockFetch((_url, init) => {
      if (init.method === "PUT") {
        rev = 4;
        return json({ id: 1, revision: 4 });
      }
      return json({
        number: 12,
        fingerprint: "sha256:" + "f".repeat(64),
        family_kind: "uvm",
        diag_id: "uvm:X",
        identity_template: "t",
        note: "n",
        occurrences: [],
        triage: [{ id: 1, branch: "core/main", revision: rev, state: "open",
                   owner: rev === 3 ? "ann" : "Ana", notes: "x", bug_urls: [], by: "ann",
                   at: "2026-11-02T08:00:00Z" }],
        exceptions: [],
      });
    });
    renderAt("/p/alpha/signatures/12?branch=core%2Fmain&suite=smoke");
    await screen.findByText("Triage on core/main");
    const owner = () => screen.getByLabelText("Owner") as HTMLInputElement;
    fireEvent.change(owner(), { target: { value: " Ana " } });
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));
    await screen.findByText(/Revision 4 by ann/);
    // The server's normalized value replaces the identical draft.
    await waitFor(() => expect(owner().value).toBe("Ana"));
  });
});
