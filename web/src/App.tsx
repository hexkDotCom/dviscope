import { useEffect, useState } from "react";
import { QueryClient, useQueryClient } from "@tanstack/react-query";
import { Link, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import {
  ApiError,
  SESSION_EVENT,
  logout,
  sessionChanged,
  setUnauthenticatedHandler,
} from "./api/client";
import { LoginPage } from "./features/LoginPage";
import { ProjectsPage } from "./features/ProjectsPage";
import { RegressionsPage } from "./features/RegressionsPage";
import { RegressionPage } from "./features/RegressionPage";
import { ReadinessPage } from "./features/ReadinessPage";
import { SignaturePage } from "./features/SignaturePage";
import { AttemptPage } from "./features/AttemptPage";
import { AdminPage } from "./features/AdminPage";
import { ReceiptPage } from "./features/ReceiptPage";
import { ChecklistsPage, FeaturePage } from "./features/ChecklistPages";
import { HealthPage, HealthStreamPage } from "./features/HealthPages";

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Authentication and authorization errors are answers, not transient failures.
        retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 2,
        refetchOnWindowFocus: false,
      },
    },
  });
}

export function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();
  const [signOutError, setSignOutError] = useState<string | null>(null);
  // Every page is mounted anew under a new session: drafts, selections and pending saves
  // a page holds belong to the session that made them. The query
  // and mutation caches are cleared alongside.
  const [session, setSession] = useState(0);
  useEffect(() => {
    const onSession = () => setSession((n) => n + 1);
    window.addEventListener(SESSION_EVENT, onSession);
    return () => window.removeEventListener(SESSION_EVENT, onSession);
  }, []);
  useEffect(() => {
    setUnauthenticatedHandler(() => {
      // The session ended: nothing cached under it may render for the next one.
      void qc.cancelQueries();
      qc.clear();
      sessionChanged();
      if (location.pathname !== "/login") {
        navigate(`/login?next=${encodeURIComponent(location.pathname + location.search)}`);
      }
    });
  }, [navigate, location, qc]);
  // Another tab of this origin signed in or out (the session cookie and the CSRF token are
  // shared): nothing loaded under the previous session may stay on screen here.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key !== null && e.key !== "dviscope.csrf") return;
      void qc.cancelQueries();
      qc.getMutationCache().clear();
      sessionChanged();
      if (e.newValue) {
        // A new session: everything is read again under it.
        void qc.resetQueries();
      } else {
        qc.clear();
        navigate("/login");
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [qc, navigate]);
  const signOut = async () => {
    setSignOutError(null);
    try {
      await logout();
    } catch (e) {
      // Not signed out: never pretend otherwise.
      setSignOutError(
        `Sign-out failed: ${e instanceof Error ? e.message : String(e)}. You are still signed in.`,
      );
      return;
    }
    void qc.cancelQueries();
    qc.clear();
    sessionChanged();
    navigate("/login");
  };
  return (
    <>
      <header className="top">
        <Link to="/" className="brand">
          DVIScope
        </Link>
        {location.pathname !== "/login" && (
          <button type="button" className="link" onClick={signOut}>
            Sign out
          </button>
        )}
        {signOutError && (
          <p className="warning" role="alert" data-testid="sign-out-error">
            {signOutError}
          </p>
        )}
      </header>
      <main key={session}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<ProjectsPage />} />
          <Route path="/p/:project" element={<RegressionsPage />} />
          <Route path="/p/:project/r/:regression" element={<RegressionPage />} />
          <Route path="/p/:project/r/:regression/readiness" element={<ReadinessPage />} />
          <Route
            path="/p/:project/r/:regression/s/:slot/a/:seq"
            element={<AttemptPage />}
          />
          <Route path="/p/:project/signatures/:number" element={<SignaturePage />} />
          <Route path="/p/:project/admin" element={<AdminPage />} />
          <Route path="/p/:project/checklists" element={<ChecklistsPage />} />
          <Route path="/p/:project/health" element={<HealthPage />} />
          <Route path="/p/:project/health/*" element={<HealthPage />} />
          <Route path="/p/:project/health-stream" element={<HealthStreamPage />} />
          <Route path="/p/:project/checklists/:checklist" element={<FeaturePage />} />
          <Route path="/p/:project/receipts/:digest" element={<ReceiptPage />} />
          <Route path="*" element={<p>Page not found.</p>} />
        </Routes>
      </main>
    </>
  );
}
