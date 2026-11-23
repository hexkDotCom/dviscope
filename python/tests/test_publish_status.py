"""Tests of the status publisher against a fake DVIScope API and a recording commit-status
endpoint (both on loopback; no real code host). All data is invented."""

from __future__ import annotations

import datetime as dt
import io
import json
import sys
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dviscope_hexk import publish_status as ps  # noqa: E402

DV_TOKEN = "dvis_test_personal_token_value"
GH_TOKEN = "github_pat_test_value"
T0 = dt.datetime(2026, 11, 8, 7, 5, tzinfo=dt.timezone.utc)
TARGET = {"repository": "hexkDotCom/dviscope-dev", "commit": "a" * 40, "context": "dviscope/merge"}


def receipt(digest: str, state: str, verdict: str, **kw) -> dict:
    r = {
        "digest": digest,
        "summary": {"verdict": verdict},
        "regression": "nightly-7",
        "producer": "ci",
        "expect_source": "sha256:" + "1" * 64,
        "target": dict(TARGET),
        "status": {"state": state, "description": f"{verdict} as of 2026-11-08 07:05Z; dig {digest[7:19]}"},
        "published_at": "2026-11-08T07:05:00Z",
        "valid_until": None,
        "monitor_until": "2026-11-22T07:05:00Z",
        "posted_at": None,
        "last_refresh_at": None,
        "retired_at": None,
        "retired_reason": None,
        "receipt_path": f"/p/alpha/receipts/{digest.replace(':', '%3A')}",
    }
    r.update(kw)
    return r


class Recorder:
    """A tiny JSON server: handlers by (method, path prefix); records every request."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.routes: dict[tuple[str, str], object] = {}
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _do(self, method: str) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                outer.requests.append({"method": method, "path": self.path, "body": body,
                                       "auth": self.headers.get("Authorization")})
                for (m, prefix), fn in outer.routes.items():
                    if m == method and self.path.startswith(prefix):
                        status, out, *how = fn(self.path, body) if callable(fn) else fn
                        data = b"" if out is None else (out if isinstance(out, bytes) else json.dumps(out).encode())
                        self.send_response(status)
                        if 300 <= status < 400 and getattr(outer, "location", None):
                            self.send_header("Location", outer.location)
                        self.send_header("Content-Type", "application/json")
                        # "truncate": the connection closes before the advertised length.
                        extra = 64 if how == ["truncate"] else 0
                        self.send_header("Content-Length", str(len(data) + extra))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def of(self, method: str, prefix: str) -> list[dict]:
        return [r for r in self.requests if r["method"] == method and r["path"].startswith(prefix)]


PUB = "/api/v1/projects/alpha/readiness/publications"


class PublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dv = Recorder()
        self.gh = Recorder()
        self.addCleanup(self.dv.close)
        self.addCleanup(self.gh.close)
        self.gh.routes[("POST", "/repos/")] = lambda path, body: (201, {"state": body["state"]})
        self.now = T0
        self.dv.routes[("POST", PUB + "/")] = self._posted
        self.targets: dict[str, dict] = {}  # digest -> target, for receipts of other targets

    def _posted(self, path: str, body: dict):
        digest = path.split("/")[-2]
        if path.endswith("/retire"):
            return 200, {"digest": digest, "retired_reason": body["reason"]}
        digest = digest.replace("%3A", ":")
        return 200, receipt(digest, body["state"], "x", posted_at="2026-11-08T07:06:00Z",
                            target=dict(self.targets.get(digest, TARGET)))

    def pub(self) -> ps.Publisher:
        return ps.Publisher(
            project="alpha",
            dv=ps.Http(self.dv.url, DV_TOKEN),
            gh=ps.GitHub(ps.Http(self.gh.url, GH_TOKEN)),
            ui_base="https://dviscope.example",
            now=lambda: self.now,
        )

    def test_publish_posts_the_receipts_status_then_records_acceptance(self) -> None:
        r = receipt("sha256:" + "a" * 64, "failure", "fail")
        self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": r})
        out = self.pub().publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET))
        self.assertEqual(out["action"], "post")
        [post] = self.gh.of("POST", "/repos/hexkDotCom/dviscope-dev/statuses/" + "a" * 40)
        self.assertEqual(post["body"]["state"], "failure")
        self.assertEqual(post["body"]["context"], "dviscope/merge")
        self.assertEqual(post["body"]["target_url"], "https://dviscope.example" + r["receipt_path"])
        self.assertEqual(post["auth"], f"Bearer {GH_TOKEN}")
        [posted] = self.dv.of("POST", PUB + "/")
        self.assertTrue(posted["path"].endswith("/posted"))
        self.assertEqual(posted["body"], {"state": "failure"})
        self.assertEqual(self.dv.of("POST", PUB)[0]["auth"], f"Bearer {DV_TOKEN}")

    def test_unchanged_status_is_reasserted(self) -> None:
        # Re-asserting repairs an obsolete status written by another publisher run.
        r = receipt("sha256:" + "a" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z")
        self.dv.routes[("POST", PUB)] = (200, {"action": "unchanged", "receipt": r})
        self.pub().publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET))
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["success"])

    def test_failed_evaluation_sets_pending_never_success(self) -> None:
        for route in [(500, {"code": "E_INTERNAL"}), (200, b"not json"), (200, {"action": "post"}),
                      (200, {"action": "post", "receipt": receipt("sha256:" + "a" * 64, "green", "pass")})]:
            self.gh.requests.clear()
            self.dv.routes[("POST", PUB)] = route
            with self.assertRaises(ps.PublishError):
                self.pub().publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET))
            states = [r["body"]["state"] for r in self.gh.requests]
            self.assertEqual(states, ["pending"], route)
            self.assertTrue(self.gh.requests[0]["body"]["description"].startswith(ps.NEEDED))

    def test_unreachable_server_sets_pending(self) -> None:
        p = self.pub()
        p.dv = ps.Http("http://127.0.0.1:9", DV_TOKEN, timeout=2)
        with self.assertRaises(ps.PublishError) as e:
            p.publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET))
        self.assertNotIn(DV_TOKEN, str(e.exception))
        self.assertEqual([r["body"]["state"] for r in self.gh.requests], ["pending"])

    def test_monitor_posts_unaccepted_receipts_after_a_restart(self) -> None:
        r = receipt("sha256:" + "b" * 64, "success", "pass")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
        self.now = T0 + dt.timedelta(minutes=5)
        log = self.pub().monitor()
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["success"])
        self.assertTrue(any(l.startswith("posted") for l in log))
        self.assertTrue(self.dv.of("POST", PUB + "/")[0]["path"].endswith("/posted"))

    def test_monitor_refreshes_hourly_and_not_before(self) -> None:
        r = receipt("sha256:" + "c" * 64, "failure", "fail", posted_at="2026-11-08T07:06:00Z",
                    last_refresh_at="2026-11-08T07:06:00Z")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
        self.dv.routes[("POST", PUB)] = (200, {"action": "unchanged", "receipt": r})
        self.now = T0 + dt.timedelta(minutes=30)
        self.pub().monitor()
        self.assertEqual(self.dv.of("POST", PUB), [])
        self.now = T0 + dt.timedelta(minutes=62)
        self.pub().monitor()
        [call] = [c for c in self.dv.of("POST", PUB) if c["path"] == PUB]
        self.assertEqual(call["body"]["regression"], "nightly-7")
        self.assertEqual(call["body"]["target"], TARGET)
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["failure"])
        # --force after a nightly re-evaluates at once.
        self.now = T0 + dt.timedelta(minutes=63)
        self.pub().monitor(force=True)
        self.assertEqual(len([c for c in self.dv.of("POST", PUB) if c["path"] == PUB]), 2)

    def test_expired_validity_is_reevaluated_and_failure_replaces_success(self) -> None:
        r = receipt("sha256:" + "d" * 64, "success", "accepted_with_exceptions",
                    posted_at="2026-11-08T07:06:00Z", last_refresh_at="2026-11-28T06:30:00Z",
                    valid_until="2026-11-28T07:00:00Z", monitor_until="2026-11-28T07:00:00Z")
        new = receipt("sha256:" + "e" * 64, "failure", "fail")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
        self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": new})
        self.now = dt.datetime(2026, 11, 28, 7, 1, tzinfo=dt.timezone.utc)
        self.pub().monitor()
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["failure"])

    def test_expired_validity_with_failed_reevaluation_is_pending(self) -> None:
        r = receipt("sha256:" + "d" * 64, "success", "accepted_with_exceptions",
                    posted_at="2026-11-08T07:06:00Z", last_refresh_at="2026-11-28T06:30:00Z",
                    valid_until="2026-11-28T07:00:00Z", monitor_until="2026-11-28T07:00:00Z")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
        self.dv.routes[("POST", PUB)] = (503, {"code": "E_UNAVAILABLE"})
        self.now = dt.datetime(2026, 11, 28, 7, 1, tzinfo=dt.timezone.utc)
        log = self.pub().monitor()
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])
        self.assertTrue(any("re-evaluation failed" in l for l in log))

    def test_undated_success_ends_as_pending_then_retires_only_after_acceptance(self) -> None:
        r = receipt("sha256:" + "f" * 64, "success", "pass", posted_at="2026-10-24T07:06:00Z",
                    published_at="2026-10-24T07:05:00Z", monitor_until="2026-11-07T07:05:00Z")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
        # The code host refuses first: nothing is retired; the next pass retries.
        self.gh.routes[("POST", "/repos/")] = (502, {})
        self.pub().monitor()
        self.assertEqual(self.dv.of("POST", PUB + "/"), [])
        self.gh.routes[("POST", "/repos/")] = lambda path, body: (201, {"state": body["state"]})
        self.pub().monitor()
        last = self.gh.requests[-1]["body"]
        self.assertEqual(last["state"], "pending")
        self.assertTrue(last["description"].startswith(ps.ENDED))
        [ret] = self.dv.of("POST", PUB + "/")
        self.assertTrue(ret["path"].endswith("/retire"))
        self.assertEqual(ret["body"], {"reason": "monitoring_ended"})

    def test_undated_failure_retires_without_a_post(self) -> None:
        r = receipt("sha256:" + "9" * 64, "failure", "fail", posted_at="2026-10-24T07:06:00Z",
                    monitor_until="2026-11-07T07:05:00Z")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
        self.pub().monitor()
        self.assertEqual(self.gh.requests, [])
        self.assertTrue(self.dv.of("POST", PUB + "/")[0]["path"].endswith("/retire"))

    def test_only_the_newest_receipt_of_a_target_is_posted(self) -> None:
        # An older unposted success and a newer unposted failure (restart, any order).
        old = receipt("sha256:" + "1" * 64, "success", "pass", published_at="2026-11-08T07:05:00Z",
                      monitor_until="2026-11-08T08:00:00Z")
        new = receipt("sha256:" + "2" * 64, "failure", "fail", published_at="2026-11-08T07:30:00Z",
                      monitor_until="2026-11-22T07:30:00Z")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [old, new]})
        self.now = T0 + dt.timedelta(minutes=40)
        self.pub().monitor()
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["failure"])
        [posted] = self.dv.of("POST", PUB + "/")
        self.assertIn("2222222222", posted["path"])

    def test_a_fenced_post_is_repaired_with_the_newest_status(self) -> None:
        old = receipt("sha256:" + "1" * 64, "success", "pass")
        new = receipt("sha256:" + "2" * 64, "failure", "fail", posted_at="2026-11-08T07:30:00Z")
        answers = [(200, {"action": "post", "receipt": old}), (200, {"action": "unchanged", "receipt": new})]
        self.dv.routes[("POST", PUB)] = lambda path, body: answers.pop(0)

        def posted(path, body):
            if "1111111111" in path:
                return 409, {"code": "E_STALE_REVISION"}
            return 200, receipt("sha256:" + "2" * 64, body["state"], "fail", posted_at="2026-11-08T07:31:00Z")

        self.dv.routes[("POST", PUB + "/")] = posted
        out = self.pub().publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET))
        self.assertEqual(out["receipt"]["digest"], "sha256:" + "2" * 64)
        # The obsolete success was overwritten by the newest status.
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["success", "failure"])

    def test_server_outage_downgrades_overdue_successes_and_never_raises(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            r = receipt("sha256:" + "3" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z")
            self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
            p = self.pub()
            p.state_file = state
            self.now = T0 + dt.timedelta(minutes=10)
            p.monitor()
            self.assertTrue(state.exists())
            self.gh.requests.clear()
            # The server goes away; within the hour nothing is downgraded.
            self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.now = T0 + dt.timedelta(minutes=30)
            log = p.monitor()
            self.assertTrue(any("cannot list" in l for l in log))
            self.assertEqual(self.gh.requests, [])
            # Overdue: the success becomes pending, once.
            self.now = T0 + dt.timedelta(minutes=70)
            p.monitor()
            p.monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])
            self.assertIn("server unreachable", self.gh.requests[0]["body"]["description"])

    def test_redirects_are_never_followed(self) -> None:
        # Default urllib follows a GET 302 and forwards the Authorization header.
        other = Recorder()
        self.addCleanup(other.close)
        other.routes[("GET", "/")] = (200, {"publications": []})
        self.dv.routes[("GET", PUB)] = (302, {})
        self.dv.location = other.url + PUB
        log = self.pub().monitor()
        self.assertTrue(any("cannot list" in l for l in log), log)
        self.assertEqual(other.requests, [], "the token must not reach another origin")

    def _ledgered(self, d: str) -> ps.Publisher:
        p = self.pub()
        p.state_file = Path(d) / "ledger.json"
        return p

    def test_fenced_monitoring_post_is_repaired_even_after_retirement(self) -> None:
        # Another publisher retired this success; our cached post of it is fenced (409).
        stale = receipt("sha256:" + "5" * 64, "success", "pass")
        fresh = receipt("sha256:" + "6" * 64, "failure", "fail")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [stale]})
        self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": fresh})

        def posted(path, body):
            if "5555555555" in path:
                return 409, {"code": "E_STALE_REVISION"}
            return 200, receipt("sha256:" + "6" * 64, body["state"], "fail", posted_at="2026-11-08T07:31:00Z")

        self.dv.routes[("POST", PUB + "/")] = posted
        with tempfile.TemporaryDirectory() as d:
            log = self._ledgered(d).monitor()
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["success", "failure"], log)
        self.assertTrue(any(l.startswith("repaired") for l in log), log)

    def test_a_failed_downgrade_is_retried_until_the_host_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = self._ledgered(d)
            r = receipt("sha256:" + "7" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z")
            self.dv.routes[("GET", PUB)] = (200, {"publications": [r]})
            self.now = T0 + dt.timedelta(minutes=10)
            p.monitor()  # registers the success
            # Re-evaluation fails and the pending post fails too.
            self.dv.routes[("POST", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.gh.routes[("POST", "/repos/")] = (502, {})
            self.now = T0 + dt.timedelta(minutes=70)
            p.monitor()
            # DVIScope becomes unreachable; the code host recovers: the pending is re-sent.
            self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.gh.routes[("POST", "/repos/")] = lambda path, body: (201, {"state": body["state"]})
            self.gh.requests.clear()
            self.now = T0 + dt.timedelta(minutes=80)
            p.monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])
            entry = next(iter(p.ledger.entries().values()))
            self.assertEqual((entry["desired"]["state"], entry["acked"]), ("pending", True))

    def test_direct_publication_is_known_to_a_later_outage(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = self._ledgered(d)
            r = receipt("sha256:" + "8" * 64, "success", "pass")
            self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": r})
            self.dv.routes[("POST", PUB + "/")] = lambda path, body: (
                200, receipt("sha256:" + "8" * 64, "success", "pass", posted_at="2026-11-08T07:05:00Z",
                             last_refresh_at="2026-11-08T07:05:00Z"))
            p.publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET))
            # A restart later, the server unreachable before any monitoring pass.
            self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.gh.requests.clear()
            self.now = T0 + dt.timedelta(minutes=70)
            self._ledgered(d).monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])

    def test_ledger_updates_from_several_writers_all_survive(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            ledger = ps.Ledger(Path(d) / "ledger.json")

            def writer(i: int) -> None:
                for j in range(10):
                    ledger.update(f"t{i}-{j}", lambda e: e.__setitem__("n", 1))

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(len(ledger.entries()), 60)

    def test_a_crash_before_confirmation_is_reconciled_not_trusted(self) -> None:
        # A posted a (now obsolete) success, then crashed before the server confirmed it.
        with tempfile.TemporaryDirectory() as d:
            a = self._ledgered(d)
            digest = "sha256:" + "9" * 64
            a._host(dict(TARGET), "success", "Pass as of ...", "https://x/r", {
                "regression": "nightly-7", "producer": "ci", "expect_source": "sha256:" + "1" * 64,
                "published_at": "2026-11-08T07:05:00Z"}, digest=digest)
            # Healthy server, the receipt retired by another publisher: nothing open.
            self.dv.routes[("GET", PUB)] = (200, {"publications": [], "next": None})
            self.dv.routes[("POST", PUB + "/")] = (409, {"code": "E_STALE_REVISION"})
            fresh = receipt("sha256:" + "a" * 64, "failure", "fail")
            self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": fresh})

            def posted(path, body):
                if "9999999999" in path:
                    return 409, {"code": "E_STALE_REVISION"}
                return 200, receipt("sha256:" + "a" * 64, body["state"], "fail", posted_at="2026-11-08T07:31:00Z")

            self.dv.routes[("POST", PUB + "/")] = posted
            self.gh.requests.clear()
            log = self._ledgered(d).monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["failure"], log)
            entry = next(iter(self._ledgered(d).ledger.entries().values()))
            self.assertEqual(entry["desired"]["state"], "failure")
            self.assertTrue(entry["confirmed"] and entry["acked"])

    def test_an_unconfirmed_success_is_downgraded_in_an_outage(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            a = self._ledgered(d)
            a._host(dict(TARGET), "success", "Pass as of ...", None, {
                "published_at": "2026-11-08T07:05:00Z", "last_refresh_at": "2026-11-08T07:05:00Z"},
                digest="sha256:" + "b" * 64)
            self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.gh.requests.clear()
            self.now = T0 + dt.timedelta(minutes=1)  # not overdue: unconfirmed is enough
            self._ledgered(d).monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])

    def test_every_inventory_page_is_read(self) -> None:
        r1 = receipt("sha256:" + "c" * 64, "failure", "fail")
        r2 = dict(receipt("sha256:" + "d" * 64, "failure", "fail"),
                  target={"repository": "o/r", "commit": "b" * 40, "context": "dviscope/merge"})

        def listing(path, body):
            if "after=" in path:
                return 200, {"publications": [r2], "next": None}
            return 200, {"publications": [r1], "next": "123.sha256:x"}

        self.dv.routes[("GET", PUB)] = listing
        self.pub().monitor()
        commits = sorted(x["path"].rsplit("/", 1)[1][:1] for x in self.gh.requests)
        self.assertEqual(commits, ["a", "b"])

    def test_retirement_and_publication_never_interleave(self) -> None:
        # B retires an undated success while A tries to post that same (cached) success.
        stale = receipt("sha256:" + "e" * 64, "success", "pass", posted_at="2026-10-24T07:06:00Z",
                        monitor_until="2026-11-07T07:05:00Z")
        fresh = receipt("sha256:" + "f" * 64, "failure", "fail")
        retired = {"v": False}

        def retire(path, body):
            retired["v"] = True
            return 200, dict(stale, retired_reason="monitoring_ended")

        def posted(path, body):
            if path.endswith("/retire"):
                return retire(path, body)
            if "eeeeeeeeee" in path:
                return (409, {"code": "E_STALE_REVISION"}) if retired["v"] else (200, stale)
            return 200, receipt("sha256:" + "f" * 64, body["state"], "fail", posted_at="2026-11-08T07:31:00Z")

        self.dv.routes[("POST", PUB + "/")] = posted
        self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": fresh})
        with tempfile.TemporaryDirectory() as d:
            a, b = self._ledgered(d), self._ledgered(d)
            started = threading.Event()
            box: dict = {}

            def gh(path, body):
                if body["state"] == "pending" and not started.is_set():
                    started.set()
                    # A tries to post the stale success while B is mid-retirement.
                    t = threading.Thread(target=lambda: box.setdefault("a", self._try(a, stale)))
                    t.start()
                    box["t"] = t
                    t.join(0.5)
                    box["blocked"] = t.is_alive()
                return 201, {"state": body["state"]}

            self.gh.routes[("POST", "/repos/")] = gh
            b._retire(dict(TARGET), stale)
            box["t"].join(10)
        self.assertTrue(box["blocked"], "A must wait for B's whole retirement")
        states = [x["body"]["state"] for x in self.gh.requests]
        # B's pending, then A's obsolete success, then A's repair: never left green.
        self.assertEqual(states, ["pending", "success", "failure"], states)

    @staticmethod
    def _try(p, r):
        try:
            return p._post_receipt(r)
        except ps.PublishError as e:
            if e.status == 409:
                return p._repair(dict(TARGET), {"regression": "nightly-7", "producer": "ci",
                                                "expect_source": "sha256:" + "1" * 64})
            raise

    def test_a_publisher_never_recovers_another_projects_entry(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            a = self._ledgered(d)
            a._host(dict(TARGET), "failure", "Fail as of ...", None, {
                "regression": "nightly-7", "expect_source": "sha256:" + "1" * 64}, digest="sha256:" + "0" * 64)
            b = self._ledgered(d)
            b.project = "beta"
            self.dv.routes[("GET", "/api/v1/projects/beta/readiness/publications")] = (
                200, {"publications": [], "next": None})
            self.gh.requests.clear()
            b.monitor()
            self.assertEqual(self.gh.requests, [])
            self.assertEqual([r for r in self.dv.requests if r["method"] == "POST"], [])

    def test_refresh_and_repair_keep_the_producer(self) -> None:
        r = receipt("sha256:" + "1" * 64, "failure", "fail", posted_at="2026-11-08T07:06:00Z",
                    last_refresh_at="2026-11-08T07:06:00Z", producer="ci-a")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
        self.dv.routes[("POST", PUB)] = (200, {"action": "unchanged", "receipt": r})
        self.now = T0 + dt.timedelta(minutes=70)
        self.pub().monitor()
        [call] = [c for c in self.dv.of("POST", PUB) if c["path"] == PUB]
        self.assertEqual(call["body"]["producer"], "ci-a")

    def test_legacy_ledger_entries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger.json"
            key = "|".join((TARGET["repository"], TARGET["commit"], TARGET["context"]))
            path.write_text(json.dumps({"targets": {key: {
                "target": dict(TARGET),
                "desired": {"state": "success", "description": "Pass", "url": None, "digest": "sha256:x"},
                "acked": True, "confirmed": True, "info": {}}}}), encoding="utf-8")
            self.dv.routes[("GET", PUB)] = (200, {"publications": [], "next": None})
            p = self._ledgered(d)
            p.monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])
            self.assertIn("publisher upgraded", self.gh.requests[0]["body"]["description"])
            self.assertNotIn(key, p.ledger.entries())
            # Also during an outage.
            path.write_text(json.dumps({"targets": {key: {
                "target": dict(TARGET),
                "desired": {"state": "success", "description": "Pass", "url": None},
                "acked": True, "info": {}}}}), encoding="utf-8")
            self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.gh.requests.clear()
            p.monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])

    def test_unacknowledged_legacy_downgrades_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger.json"
            key = "|".join((TARGET["repository"], TARGET["commit"], TARGET["context"]))
            for state in ("failure", "error"):
                path.write_text(json.dumps({"targets": {key: {
                    "target": dict(TARGET),
                    "desired": {"state": state, "description": "x", "url": None},
                    "acked": False, "info": {}}}}), encoding="utf-8")
                self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
                self.gh.requests.clear()
                p = self._ledgered(d)
                p.monitor()
                self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"], state)
                self.assertNotIn(key, p.ledger.entries())

    def test_repair_without_a_recorded_producer_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            a = self._ledgered(d)
            # A namespaced entry from before producers were recorded, unconfirmed.
            a._host(dict(TARGET), "failure", "Fail", None, {
                "regression": "nightly-7", "expect_source": "sha256:" + "1" * 64},
                digest="sha256:" + "2" * 64)
            self.dv.routes[("GET", PUB)] = (200, {"publications": [], "next": None})
            self.dv.routes[("POST", PUB + "/")] = (409, {"code": "E_STALE_REVISION"})
            self.gh.requests.clear()
            a.monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])
            self.assertEqual([c for c in self.dv.of("POST", PUB) if c["path"] == PUB], [],
                             "no unqualified re-evaluation")

    def test_a_fenced_retry_uses_the_receipts_producer(self) -> None:
        # Published without --producer; the server resolved producer "ci-a".
        first = dict(receipt("sha256:" + "3" * 64, "failure", "fail"), producer="ci-a")
        newer = dict(receipt("sha256:" + "4" * 64, "failure", "fail", posted_at="2026-11-08T07:31:00Z"),
                     producer="ci-a")
        answers = [(200, {"action": "post", "receipt": first}), (200, {"action": "unchanged", "receipt": newer})]
        self.dv.routes[("POST", PUB)] = lambda path, body: answers.pop(0)
        self.dv.routes[("POST", PUB + "/")] = lambda path, body: (
            (409, {"code": "E_STALE_REVISION"}) if "3333333333" in path else (200, newer))
        self.pub().publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET))
        calls = [c for c in self.dv.of("POST", PUB) if c["path"] == PUB]
        self.assertNotIn("producer", calls[0]["body"])
        self.assertEqual(calls[1]["body"]["producer"], "ci-a")

    def test_an_unconfirmable_overdue_success_is_never_replayed(self) -> None:
        for valid_until, monitor_until in [("2026-11-08T08:00:00Z", "2026-11-08T08:00:00Z"),
                                           (None, "2026-11-08T08:00:00Z")]:
            self.gh.requests.clear()
            r = receipt("sha256:" + "5" * 64, "success", "pass", valid_until=valid_until,
                        monitor_until=monitor_until)
            self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
            self.dv.routes[("POST", PUB + "/")] = (503, {"code": "E_UNAVAILABLE"})
            self.dv.routes[("POST", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            with tempfile.TemporaryDirectory() as d:
                p = self._ledgered(d)
                for h in range(3):
                    self.now = T0 + dt.timedelta(hours=2 + h)
                    p.monitor()
            states = [x["body"]["state"] for x in self.gh.requests]
            self.assertNotIn("success", states, (valid_until, states))
            self.assertIn("pending", states)

    def test_a_posted_success_past_its_validity_is_reevaluated(self) -> None:
        # Refreshed at 07:05, valid until 07:10; monitoring at 07:20 (well
        # before the hourly refresh) must evaluate again.
        r = receipt("sha256:" + "7" * 64, "success", "pass", posted_at="2026-11-08T07:05:00Z",
                    last_refresh_at="2026-11-08T07:05:00Z", valid_until="2026-11-08T07:10:00Z")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
        newer = receipt("sha256:" + "8" * 64, "failure", "fail")
        self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": newer})
        self.dv.routes[("POST", PUB + "/")] = (200, newer)
        self.now = T0 + dt.timedelta(minutes=15)
        with tempfile.TemporaryDirectory() as d:
            self._ledgered(d).monitor()
        evaluations = [c for c in self.dv.of("POST", PUB) if c["path"] == PUB]
        self.assertEqual(len(evaluations), 1, self.dv.requests)

    def test_a_success_the_server_cannot_confirm_becomes_pending(self) -> None:
        r = receipt("sha256:" + "6" * 64, "success", "pass")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
        self.dv.routes[("POST", PUB + "/")] = (503, {"code": "E_UNAVAILABLE"})
        self.now = T0 + dt.timedelta(minutes=5)
        with tempfile.TemporaryDirectory() as d:
            self._ledgered(d).monitor()
        self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["success", "pending"])

    def test_retry_never_replays_an_expired_success(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            a = self._ledgered(d)
            # An unacknowledged success (the host write failed) recorded before a restart.
            self.gh.routes[("POST", "/repos/")] = (502, {})
            with self.assertRaises(ps.PublishError):
                a._host(dict(TARGET), "success", "Pass", None, {
                    "regression": "nightly-7", "producer": "ci", "expect_source": "sha256:" + "1" * 64,
                    "published_at": "2026-11-08T07:05:00Z", "valid_until": "2026-11-08T08:00:00Z",
                    "monitor_until": "2026-11-08T08:00:00Z"}, digest="sha256:" + "7" * 64)
            # Hours later: the host is back, the server fails every evaluation.
            self.gh.routes[("POST", "/repos/")] = lambda path, body: (201, {"state": body["state"]})
            self.gh.requests.clear()
            self.dv.routes[("GET", PUB)] = (200, {"publications": [], "next": None})
            self.dv.routes[("POST", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.dv.routes[("POST", PUB + "/")] = (503, {"code": "E_UNAVAILABLE"})
            for h in range(3):
                self.now = T0 + dt.timedelta(hours=2 + h)
                self._ledgered(d).monitor()
            states = [x["body"]["state"] for x in self.gh.requests]
            self.assertNotIn("success", states, states)
            self.assertIn("pending", states)

    def test_a_malformed_reevaluation_sets_pending_and_monitoring_continues(self) -> None:
        for broken in ("target", "receipt_path", "description"):
            self.gh.requests.clear()
            r = receipt("sha256:" + "8" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z", valid_until="2026-11-08T08:00:00Z",
                        monitor_until="2026-11-08T08:00:00Z")
            bad = receipt("sha256:" + "9" * 64, "failure", "fail")
            if broken == "description":
                del bad["status"]["description"]
            else:
                del bad[broken]
            self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
            self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": bad})
            with tempfile.TemporaryDirectory() as d:
                p = self._ledgered(d)
                for h in range(3):
                    self.now = T0 + dt.timedelta(hours=2 + h)
                    p.monitor()
            states = [x["body"]["state"] for x in self.gh.requests]
            self.assertNotIn("success", states, (broken, states))
            self.assertIn("pending", states, broken)

    def test_an_outage_respects_the_monitoring_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = self._ledgered(d)
            r = receipt("sha256:" + "a" * 64, "success", "pass", posted_at="2026-11-08T06:00:00Z",
                        last_refresh_at="2026-11-08T07:00:00Z", monitor_until="2026-11-08T07:05:00Z")
            self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
            self.now = T0 - dt.timedelta(minutes=1)  # 07:04, refreshed at 07:00
            p.monitor()
            self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.gh.requests.clear()
            self.now = T0 + dt.timedelta(minutes=5)  # 07:10: monitoring ended, refresh not due
            p.monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"])

    def test_a_malformed_confirmation_sets_pending(self) -> None:
        # A 200 /posted answer that is null or carries unreadable times.
        good = receipt("sha256:" + "b" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z")
        for answer in (None, dict(good, posted_at="not a time"), dict(good, posted_at="2026-11-08T07:06:00"),
                       dict(good, published_at=7)):
            for path in ("publish", "monitor"):
                self.gh.requests.clear()
                r = receipt("sha256:" + "b" * 64, "success", "pass")
                self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": r})
                self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
                self.dv.routes[("POST", PUB + "/")] = (200, answer)
                with tempfile.TemporaryDirectory() as d:
                    p = self._ledgered(d)
                    if path == "publish":
                        with self.assertRaises(ps.PublishError):
                            p.publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET), producer="ci")
                    else:
                        p.monitor()
                states = [x["body"]["state"] for x in self.gh.requests]
                self.assertEqual(states[-1], "pending", (answer, path, states))

    def test_unreadable_ledger_times_fail_closed_in_an_outage(self) -> None:
        # Naive or garbled deadlines in the ledger are overdue; a broken entry
        # never stops the others from being downgraded.
        other = dict(TARGET, context="dviscope/other")
        with tempfile.TemporaryDirectory() as d:
            p = self._ledgered(d)
            a = receipt("sha256:" + "c" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z")
            b = receipt("sha256:" + "d" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z", target=dict(other))
            self.dv.routes[("GET", PUB)] = (200, {"publications": [a, b], "next": None})
            self.now = T0 + dt.timedelta(minutes=2)
            p.monitor()
            doc = json.loads(p.state_file.read_text(encoding="utf-8"))
            for key, e in doc["targets"].items():
                if key.endswith("dviscope/merge"):
                    e["info"] = "garbled"  # sorts first: must not stop the next entry
                else:
                    e["info"]["last_refresh_at"] = "2026-11-08T07:06:00"
                    e["info"]["posted_at"] = "2026-11-08T07:06:00"
            # A corrupt entry first in the ledger: it must not stop the others.
            [first] = [e for k, e in doc["targets"].items() if k.endswith("dviscope/merge")]
            doc["targets"] = {"corrupt": dict(first, target=["not", "a", "target"]), **doc["targets"]}
            p.state_file.write_text(json.dumps(doc), encoding="utf-8")
            self.dv.routes[("GET", PUB)] = (503, {"code": "E_UNAVAILABLE"})
            self.gh.requests.clear()
            self.now = T0 + dt.timedelta(minutes=10)  # nothing is due by the readable times
            p.monitor()
            downgraded = sorted((x["body"]["context"], x["body"]["state"]) for x in self.gh.requests)
            self.assertEqual(downgraded, [("dviscope/merge", "pending"), ("dviscope/other", "pending")])

    def test_a_malformed_inventory_entry_never_blocks_the_others(self) -> None:
        # One entry without a target must not stop the pass; successes it might
        # hide become pending.
        other = dict(TARGET, context="dviscope/other")
        with tempfile.TemporaryDirectory() as d:
            p = self._ledgered(d)
            a = receipt("sha256:" + "e" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z", valid_until="2026-11-08T08:00:00Z")
            b = receipt("sha256:" + "f" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z", target=dict(other))
            self.dv.routes[("GET", PUB)] = (200, {"publications": [a, b], "next": None})
            self.now = T0 + dt.timedelta(minutes=2)
            p.monitor()
            # Later: a's validity has ended (its re-evaluation fails); b comes back malformed.
            broken = dict(b)
            del broken["target"]
            fail = receipt("sha256:" + "0" * 64, "failure", "fail")
            self.dv.routes[("GET", PUB)] = (200, {"publications": [broken, a], "next": None})
            self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": fail})
            self.gh.requests.clear()
            self.now = T0 + dt.timedelta(hours=2)
            log = p.monitor()
            by_context = {}
            for x in self.gh.requests:
                by_context.setdefault(x["body"]["context"], []).append(x["body"]["state"])
            self.assertEqual(by_context.get("dviscope/merge"), ["failure"], log)
            self.assertEqual(by_context.get("dviscope/other"), ["pending"], log)

    def test_a_malformed_entry_with_a_target_sets_that_target_pending(self) -> None:
        # With no ledger (a restart, another machine), a posted success whose
        # inventory entry is malformed but names its target must not stay green.
        other = dict(TARGET, context="dviscope/other")
        for broken in ("receipt_path", "published_at", "status", "valid_until"):
            self.gh.requests.clear()
            r = receipt("sha256:" + "1" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z")
            if broken == "valid_until":
                r["valid_until"] = "tomorrow"
            else:
                del r[broken]
            fine = receipt("sha256:" + "2" * 64, "failure", "fail", target=dict(other))
            self.targets[fine["digest"]] = other
            self.dv.routes[("GET", PUB)] = (200, {"publications": [r, fine], "next": None})
            with tempfile.TemporaryDirectory() as d:
                p = self._ledgered(d)
                for h in range(3):
                    self.now = T0 + dt.timedelta(hours=h)
                    p.monitor()
            merge = [x["body"]["state"] for x in self.gh.requests if x["body"]["context"] == "dviscope/merge"]
            others = [x["body"]["state"] for x in self.gh.requests if x["body"]["context"] == "dviscope/other"]
            self.assertEqual(merge, ["pending"], broken)  # once: then it is known to be pending
            self.assertEqual(others[:1], ["failure"], broken)

    def test_a_confirmation_for_another_receipt_is_rejected(self) -> None:
        # Found while fixing r11: the ledger recorded a confirmation under the target the
        # answer named, overwriting another target's entry.
        other = dict(TARGET, context="dviscope/other")
        with tempfile.TemporaryDirectory() as d:
            p = self._ledgered(d)
            a = receipt("sha256:" + "5" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z")
            self.dv.routes[("GET", PUB)] = (200, {"publications": [a], "next": None})
            p.monitor()
            b = receipt("sha256:" + "6" * 64, "failure", "fail", target=dict(other))
            self.dv.routes[("GET", PUB)] = (200, {"publications": [a, b], "next": None})
            # The server answers b's confirmation with a's target (or another digest).
            for wrong in (dict(b, target=dict(TARGET)), dict(b, digest=a["digest"]), dict(b, status=a["status"])):
                self.dv.routes[("POST", PUB + "/")] = (200, dict(wrong, posted_at="2026-11-08T07:06:00Z"))
                self.now += dt.timedelta(minutes=1)
                p.monitor()
                doc = json.loads(p.state_file.read_text(encoding="utf-8"))
                [mine] = [e for k, e in doc["targets"].items() if k.endswith("dviscope/merge")]
                self.assertEqual(mine["desired"]["digest"], a["digest"], wrong)
                self.assertEqual(mine["desired"]["state"], "success", wrong)

    def test_a_malformed_entry_with_any_valid_context_sets_pending(self) -> None:
        # Contexts the server accepts, `|` included, are recovered after a restart.
        for context in ("ci | dviscope", "a|b|c", "x"):
            self.gh.requests.clear()
            target = dict(TARGET, context=context)
            r = receipt("sha256:" + "7" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z", target=dict(target))
            del r["receipt_path"]
            self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
            with tempfile.TemporaryDirectory() as d:
                p = self._ledgered(d)
                for h in range(3):
                    self.now = T0 + dt.timedelta(hours=h)
                    p.monitor()
            self.assertEqual([(x["body"]["context"], x["body"]["state"]) for x in self.gh.requests],
                             [(context, "pending")], context)

    def test_a_failed_later_page_keeps_what_earlier_pages_showed(self) -> None:
        # Page 1 lists expired posted successes, page 2 fails; with an empty
        # ledger (a restart) the successes must still become pending.
        contexts = ["dviscope/a", "dviscope/b", "dviscope/c"]
        page1 = [receipt("sha256:" + str(i + 1) * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                         last_refresh_at="2026-11-08T07:06:00Z", valid_until="2026-11-08T08:00:00Z",
                         target=dict(TARGET, context=c)) for i, c in enumerate(contexts)]
        broken = receipt("sha256:" + "9" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                         target=dict(TARGET, context="dviscope/d"))
        del broken["receipt_path"]
        page1.append(broken)
        contexts.append("dviscope/d")
        for page2 in ((503, {"code": "E_UNAVAILABLE"}), (200, {"publications": [], "next": None}, "truncate"),
                      (200, {"publications": 5}), (200, [1]), (200, {"publications": [], "next": 7})):
            self.gh.requests.clear()

            def inventory(path, body, page2=page2):
                return page2 if "after=" in path else (200, {"publications": page1, "next": "p2"})

            self.dv.routes[("GET", PUB)] = inventory
            with tempfile.TemporaryDirectory() as d:
                p = self._ledgered(d)
                for h in range(3):
                    self.now = T0 + dt.timedelta(hours=2 + h)
                    p.monitor()
            sent = sorted((x["body"]["context"], x["body"]["state"]) for x in self.gh.requests)
            self.assertEqual(sent, [(c, "pending") for c in contexts], page2)

    def _partial(self, page1: list, page2: tuple) -> None:
        def inventory(path, body):
            return page2 if "after=" in path else (200, {"publications": page1, "next": "p2"})

        self.dv.routes[("GET", PUB)] = inventory

    PAGE2_FAILURES = ((503, {"code": "E_UNAVAILABLE"}), (200, {"publications": [], "next": None}, "truncate"),
                      (200, {"publications": 5}))

    def test_an_unposted_newer_receipt_never_hides_a_visible_success(self) -> None:
        # Page 1 holds an overdue posted success and a newer unposted failure.
        for page2 in self.PAGE2_FAILURES:
            self.gh.requests.clear()
            ok = receipt("sha256:" + "1" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                         last_refresh_at="2026-11-08T07:06:00Z", valid_until="2026-11-08T08:00:00Z")
            newer = receipt("sha256:" + "2" * 64, "failure", "fail", published_at="2026-11-08T09:00:00Z")
            self._partial([newer, ok], page2)
            with tempfile.TemporaryDirectory() as d:
                p = self._ledgered(d)
                for h in range(3):
                    self.now = T0 + dt.timedelta(hours=3 + h)
                    p.monitor()
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"], page2)

    def test_an_unconfirmed_success_on_an_incomplete_inventory_is_downgraded(self) -> None:
        # Never confirmed as posted (a publisher may have written it to the host, then
        # stopped): not vouched for even while fresh. A fresh posted one stands.
        for page2 in self.PAGE2_FAILURES:
            self.gh.requests.clear()
            unposted = receipt("sha256:" + "5" * 64, "success", "pass")
            fresh = receipt("sha256:" + "6" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                            last_refresh_at="2026-11-08T07:06:00Z", target=dict(TARGET, context="dviscope/fresh"))
            self._partial([unposted, fresh], page2)
            self.now = T0 + dt.timedelta(minutes=10)
            with tempfile.TemporaryDirectory() as d:
                self._ledgered(d).monitor()
            self.assertEqual([(x["body"]["context"], x["body"]["state"]) for x in self.gh.requests],
                             [("dviscope/merge", "pending")], page2)

    def test_a_success_posted_elsewhere_is_downgraded_whatever_the_ledger_says(self) -> None:
        # This ledger last wrote failure (or pending); another publisher posted a
        # success since. Seen overdue on an incomplete inventory, it must become pending.
        for earlier in ("failure", "pending"):
            for page2 in self.PAGE2_FAILURES:
                self.gh.requests.clear()
                with tempfile.TemporaryDirectory() as d:
                    p = self._ledgered(d)
                    self.now = T0
                    if earlier == "failure":
                        f = receipt("sha256:" + "3" * 64, "failure", "fail", posted_at="2026-11-08T07:06:00Z",
                                    last_refresh_at="2026-11-08T07:06:00Z")
                        self.dv.routes[("GET", PUB)] = (200, {"publications": [f], "next": None})
                        p.monitor()
                    else:
                        self.dv.routes[("POST", PUB)] = (503, {"code": "E_UNAVAILABLE"})
                        with self.assertRaises(ps.PublishError):
                            p.publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET), producer="ci")
                    self.gh.requests.clear()
                    elsewhere = receipt("sha256:" + "4" * 64, "success", "pass", published_at="2026-11-08T08:00:00Z",
                                        posted_at="2026-11-08T08:01:00Z", last_refresh_at="2026-11-08T08:01:00Z",
                                        valid_until="2026-11-08T09:00:00Z")
                    self._partial([elsewhere], page2)
                    for h in range(3):
                        self.now = T0 + dt.timedelta(hours=3 + h)
                        p.monitor()
                    self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"], (earlier, page2))
                    # Refreshed again elsewhere: newly seen, so pending is written again.
                    self._partial([dict(elsewhere, last_refresh_at="2026-11-08T10:30:00Z")], page2)
                    self.now = T0 + dt.timedelta(hours=6)
                    p.monitor()
                    self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending", "pending"])

    def test_targets_are_compared_without_case(self) -> None:
        # GitHub compares repositories and contexts without case; an older
        # unposted success of a case variant must not be posted over a newer failure.
        variant = {"repository": "HexkDotCom/DVIScope-dev", "commit": "A" * 40, "context": "DVIScope/Merge"}
        old = receipt("sha256:" + "7" * 64, "success", "pass", target=dict(variant))
        new = receipt("sha256:" + "8" * 64, "failure", "fail", published_at="2026-11-08T07:30:00Z",
                      posted_at="2026-11-08T07:31:00Z", last_refresh_at="2026-11-08T07:31:00Z")
        self.dv.routes[("GET", PUB)] = (200, {"publications": [old, new], "next": None})
        self.now = T0 + dt.timedelta(minutes=40)
        with tempfile.TemporaryDirectory() as d:
            self._ledgered(d).monitor()
        self.assertNotIn("success", [x["body"]["state"] for x in self.gh.requests], self.gh.requests)

    def test_ledger_entries_under_old_key_spellings_are_rekeyed(self) -> None:
        # An unacknowledged pending under a mixed-case key (written before
        # targets compared without case) is not replayed on every pass.
        with tempfile.TemporaryDirectory() as d:
            p = self._ledgered(d)
            mixed = dict(TARGET, context="DVIScope/Merge")
            old_key = "|".join((p.dv.base, "alpha", mixed["repository"], mixed["commit"], mixed["context"]))
            p.state_file.write_text(json.dumps({"targets": {old_key: {
                "server": p.dv.base, "project": "alpha", "target": mixed,
                "desired": {"state": "pending", "description": "x", "url": None, "digest": None, "gen": "g"},
                "acked": False, "confirmed": True}}}), encoding="utf-8")
            f = receipt("sha256:" + "9" * 64, "failure", "fail", posted_at="2026-11-08T07:06:00Z",
                        last_refresh_at="2026-11-08T07:06:00Z")
            self.dv.routes[("GET", PUB)] = (200, {"publications": [f], "next": None})
            for m in range(3):
                self.now = T0 + dt.timedelta(minutes=5 + m)
                p.monitor()
            states = [x["body"]["state"] for x in self.gh.requests]
            self.assertLessEqual(states.count("pending"), 1, states)
            doc = json.loads(p.state_file.read_text(encoding="utf-8"))
            self.assertEqual([k for k in doc["targets"] if k != k.lower() and k.endswith("Merge")], [], doc)

    def test_truncated_responses_are_failures(self) -> None:
        # A connection closing before Content-Length raises IncompleteRead.
        for status in (200, 503):
            # Inventory: an outage, so an overdue success is downgraded and nothing raises.
            with tempfile.TemporaryDirectory() as d:
                p = self._ledgered(d)
                r = receipt("sha256:" + "3" * 64, "success", "pass", posted_at="2026-11-08T07:06:00Z",
                            last_refresh_at="2026-11-08T07:06:00Z")
                self.dv.routes[("GET", PUB)] = (200, {"publications": [r], "next": None})
                self.now = T0 + dt.timedelta(minutes=2)
                p.monitor()
                self.gh.requests.clear()
                self.dv.routes[("GET", PUB)] = (status, {"publications": [r], "next": None}, "truncate")
                self.now = T0 + dt.timedelta(minutes=70)
                log = p.monitor()
                self.assertTrue(any("cannot list" in l for l in log), (status, log))
                self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["pending"], status)
            # Confirmation: the posted success becomes pending.
            self.gh.requests.clear()
            fresh = receipt("sha256:" + "4" * 64, "success", "pass")
            self.dv.routes[("POST", PUB)] = (200, {"action": "post", "receipt": fresh})
            self.dv.routes[("POST", PUB + "/")] = (status, dict(fresh, posted_at="2026-11-08T07:06:00Z"), "truncate")
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ps.PublishError):
                    self._ledgered(d).publish("nightly-7", "sha256:" + "1" * 64, dict(TARGET), producer="ci")
            self.assertEqual([x["body"]["state"] for x in self.gh.requests], ["success", "pending"], status)

    def test_urls_and_tokens(self) -> None:
        with self.assertRaises(ps.PublishError):
            ps.Http("http://example.com", "t")
        ps.Http("http://127.0.0.1:1", "t")
        ps.Http("https://api.github.com", "t")
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "tok"
            f.write_text("one\ntwo\n")
            with self.assertRaises(ps.PublishError):
                ps._token(str(f))
            f.write_text(GH_TOKEN + "\n")
            self.assertEqual(ps._token(str(f)), GH_TOKEN)

    def test_cli_never_prints_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dv_tok, gh_tok = Path(d) / "dv", Path(d) / "gh"
            dv_tok.write_text(DV_TOKEN)
            gh_tok.write_text(GH_TOKEN)
            self.dv.routes[("POST", PUB)] = (500, {"code": "E_INTERNAL"})
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = ps.main([
                    "--server", self.dv.url, "--token-file", str(dv_tok),
                    "--github-api", self.gh.url, "--github-token-file", str(gh_tok),
                    "--project", "alpha", "publish", "--regression", "nightly-7",
                    "--repo", TARGET["repository"], "--commit", TARGET["commit"],
                    "--expect-source", "sha256:" + "1" * 64,
                ])
            self.assertEqual(code, 4)
            text = out.getvalue() + err.getvalue()
            self.assertNotIn(DV_TOKEN, text)
            self.assertNotIn(GH_TOKEN, text)
            self.assertIn("pending", text)


if __name__ == "__main__":
    unittest.main()
