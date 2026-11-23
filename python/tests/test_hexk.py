"""Tests of the hexk adapter with invented lists, fake processes and files. With
``DVISCOPE_BIN`` set, the generated records are also checked by the real collector."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dviscope_hexk import lists, manifest, questa  # noqa: E402
from dviscope_hexk.driver import MANIFEST, Driver, Plan  # noqa: E402

REGRESSION = """\
# invented list in the hexk format
alpha_test  | 1 | +mode=a +n=3 | PASSED |
alpha_test  | 2 |              | PASSED | W_NOISE:W:2
beta_test   | 3 |              | FAILED | B_DONE:E:1 B_TIMEOUT:E:1 match=B_TIMEOUT\\s+env
gamma_test  | 4 |              | NONE   | G_DOG:F:1 match=no\\sbeat
"""

CORE = """\
# suite simulators count message
unit_a   all             1  unit_a::f: bad width 0
unit_a   all             2  unit_a::g: index 9 is out of range
unit_b   questa,vcs      1  unit_b::h: null model
"""

UVM = """\
unit_a   all        UVM_ERROR  UA_EXPECTED  3
unit_b   verilator  UVM_FATAL  UB_STOP      1
"""


class Lists(unittest.TestCase):
    def test_regression_rows(self):
        runs = lists.parse_regression(REGRESSION)
        self.assertEqual([r.verdict for r in runs], ["PASSED", "PASSED", "FAILED", "NONE"])
        self.assertEqual(runs[0].plusargs, ("+mode=a", "+n=3"))
        self.assertEqual(runs[2].expects[1], lists.Expect("uvm:B_TIMEOUT", "error", 1))
        self.assertEqual(runs[2].matches, ("B_TIMEOUT\\s+env",))
        self.assertEqual(runs[3].line, 5)

    def test_malformed_lines_name_their_line(self):
        for text, needle in [
            ("t | x | | PASSED |\n", "seed"),
            ("t | 1 | | MAYBE |\n", "verdict"),
            ("t | 1 | | FAILED | X:Q:1\n", "ID:W|E|F:count"),
            ("t | 1 | | FAILED |\n", "needs an expected error"),
            ("t | 1 | | NONE | X:E:1\n", "needs an expected fatal"),
            ("t | 1 | PASSED\n", "5 columns"),
        ]:
            with self.assertRaises(lists.ListError) as e:
                lists.parse_regression("# header\n" + text, "reg.txt")
            self.assertIn("reg.txt:2", str(e.exception))
            self.assertIn(needle, str(e.exception))

    def test_error_lists(self):
        core = lists.parse_core_errors(CORE)
        self.assertEqual(len(core), 3)
        self.assertEqual(core[2].simulators, frozenset({"questa", "vcs"}))
        uvm = lists.parse_uvm_errors(UVM)
        self.assertEqual(uvm[1].severity, "fatal")
        with self.assertRaises(lists.ListError):
            lists.parse_uvm_errors("s all UVM_INFO X 1\n")
        with self.assertRaises(lists.ListError):
            lists.parse_core_errors("s xcelium 1 msg\n")


class Manifest(unittest.TestCase):
    def test_regression_expectations(self):
        slots = manifest.regression_slots(lists.parse_regression(REGRESSION))
        self.assertNotIn("expected", slots[0])
        self.assertEqual(slots[1]["expected"]["verdict"], "pass")
        self.assertEqual(
            slots[2]["expected"]["diagnostics"],
            [
                {"diag_id": "uvm:B_DONE", "severity": "error", "count": 1},
                {"diag_id": "uvm:B_TIMEOUT", "severity": "error", "count": 1},
            ],
        )
        self.assertEqual(slots[3]["expected"]["verdict"], "fail")
        self.assertEqual(slots[3]["slot_ref"], "gamma_test.s4")
        with self.assertRaises(ValueError):
            manifest.regression_slots(lists.parse_regression(REGRESSION + "alpha_test | 1 | | PASSED |\n"))

    def test_suites_per_simulator(self):
        errors = lists.parse_core_errors(CORE) + lists.parse_uvm_errors(UVM)
        # Core $error messages have no identity of their own: such suites are refused...
        with self.assertRaises(manifest.UnrepresentableExpectations) as e:
            manifest.suite_slots(["unit_a", "unit_b", "unit_c"], errors, "questa")
        self.assertEqual(e.exception.suites, ["unit_a", "unit_b"])
        # ...or explicitly left out (never declared without their expectations).
        q = {s["slot_ref"]: s for s in manifest.suite_slots(
            ["unit_a", "unit_b", "unit_c"], errors, "questa", skip_unrepresentable=True)}
        self.assertEqual(sorted(q), ["unit.unit_c"])
        self.assertEqual(
            sorted((e.suite, e.count) for e in manifest.unrepresented(errors, "questa")),
            [("unit_a", 1), ("unit_a", 2), ("unit_b", 1)],
        )
        self.assertNotIn("expected", q["unit.unit_c"])
        v = {s["slot_ref"]: s for s in manifest.suite_slots(
            ["unit_a", "unit_b"], errors, "verilator", skip_unrepresentable=True)}
        self.assertEqual(
            v["unit.unit_b"]["expected"]["diagnostics"],
            [{"diag_id": "uvm:UB_STOP", "severity": "fatal", "count": 1}],
        )
        self.assertNotIn("unit.unit_a", v)
        with self.assertRaises(ValueError):
            manifest.suite_slots(["unit_c"], lists.parse_uvm_errors(UVM), "questa")

    def test_slots_name_their_simulator(self):
        runs = lists.parse_regression(REGRESSION, "r.txt")
        q = [manifest.on_simulator(s, "questa") for s in manifest.regression_slots(runs)]
        v = [manifest.on_simulator(s, "vcs") for s in manifest.regression_slots(runs)]
        self.assertEqual(q[0]["exec_inputs"]["extra"], {"tool": {"simulator": "questa"}})
        self.assertNotEqual(q[0]["exec_inputs"], v[0]["exec_inputs"])
        # The original slot is not modified.
        self.assertNotIn("extra", manifest.regression_slots(runs)[0]["exec_inputs"])

    def test_chunks(self):
        c = manifest.chunks([{"slot_ref": str(i)} for i in range(1201)], MANIFEST)
        self.assertEqual([len(x["slots"]) for x in c], [500, 500, 201])


class Locks(unittest.TestCase):
    def test_only_dead_local_owners_are_removed(self):
        with tempfile.TemporaryDirectory() as d:
            w = Path(d)
            (w / "_lock").write_text("u@HOSTA, pid = 100\r\n")
            (w / "_opt__lock").write_text("u@HOSTA, pid = 200\r\n")
            (w / "_opt1__lock").write_text("u@OTHER, pid = 100\r\n")
            (w / "_opt2__lock").write_text("garbage")
            (w / "_info").write_text("not a lock")
            out = questa.remove_stale_locks(w, host="hosta", alive=lambda pid: pid == 200)
            self.assertEqual(out["removed"], ["_lock"])
            kept = {k["lock"]: k["why"] for k in out["kept"]}
            self.assertIn("running", kept["_opt__lock"])
            self.assertIn("another host", kept["_opt1__lock"])
            self.assertIn("not recognized", kept["_opt2__lock"])
            self.assertTrue((w / "_info").exists())

    def test_this_process_is_alive(self):
        self.assertTrue(questa.pid_alive(os.getpid()))


class FakeRunner:
    """Records every command; answers like the collector."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, capture_output, text, check, cwd=None):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"ok": True}), stderr="")


def plan(slots, command) -> Plan:
    return Plan(
        producer="pilot",
        regression_ref="nightly-2026-11-08",
        suite="nightly",
        branch=("rtl", "main"),
        source_manifest_ref="rtl@abc",
        revisions=[("rtl", "abc")],
        started_at="2026-11-08T01:00:00Z",
        slots=slots,
        simulator="questa",
        command=command,
        timeout_s=600,
    )


class Driving(unittest.TestCase):
    def test_steps_and_argv(self):
        slots = manifest.regression_slots(lists.parse_regression(REGRESSION))
        with tempfile.TemporaryDirectory() as d:
            fake = FakeRunner()
            drv = Driver("dviscope", Path(d) / "work", Path(d) / "journal", runner=fake)
            p = plan(slots, ["make", "sim", "TEST={test}", "SEED={seed}", "{plusargs}", "LOG={log}"])
            drv.prepare(p)
            kinds = [c[1:3] for c in fake.calls]
            self.assertEqual(
                kinds,
                [["journal", "init"], ["source-manifest", "--journal"], ["regression", "create"],
                 ["manifest", "declare"], ["manifest", "seal"]],
            )
            drv.run_slot(p, slots[0])
            run = fake.calls[-1]
            cmd = run[run.index("--") + 1 :]
            self.assertEqual(cmd[:5], ["make", "sim", "TEST=alpha_test", "SEED=1", "+mode=a"])
            self.assertEqual(cmd[5], "+n=3")
            self.assertTrue(cmd[6].startswith("LOG=") and cmd[6].endswith("alpha_test.s1.a1.log"))
            self.assertIn("--timeout", run)
            # A deliberate second attempt of the slot (its completion marker removed) gets a
            # fresh log path and attempt reference.
            Path(cmd[6][4:]).write_text("")
            (Path(d) / "work" / "done" / "alpha_test.s1.json").unlink()
            drv.run_slot(p, slots[0])
            run = fake.calls[-1]
            self.assertTrue(run[-1].endswith("alpha_test.s1.a2.log"))
            launch = json.loads(Path(run[run.index("--launch") + 1]).read_text())
            self.assertEqual(launch["attempt_ref"], "nightly-2026-11-08.alpha_test.s1.a2")
            drv.finish()
            self.assertEqual(fake.calls[-1][1:3], ["spool", "flush"])
            self.assertTrue(drv.closed())
            # A re-run skips completed slots (no launch).
            n = len(fake.calls)
            out = drv.run_slot(p, slots[0])
            self.assertTrue(out.get("skipped"))
            self.assertEqual(len(fake.calls), n)

    def test_relative_paths_survive_another_working_directory(self):
        # With --cwd, every path handed to the collector is absolute (it
        # runs elsewhere); a relative collector binary too; a bare name stays a PATH lookup.
        slots = manifest.regression_slots(lists.parse_regression(REGRESSION))
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                fake = FakeRunner()
                drv = Driver("bin/dviscope", Path("work"), Path("journal"), runner=fake)
                p = plan(slots, ["make", "LOG={log}"])
                p.cwd = Path("build")
                drv.prepare(p)
                drv.run_slot(p, slots[0])
            finally:
                os.chdir(old)
            run = fake.calls[-1]
            self.assertTrue(Path(run[0]).is_absolute(), run[0])
            for flag in ("--journal", "--launch", "--log"):
                self.assertTrue(Path(run[run.index(flag) + 1]).is_absolute(), (flag, run))
            self.assertEqual(Driver("dviscope", Path("w"), Path("j")).dviscope, "dviscope")

    @unittest.skipUnless(os.environ.get("DVISCOPE_BIN"), "DVISCOPE_BIN not set")
    def test_records_are_accepted_by_the_collector(self):
        slots = manifest.regression_slots(lists.parse_regression(REGRESSION))
        errors = lists.parse_core_errors(CORE) + lists.parse_uvm_errors(UVM)
        slots += manifest.suite_slots(["unit_a", "unit_b"], errors, "questa", skip_unrepresentable=True)
        with tempfile.TemporaryDirectory() as d:
            drv = Driver(os.environ["DVISCOPE_BIN"], Path(d) / "work", Path(d) / "journal")
            drv.prepare(plan(slots, ["x"]))
            # Idempotent: preparing again journals nothing new and fails nothing.
            drv.prepare(plan(slots, ["x"]))


if __name__ == "__main__":
    unittest.main()


class JournalResume(unittest.TestCase):
    def test_a_launch_in_the_journal_is_not_repeated(self):
        # A crash after `dviscope run` journalled the launch, before the driver wrote its
        # marker: the journal says the slot launched, so it is not launched again.
        slots = manifest.regression_slots(lists.parse_regression(REGRESSION))

        class Journalled(FakeRunner):
            def __call__(self, argv, capture_output, text, check, cwd=None):
                self.calls.append(argv)
                out = {"ok": True}
                if argv[1:3] == ["journal", "status"]:
                    out = {"entries": [{"identity": "attempt_started:nightly-2026-11-08.alpha_test.s1.a1"}]}
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(out), stderr="")

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "journal").mkdir()
            (Path(d) / "journal" / "journal.json").write_text("{}")
            fake = Journalled()
            drv = Driver("dviscope", Path(d) / "work", Path(d) / "journal", runner=fake)
            out = drv.run_slot(plan(slots, ["x"]), slots[0])
            self.assertTrue(out.get("from_journal"))
            self.assertFalse(any(c[1] == "run" for c in fake.calls))
            # Another slot still runs.
            drv.run_slot(plan(slots, ["x"]), slots[1])
            self.assertTrue(any(c[1] == "run" for c in fake.calls))


class InterruptedResume(unittest.TestCase):
    """A slot whose only launch was interrupted (recovered with
    termination unknown, no result) runs again on resume, as a new attempt; a slot with a
    launch that was not interrupted is still not repeated."""

    def _drive(self, entries):
        slots = [{"slot_ref": "foo.s1", "exec_inputs": {"test": "foo", "seed": "1"}, "required": True}]

        class J(FakeRunner):
            def __call__(self, argv, capture_output, text, check, cwd=None):
                self.calls.append(argv)
                out = {"ok": True}
                if argv[1:3] == ["journal", "status"]:
                    out = {"entries": entries}
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(out), stderr="")

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "journal").mkdir()
            (Path(d) / "journal" / "journal.json").write_text("{}")
            fake = J()
            drv = Driver("dviscope", Path(d) / "work", Path(d) / "journal", runner=fake)
            out = drv.run_slot(plan(slots, ["x"]), slots[0])
            return out, [c for c in fake.calls if c[1] == "run"]

    def test_an_interrupted_launch_runs_again_as_a_new_attempt(self):
        a1 = "attempt_started:nightly-2026-11-08.foo.s1.a1"
        out, runs = self._drive([{"identity": a1, "interrupted": True}])
        self.assertFalse(out.get("skipped"), out)
        [run] = runs
        # A new attempt (a2), never the interrupted one's identity again.
        self.assertTrue(any("foo.s1.a2" in a for a in run), run)

    def test_a_completed_launch_is_not_repeated(self):
        a1 = "attempt_started:nightly-2026-11-08.foo.s1.a1"
        a2 = "attempt_started:nightly-2026-11-08.foo.s1.a2"
        out, runs = self._drive([{"identity": a1, "interrupted": True}, {"identity": a2}])
        self.assertTrue(out.get("from_journal"), out)
        self.assertEqual(runs, [])


class LiveThenInterrupted(unittest.TestCase):
    """A slot skipped because its launch was still live is not
    cached as done: once recovery marks the launch interrupted, the slot runs again."""

    def test_a_live_launch_is_rechecked_on_the_next_resume(self):
        slots = [{"slot_ref": "foo.s1", "exec_inputs": {"test": "foo", "seed": "1"}, "required": True}]
        state = {"interrupted": False}

        class J(FakeRunner):
            def __call__(self, argv, capture_output, text, check, cwd=None):
                self.calls.append(argv)
                out = {"ok": True}
                if argv[1:3] == ["journal", "status"]:
                    out = {"entries": [{"identity": "attempt_started:nightly-2026-11-08.foo.s1.a1",
                                        "interrupted": state["interrupted"]}]}
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(out), stderr="")

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "journal").mkdir()
            (Path(d) / "journal" / "journal.json").write_text("{}")
            fake = J()
            drv = Driver("dviscope", Path(d) / "work", Path(d) / "journal", runner=fake)
            out = drv.run_slot(plan(slots, ["x"]), slots[0])
            self.assertTrue(out.get("from_journal"))
            self.assertFalse((Path(d) / "work" / "done" / "foo.s1.json").exists())
            state["interrupted"] = True
            out = drv.run_slot(plan(slots, ["x"]), slots[0])
            self.assertFalse(out.get("skipped"), out)
            self.assertTrue(any(c[1] == "run" for c in fake.calls))
            # An old journal-derived marker is checked again, not trusted.
            (Path(d) / "work2" / "done").mkdir(parents=True)
            (Path(d) / "work2" / "done" / "foo.s1.json").write_text(json.dumps({"from_journal": True}))
            drv2 = Driver("dviscope", Path(d) / "work2", Path(d) / "journal", runner=fake)
            self.assertFalse(drv2.run_slot(plan(slots, ["x"]), slots[0]).get("skipped"))


class DeferredClosure(unittest.TestCase):
    """Through two complete runs, a launch still live in the first is
    recovered in the second and its slot runs again (the first does not close)."""

    def test_two_runs_with_a_live_launch_in_between(self):
        slots = [{"slot_ref": "foo.s1", "exec_inputs": {"test": "foo", "seed": "1"}, "required": True}]
        state = {"live": True}

        class J(FakeRunner):
            def __call__(self, argv, capture_output, text, check, cwd=None):
                self.calls.append(argv)
                out = {"ok": True, "_code": 0, "pending": 0}
                if argv[1:3] == ["journal", "recover"]:
                    out = {"recovered": [], "live_orphans": [5] if state["live"] else [],
                           "unverifiable": []}
                if argv[1:3] == ["journal", "status"]:
                    out = {"entries": [{"identity": "attempt_started:nightly-2026-11-08.foo.s1.a1",
                                        "interrupted": not state["live"]}]}
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(out), stderr="")

        def one_run(fake, d):
            drv = Driver("dviscope", Path(d) / "work", Path(d) / "journal", runner=fake)
            if not drv.closed():
                drv.recover()
                for slot in slots:
                    drv.run_slot(plan(slots, ["x"]), slot)
            return drv.finish()

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "journal").mkdir()
            (Path(d) / "journal" / "journal.json").write_text("{}")
            fake = J()
            first = one_run(fake, d)
            self.assertTrue(first.get("close_deferred"), first)
            self.assertFalse(any(c[1:3] == ["journal", "close"] for c in fake.calls))
            self.assertFalse((Path(d) / "work" / "closed").exists())
            # The launch has ended meanwhile: recovered as interrupted, the slot runs again.
            state["live"] = False
            fake.calls.clear()
            second = one_run(fake, d)
            self.assertFalse(second.get("close_deferred"), second)
            self.assertTrue(any(c[1] == "run" for c in fake.calls))
            self.assertTrue(any(c[1:3] == ["journal", "close"] for c in fake.calls))


class ExactSlotResume(unittest.TestCase):
    def test_a_longer_slot_name_does_not_count(self):
        slots = [{"slot_ref": "foo.s1", "exec_inputs": {"test": "foo", "seed": "1"}, "required": True}]

        class J(FakeRunner):
            def __call__(self, argv, capture_output, text, check, cwd=None):
                self.calls.append(argv)
                out = {"ok": True}
                if argv[1:3] == ["journal", "status"]:
                    out = {"entries": [{"identity": "attempt_started:nightly-2026-11-08.foo.s1.another.s1.a1"}]}
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(out), stderr="")

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "journal").mkdir()
            (Path(d) / "journal" / "journal.json").write_text("{}")
            fake = J()
            drv = Driver("dviscope", Path(d) / "work", Path(d) / "journal", runner=fake)
            out = drv.run_slot(plan(slots, ["x"]), slots[0])
            self.assertFalse(out.get("skipped"))
            self.assertTrue(any(c[1] == "run" for c in fake.calls))
