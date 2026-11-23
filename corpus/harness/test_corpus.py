# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 HEXK
"""Self-tests of the corpus harness (no simulators): python corpus/harness/test_corpus.py"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus  # noqa: E402


class BoundedExecution(unittest.TestCase):
    def test_lingering_child_cannot_block_the_runner(self):
        # The child starts a grandchild that keeps the output open and ignores the parent's end.
        code = ("import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']);"
                "time.sleep(30)")
        with tempfile.TemporaryDirectory() as d:
            t0 = time.monotonic()
            old = corpus.GRACE_S
            corpus.GRACE_S = 1
            try:
                r = corpus.run_bounded([sys.executable, "-c", code], Path(d), dict(os.environ), 1.0,
                                       Path(d) / "out.bin")
            finally:
                corpus.GRACE_S = old
            self.assertLess(time.monotonic() - t0, 10)
            self.assertIn(r["termination"], ("timeout", "unreaped"))

    @unittest.skipUnless(sys.platform == "win32", "Windows job objects")
    def test_descendants_are_ended_with_the_job(self):
        # The grandchild would outlive a plain kill of the child; the job ends it, so the
        # capture file is released and deleted.
        code = ("import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
                "time.sleep(60)")
        with tempfile.TemporaryDirectory() as d:
            cap = Path(d) / "out.bin"
            r = corpus.run_bounded([sys.executable, "-c", code], Path(d), dict(os.environ), 1.0, cap)
            self.assertEqual(r.get("process_tree"), "job")
            self.assertNotIn("cleanup", r)
            self.assertFalse(cap.exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows job objects")
    def test_early_spawned_descendant_does_not_outlive_a_normal_exit(self):
        # The launcher starts a long-lived child at once and exits normally: the child must be
        # in the job (the launcher was created suspended) and end with the attempt.
        import ctypes
        with tempfile.TemporaryDirectory() as d:
            pidfile = Path(d) / "pid.txt"
            code = ("import subprocess,sys;"
                    "c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
                    f"open(r'{pidfile}','w').write(str(c.pid))")
            r = corpus.run_bounded([sys.executable, "-c", code], Path(d), dict(os.environ), 30,
                                   Path(d) / "out.bin")
            self.assertEqual((r["termination"], r.get("exit_code"), r.get("process_tree")), ("exited", 0, "job"))
            k = ctypes.WinDLL("kernel32")
            k.OpenProcess.restype = ctypes.c_void_p
            h = k.OpenProcess(0x00100000, False, int(pidfile.read_text()))  # SYNCHRONIZE
            if h:
                alive = k.WaitForSingleObject(ctypes.c_void_p(h), 2000) != 0
                k.CloseHandle(ctypes.c_void_p(h))
                self.assertFalse(alive, "descendant outlived the attempt")

    def test_exit_status_and_output(self):
        with tempfile.TemporaryDirectory() as d:
            r = corpus.run_bounded([sys.executable, "-c", "print('x'); raise SystemExit(3)"], Path(d),
                                   dict(os.environ), 30, Path(d) / "out.bin")
            self.assertEqual((r["termination"], r["exit_code"]), ("exited", 3))
            self.assertIn(b"x", r["stdout"])

    def test_missing_tool_is_not_started(self):
        with tempfile.TemporaryDirectory() as d:
            r = corpus.run_bounded(["no-such-tool-dviscope"], Path(d), dict(os.environ), 5, Path(d) / "o")
            self.assertEqual(r["termination"], "not_started")


class Confinement(unittest.TestCase):
    def test_repository_paths_are_refused(self):
        with self.assertRaises(SystemExit):
            corpus.outside_repo(corpus.REPO / "corpus")

    def test_private_path_cannot_escape(self):
        with tempfile.TemporaryDirectory() as d:
            priv = corpus.Private(Path(d) / "out")
            with self.assertRaises(SystemExit):
                priv.path("..", "elsewhere.txt")

    @unittest.skipIf(sys.platform == "win32", "creating links needs privileges on Windows")
    def test_linked_fixture_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out"
            out.mkdir()
            (out / "fixtures").symlink_to(corpus.REPO / "corpus")
            with self.assertRaises(SystemExit):
                corpus.Private(out)


class Evidence(unittest.TestCase):
    def test_required_streams(self):
        not_run = {"runner": {"termination": "not_run"}}
        self.assertEqual(corpus.required_evidence(not_run, {}), ["build_log"])
        ran = {"runner": {"termination": "exited"}, "log_exists": True}
        self.assertEqual(corpus.required_evidence(ran, {"log_from": "x.log"}), ["build_log", "log", "stdout"])
        self.assertEqual(corpus.required_evidence(ran, {"log_from": "stdout"}), ["build_log", "log"])


class QuestaLoadFailureOracle(unittest.TestCase):
    """A design that does not load is complete only with the error summary and the end-time
    trailer."""

    def expectation(self, log: str) -> dict:
        with tempfile.TemporaryDirectory() as d:
            Path(d, "c.log").write_text(log, encoding="utf-8")
            group = {"design": "hexk-ref", "id": "g",
                     "expect": {"run_marker": "Error loading design", "mentions": "tb.sv"}}
            r = {"sim": "questa", "facts": {"runner": {"termination": "exited"}},
                 "oracle": {"verdict": "NONE", "seen": {}}}
            return corpus.expectation(group, "c", r, Path(d), {})

    def test_the_trailer_is_required(self):
        base = ("# ** Error: (vopt-1) tb.sv(3): bad\n# Error loading design\n"
                "# Errors: 1, Warnings: 0\n")
        end = "# End time: 01:06:00 on Nov 08,2026, Elapsed time: 0:00:01\n"
        with_end = self.expectation(base + end)
        self.assertEqual((with_end.get("completion"), with_end.get("mode")),
                         ("complete", "early_fatal"))
        without = self.expectation(base)
        self.assertEqual(without.get("completion"), "incomplete")


if __name__ == "__main__":
    unittest.main()

