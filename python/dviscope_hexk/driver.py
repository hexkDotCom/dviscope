"""Drives one hexk regression through the ``dviscope`` collector.

Order: the journal (created once), the source manifest, the regression, its manifest
chunks and seal, then one supervised ``dviscope run`` per slot with a fresh log path, and
finally the closure and a flush. Every step is a ``dviscope`` command, so a crash at any
point is recovered by the journal; re-running the driver for the same regression reference
resumes (journalled records are idempotent; a slot already launched is not relaunched,
unless every launch of it was interrupted: then it runs again as a new attempt).

The simulator command is a JSON list of arguments; ``{test}``, ``{seed}``, ``{log}``,
``{slot}`` and ``{attempt}`` are replaced in each element, and an element that is exactly
``{plusargs}`` expands into the run's plusargs.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest as mf
from .questa import remove_stale_locks

INGEST = "dviscope.ingest/1.0-dev.3"
MANIFEST = "dviscope.manifest/1.0-dev.3"


@dataclass
class Plan:
    """What one regression run needs."""

    producer: str
    regression_ref: str
    suite: str
    branch: tuple[str, str]  # repository, branch name
    source_manifest_ref: str
    revisions: list[tuple[str, str]]  # (repository, revision)
    started_at: str  # RFC 3339
    slots: list[dict]
    simulator: str
    command: list[str]
    timeout_s: float | None = None
    questa_work: list[Path] = field(default_factory=list)
    #: Working directory of the simulator command (e.g. the build directory).
    cwd: Path | None = None
    #: Extra arguments of every ``dviscope run`` (packs, source roots).
    run_args: list[str] = field(default_factory=list)


class DviscopeError(RuntimeError):
    """A ``dviscope`` command failed."""


class Driver:
    """Runs the steps with one ``dviscope`` executable and a work directory."""

    def __init__(self, dviscope: str, work: Path, journal: Path, runner=subprocess.run) -> None:
        # Absolute from the start: the simulator command may run in another directory
        # (--cwd), and every path handed to the collector must still name the same file. A bare command name stays a PATH lookup.
        has_dir = "/" in dviscope or "\\" in dviscope
        self.dviscope = str(Path(dviscope).absolute()) if has_dir else dviscope
        self.work = Path(work).absolute()
        self.journal = Path(journal).absolute()
        self.runner = runner
        self.steps: list[dict] = []

    def _call(self, *args: str, check: bool = True, cwd: Path | None = None) -> dict:
        p = self.runner(
            [self.dviscope, *args],
            capture_output=True,
            text=True,
            check=False,
            cwd=cwd,
        )
        out: dict = {}
        if p.stdout.strip():
            try:
                out = json.loads(p.stdout)
            except json.JSONDecodeError:
                out = {"stdout": p.stdout[-2000:]}
        self.steps.append({"args": list(args[:2]), "code": p.returncode})
        if check and p.returncode != 0:
            raise DviscopeError(
                f"dviscope {' '.join(args[:2])} failed ({p.returncode}): {p.stderr.strip()[-500:]}"
            )
        out["_code"] = p.returncode
        return out

    def _json(self, name: str, value: dict) -> Path:
        p = self.work / name
        p.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        return p

    def prepare(self, plan: Plan) -> None:
        """Journal, source manifest, regression, chunks and seal (idempotent)."""
        self.work.mkdir(parents=True, exist_ok=True)
        if not (self.journal / "journal.json").exists():
            self._call("journal", "init", "--dir", str(self.journal), "--id", plan.regression_ref)
        sm = self._json(
            "source-manifest.json",
            {
                "schema": INGEST,
                "producer_id": plan.producer,
                "source_manifest_ref": plan.source_manifest_ref,
                "repositories": [
                    {"repository": r, "revision": v} for r, v in plan.revisions
                ],
            },
        )
        self._call("source-manifest", "--journal", str(self.journal), "--body", str(sm))
        reg = self._json(
            "regression.json",
            {
                "schema": INGEST,
                "producer_id": plan.producer,
                "regression_ref": plan.regression_ref,
                "suite": plan.suite,
                "branch": {"repository": plan.branch[0], "name": plan.branch[1]},
                "source_manifest_ref": plan.source_manifest_ref,
                "trigger": {"kind": "nightly"},
                "started_at": plan.started_at,
            },
        )
        self._call("regression", "create", "--journal", str(self.journal), "--body", str(reg))
        for n, chunk in enumerate(mf.chunks(plan.slots, MANIFEST), start=1):
            c = self._json(f"chunk-{n}.json", chunk)
            self._call(
                "manifest", "declare", "--journal", str(self.journal),
                "--regression", plan.regression_ref, "--chunk", str(n), "--body", str(c),
            )
        self._call(
            "manifest", "seal", "--journal", str(self.journal), "--regression", plan.regression_ref
        )

    def _argv(self, plan: Plan, slot: dict, log: Path, attempt: str) -> list[str]:
        e = slot["exec_inputs"]
        values = {
            "test": e["test"],
            "seed": e["seed"],
            "log": str(log),
            "slot": slot["slot_ref"],
            "attempt": attempt,
        }
        argv: list[str] = []
        for a in plan.command:
            if a == "{plusargs}":
                argv.extend(e.get("plusargs", []))
            else:
                argv.append(a.format(**values))
        return argv

    def recover(self) -> None:
        """Marks interrupted launches of an earlier run (termination unknown; never a
        pass, never relaunched as such). Launches still live or unverifiable keep the
        journal open: closing waits until a later run can resolve them."""
        if (self.journal / "journal.json").exists():
            out = self._call("journal", "recover", "--dir", str(self.journal))
            self.unresolved = bool(out.get("live_orphans") or out.get("unverifiable"))

    def _launched(self) -> list[tuple[str, bool]]:
        """Identities of the launches in the journal, each with whether it was interrupted
        (recovered with termination unknown: no result)."""
        if not (self.journal / "journal.json").exists():
            return []
        st = self._call("journal", "status", "--dir", str(self.journal))
        return [
            (e.get("identity") or "", bool(e.get("interrupted")))
            for e in st.get("entries", [])
            if (e.get("identity") or "").startswith("attempt_started:")
        ]

    def closed(self) -> bool:
        """Whether this run's launches were already closed (only a flush remains)."""
        return (self.work / "closed").exists()

    def run_slot(self, plan: Plan, slot: dict) -> dict:
        """One supervised attempt of a slot with a fresh log path (never reused). A slot
        whose attempt already completed in an earlier run of the driver is skipped."""
        done = self.work / "done" / f"{slot['slot_ref']}.json"
        if done.exists():
            marker = json.loads(done.read_text(encoding="utf-8"))
            # A marker this driver wrote after running the slot ends here; a journal-derived
            # one (an earlier version) is checked against the journal again.
            if not marker.get("from_journal"):
                return marker | {"skipped": True}
        # The journal is the authority: a launch of this slot by an earlier run of the
        # driver (even one that crashed before writing its marker) is not repeated, unless
        # every launch of it was interrupted (no result): then it runs again.
        mine = re.compile(
            "attempt_started:" + re.escape(f"{plan.regression_ref}.{slot['slot_ref']}") + r"\.a[0-9]+"
        )
        journalled = [(i, stopped) for i, stopped in self._launched() if mine.fullmatch(i)]
        launches = [stopped for _, stopped in journalled]
        if launches and not all(launches):
            # Not cached: a launch still live or unverifiable may later be recovered as
            # interrupted, and then this slot runs again.
            return {"skipped": True, "from_journal": True}
        logs = self.work / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        # A new attempt number: after every journalled launch of the slot and every log.
        n = 1 + max((int(i.rsplit(".a", 1)[1]) for i, _ in journalled), default=0)
        while (logs / f"{slot['slot_ref']}.a{n}.log").exists():
            n += 1
        attempt = f"{plan.regression_ref}.{slot['slot_ref']}.a{n}"
        log = logs / f"{slot['slot_ref']}.a{n}.log"
        launch = self._json(
            f"launch-{slot['slot_ref']}.a{n}.json",
            {
                "producer_id": plan.producer,
                "regression_ref": plan.regression_ref,
                "slot_ref": slot["slot_ref"],
                "attempt_ref": attempt,
                "source_manifest_ref": plan.source_manifest_ref,
                "execution": slot["exec_inputs"],
            },
        )
        locks = [remove_stale_locks(w) for w in plan.questa_work]
        args = ["run", "--journal", str(self.journal), "--launch", str(launch), "--log", str(log),
                "--simulator", plan.simulator]
        if plan.timeout_s:
            args += ["--timeout", str(plan.timeout_s)]
        args += plan.run_args
        out = self._call(*args, "--", *self._argv(plan, slot, log, attempt), cwd=plan.cwd)
        out["locks"] = locks
        done.parent.mkdir(parents=True, exist_ok=True)
        done.write_text(json.dumps({"attempt": attempt, "log": str(log)}), encoding="utf-8")
        return out

    def finish(self) -> dict:
        """Closes launches and flushes (the regression's finish is the operator's call).
        While an earlier launch is still live or unverifiable, the journal stays open (only
        a flush): a later run recovers that launch and runs its slot again."""
        if getattr(self, "unresolved", False):
            out = self._call("spool", "flush", "--dir", str(self.journal), check=False)
            return out | {"close_deferred": True}
        self._call("journal", "close", "--dir", str(self.journal))
        (self.work / "closed").write_text("closed", encoding="utf-8")
        return self._call("spool", "flush", "--dir", str(self.journal), check=False)
