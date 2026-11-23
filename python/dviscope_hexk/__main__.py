"""``python -m dviscope_hexk``: ``slots`` prints the manifest slots of hexk lists; ``run``
drives a regression through ``dviscope``."""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from . import lists, manifest
from .driver import Driver, Plan


def _slots(a) -> list[dict]:
    slots: list[dict] = []
    if a.regression_list:
        slots += manifest.regression_slots(
            lists.parse_regression(Path(a.regression_list).read_text(encoding="utf-8"), a.regression_list)
        )
    if a.suites:
        errors = []
        if a.core_errors:
            errors += lists.parse_core_errors(Path(a.core_errors).read_text(encoding="utf-8"), a.core_errors)
        if a.uvm_errors:
            errors += lists.parse_uvm_errors(Path(a.uvm_errors).read_text(encoding="utf-8"), a.uvm_errors)
        slots += manifest.suite_slots(
            a.suites.split(","), errors, a.simulator, a.skip_unrepresentable
        )
        for s in sorted({e.suite for e in manifest.unrepresented(errors, a.simulator)}):
            print(f"note: suite {s} left out: its expected $error messages cannot be checked",
                  file=sys.stderr)
    return [manifest.on_simulator(s, a.simulator) for s in slots]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dviscope_hexk")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("slots", "run"):
        s = sub.add_parser(name)
        s.add_argument("--regression-list")
        s.add_argument("--suites", help="comma-separated unit suites")
        s.add_argument("--core-errors")
        s.add_argument("--uvm-errors")
        s.add_argument("--simulator", required=True, choices=list(lists.SIMULATORS))
        s.add_argument("--skip-unrepresentable", action="store_true",
                       help="leave out suites whose expected $error messages cannot be checked")
    r = sub.choices["run"]
    r.add_argument("--dviscope", default="dviscope")
    r.add_argument("--work", required=True, help="adapter work directory (logs, records)")
    r.add_argument("--journal", required=True)
    r.add_argument("--producer", required=True)
    r.add_argument("--regression-ref", required=True, help="e.g. nightly-2026-11-08-questa")
    r.add_argument("--suite", default="nightly")
    r.add_argument("--repository", required=True)
    r.add_argument("--branch", required=True)
    r.add_argument("--revision", required=True)
    r.add_argument("--command", required=True, help="JSON list; {test} {seed} {log} {slot} {attempt} {plusargs}")
    r.add_argument("--timeout", type=float)
    r.add_argument("--questa-work", action="append", default=[])
    r.add_argument("--cwd", help="working directory of the simulator command")
    r.add_argument("--run-arg", action="append", default=[], help="extra `dviscope run` argument (repeatable)")
    a = p.parse_args(argv)
    try:
        slots = _slots(a)
    except (lists.ListError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.cmd == "slots":
        print(json.dumps(slots, indent=2))
        return 0
    # A re-run of the same regression resumes it: the regression record (its start time
    # included) is the one journalled first.
    previous = Path(a.work) / "regression.json"
    started_at = (
        json.loads(previous.read_text(encoding="utf-8"))["started_at"]
        if previous.exists()
        else datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    plan = Plan(
        producer=a.producer,
        regression_ref=a.regression_ref,
        suite=a.suite,
        branch=(a.repository, a.branch),
        source_manifest_ref=f"{a.repository}@{a.revision}",
        revisions=[(a.repository, a.revision)],
        started_at=started_at,
        slots=slots,
        simulator=a.simulator,
        command=json.loads(a.command),
        timeout_s=a.timeout,
        questa_work=[Path(w) for w in a.questa_work],
        cwd=Path(a.cwd) if a.cwd else None,
        run_args=a.run_arg,
    )
    d = Driver(a.dviscope, Path(a.work), Path(a.journal))
    if not d.closed():
        d.prepare(plan)
        d.recover()
        for slot in slots:
            d.run_slot(plan, slot)
    flushed = d.finish()
    print(json.dumps({"slots": len(slots), "flush": flushed}, indent=2))
    return 0 if flushed.get("_code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
