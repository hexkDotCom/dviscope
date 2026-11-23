"""Manifest slots with expectations from the hexk lists.

A regression run ``test | seed | plusargs | verdict | expectations`` becomes one slot
``<test>.s<seed>``; a ``FAILED`` or ``NONE`` verdict, or any listed diagnostic, becomes an
expectation (verdict, diagnostics with exact counts, no extras). ``match=`` items stay with
the hexk checker: DVIScope expectations do not match message text.

A unit suite becomes one slot ``unit.<suite>``; the UVM errors the lists expect from it on
the selected simulator become a passing expectation with those diagnostics. Expected core
``$error`` messages cannot be expectations: DVIScope identifies them all as
``sv:severity_task`` without a site or checker, so an expectation would let any unrelated
``$error`` stand in for an expected one, and dropping them would let a missing expected
error pass unnoticed. A suite with such errors on the selected simulator is therefore
refused (``UnrepresentableExpectations``) unless the caller explicitly leaves it out of
the plan (it is then not declared, and the caller reports it).
"""

from __future__ import annotations

from collections import OrderedDict

from .lists import RegressionRun, SuiteError

#: Slots per manifest chunk.
CHUNK_SLOTS = 500


def _diagnostics(items) -> list[dict]:
    total: "OrderedDict[tuple[str, str], int]" = OrderedDict()
    for diag_id, severity, count in items:
        total[(diag_id, severity)] = total.get((diag_id, severity), 0) + count
    return [
        {"diag_id": d, "severity": s, "count": n} for (d, s), n in total.items()
    ]


def regression_slot(run: RegressionRun, source: str = "hexk_ref_regression.txt") -> dict:
    """The ``SlotDecl`` of one regression run."""
    slot = {
        "slot_ref": f"{run.test}.s{run.seed}",
        "exec_inputs": {
            "test": run.test,
            "seed": str(run.seed),
            "plusargs": list(run.plusargs),
        },
        "required": True,
    }
    if run.verdict != "PASSED" or run.expects:
        slot["expected"] = {
            "verdict": "pass" if run.verdict == "PASSED" else "fail",
            "diagnostics": _diagnostics(
                (e.diag_id, e.severity, e.count) for e in run.expects
            ),
            "extras": "none",
            "reason": f"{source} line {run.line}",
        }
    return slot


def on_simulator(slot: dict, simulator: str) -> dict:
    """Names the simulator in the slot's execution inputs (``extra.tool.simulator``): the
    slots declare no build requirement, so without it a test on Questa and the same test on
    VCS would be one configuration (comparison baselines and feature candidates would mix
    simulators)."""
    out = dict(slot)
    out["exec_inputs"] = dict(slot["exec_inputs"])
    out["exec_inputs"]["extra"] = {"tool": {"simulator": simulator}}
    return out


def regression_slots(runs: list[RegressionRun]) -> list[dict]:
    """Slots of a regression list; a test and seed listed twice is an error."""
    slots, seen = [], set()
    for r in runs:
        s = regression_slot(r)
        if s["slot_ref"] in seen:
            raise ValueError(f"line {r.line}: {r.test} seed {r.seed} is listed twice")
        seen.add(s["slot_ref"])
        slots.append(s)
    return slots


def representable(e: SuiteError) -> bool:
    """Whether an expected error has an identity of its own (a UVM message ID)."""
    return e.diag_id.startswith("uvm:")


def unrepresented(errors: list[SuiteError], simulator: str) -> list[SuiteError]:
    """Expected errors on `simulator` that cannot become expectations."""
    return [e for e in errors if simulator in e.simulators and not representable(e)]


class UnrepresentableExpectations(ValueError):
    """Suites whose expected errors DVIScope cannot check faithfully."""

    def __init__(self, suites: list[str]) -> None:
        self.suites = suites
        super().__init__(
            "expected $error messages without distinct identities in suites: "
            + ", ".join(suites)
            + " (leave them out explicitly, or give the messages identities in a project pack)"
        )


def suite_slots(
    suites: list[str], errors: list[SuiteError], simulator: str, skip_unrepresentable: bool = False
) -> list[dict]:
    """Slots of unit suites run on `simulator`, with the UVM errors the lists expect there.
    Suites with unrepresentable expected errors are refused, or left out when asked."""
    bad = sorted({e.suite for e in unrepresented(errors, simulator)} & set(suites))
    if bad and not skip_unrepresentable:
        raise UnrepresentableExpectations(bad)
    slots = []
    for suite in suites:
        if suite in bad:
            continue
        mine = [
            e
            for e in errors
            if e.suite == suite and simulator in e.simulators and representable(e)
        ]
        slot = {
            "slot_ref": f"unit.{suite}",
            "exec_inputs": {"test": suite, "seed": "0"},
            "required": True,
        }
        if mine:
            slot["expected"] = {
                "verdict": "pass",
                "diagnostics": _diagnostics(
                    (e.diag_id, e.severity, e.count) for e in mine
                ),
                "extras": "none",
                "reason": "hexk expected error lists",
            }
        slots.append(slot)
    unknown = sorted({e.suite for e in errors} - set(suites))
    if unknown:
        raise ValueError(f"the error lists name suites that are not run: {', '.join(unknown)}")
    return slots


def chunks(slots: list[dict], schema: str, size: int = CHUNK_SLOTS) -> list[dict]:
    """``ManifestChunk`` records of at most `size` slots, in order."""
    return [
        {"schema": schema, "slots": slots[i : i + size]}
        for i in range(0, len(slots), size)
    ]
