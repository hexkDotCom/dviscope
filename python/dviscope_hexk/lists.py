"""Parsers of the hexk list formats (hexk adapter).

* ``hexk_ref_regression.txt``: ``test | seed | plusargs | verdict | expectations``, where the
  verdict is ``PASSED``, ``FAILED`` or ``NONE`` (after a fatal) and the expectations are
  ``ID:W|E|F:count`` items and ``match=REGEX`` items.
* ``expected_core_errors.txt``: ``suite simulators count message...`` (``$error`` messages
  that unit tests cause on purpose).
* ``expected_uvm_errors.txt``: ``suite simulators severity id count``.

``simulators`` is ``all`` or a comma-separated list of ``verilator``, ``questa``, ``vcs``.
Comments start with ``#``; blank lines are ignored. Every malformed line is an error that
names its line number: a list that cannot be read exactly is never half-applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SIMULATORS = ("verilator", "questa", "vcs")
_SEVERITY = {"W": "warning", "E": "error", "F": "fatal"}


class ListError(ValueError):
    """A malformed list line."""

    def __init__(self, source: str, line: int, message: str) -> None:
        super().__init__(f"{source}:{line}: {message}")


@dataclass(frozen=True)
class Expect:
    """One expected diagnostic of a regression run."""

    diag_id: str
    severity: str
    count: int


@dataclass(frozen=True)
class RegressionRun:
    """One line of the regression list."""

    test: str
    seed: int
    plusargs: tuple[str, ...]
    verdict: str  # PASSED, FAILED or NONE
    expects: tuple[Expect, ...] = ()
    matches: tuple[str, ...] = ()
    line: int = 0


@dataclass(frozen=True)
class SuiteError:
    """One expected error of a unit suite on some simulators."""

    suite: str
    simulators: frozenset[str]
    diag_id: str
    severity: str
    count: int
    message: str = field(default="")


def _lines(text: str):
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line and not line.startswith("#"):
            yield n, line


def _simulators(source: str, n: int, value: str) -> frozenset[str]:
    if value == "all":
        return frozenset(SIMULATORS)
    sims = frozenset(value.split(","))
    unknown = sims - set(SIMULATORS)
    if not sims or unknown:
        raise ListError(source, n, f"unknown simulators {sorted(unknown) or value!r}")
    return sims


def parse_regression(text: str, source: str = "regression list") -> list[RegressionRun]:
    """Parses ``hexk_ref_regression.txt``."""
    runs = []
    for n, line in _lines(text):
        cols = [c.strip() for c in line.split("|")]
        if len(cols) != 5:
            raise ListError(source, n, f"expected 5 columns separated by '|', found {len(cols)}")
        test, seed, plusargs, verdict, rest = cols
        if not test:
            raise ListError(source, n, "empty test name")
        try:
            seed_n = int(seed)
        except ValueError:
            raise ListError(source, n, f"seed {seed!r} is not an integer") from None
        if seed_n < 0:
            raise ListError(source, n, "a seed is not negative")
        if verdict not in ("PASSED", "FAILED", "NONE"):
            raise ListError(source, n, f"verdict {verdict!r} is not PASSED, FAILED or NONE")
        expects, matches = [], []
        for item in rest.split():
            if item.startswith("match="):
                matches.append(item[len("match="):])
                continue
            parts = item.split(":")
            if len(parts) != 3 or parts[1] not in _SEVERITY or not parts[0]:
                raise ListError(source, n, f"expectation {item!r} is not ID:W|E|F:count")
            try:
                count = int(parts[2])
            except ValueError:
                raise ListError(source, n, f"count of {item!r} is not an integer") from None
            if count < 1:
                raise ListError(source, n, f"count of {item!r} is below 1")
            expects.append(Expect(f"uvm:{parts[0]}", _SEVERITY[parts[1]], count))
        if verdict == "NONE" and not any(e.severity == "fatal" for e in expects):
            raise ListError(source, n, "verdict NONE (after a fatal) needs an expected fatal")
        if verdict == "FAILED" and not any(e.severity in ("error", "fatal") for e in expects):
            raise ListError(source, n, "verdict FAILED needs an expected error or fatal")
        runs.append(
            RegressionRun(
                test=test,
                seed=seed_n,
                plusargs=tuple(plusargs.split()),
                verdict=verdict,
                expects=tuple(expects),
                matches=tuple(matches),
                line=n,
            )
        )
    return runs


def parse_core_errors(text: str, source: str = "core error list") -> list[SuiteError]:
    """Parses ``expected_core_errors.txt`` (``$error`` messages of the core library)."""
    out = []
    for n, line in _lines(text):
        cols = line.split(None, 3)
        if len(cols) != 4:
            raise ListError(source, n, "expected: suite simulators count message")
        suite, sims, count, message = cols
        try:
            count_n = int(count)
        except ValueError:
            raise ListError(source, n, f"count {count!r} is not an integer") from None
        if count_n < 1:
            raise ListError(source, n, "a count is at least 1")
        out.append(
            SuiteError(
                suite=suite,
                simulators=_simulators(source, n, sims),
                diag_id="sv:severity_task",
                severity="error",
                count=count_n,
                message=message,
            )
        )
    return out


def parse_uvm_errors(text: str, source: str = "UVM error list") -> list[SuiteError]:
    """Parses ``expected_uvm_errors.txt``."""
    out = []
    for n, line in _lines(text):
        cols = line.split()
        if len(cols) != 5:
            raise ListError(source, n, "expected: suite simulators severity id count")
        suite, sims, severity, ident, count = cols
        sev = {"UVM_WARNING": "warning", "UVM_ERROR": "error", "UVM_FATAL": "fatal"}.get(severity)
        if sev is None:
            raise ListError(source, n, f"severity {severity!r} is not UVM_WARNING, UVM_ERROR or UVM_FATAL")
        try:
            count_n = int(count)
        except ValueError:
            raise ListError(source, n, f"count {count!r} is not an integer") from None
        if count_n < 1:
            raise ListError(source, n, "a count is at least 1")
        out.append(
            SuiteError(
                suite=suite,
                simulators=_simulators(source, n, sims),
                diag_id=f"uvm:{ident}",
                severity=sev,
                count=count_n,
            )
        )
    return out
