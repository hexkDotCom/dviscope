#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 HEXK
"""DVIScope corpus harness (plan §4.4, D.3, D.12; see corpus/README.md).

    corpus.py --config LOCAL.toml prepare
    corpus.py --config LOCAL.toml campaign
    corpus.py --config LOCAL.toml run   --group GROUP [--sim SIM]
    corpus.py --config LOCAL.toml label
    corpus.py --config LOCAL.toml manifest --side NAME=OUT_DIR ... --out FILE
    corpus.py --config LOCAL.toml ids > corpus/public-ids.txt
    corpus.py --config LOCAL.toml extract-check --side NAME=OUT_DIR ... --dviscope BIN
              --pack PACK ... --source-root PREFIX ... --work PRIVATE_DIR

Runs simulators on private copies of open designs, applies mutations and runtime faults, and
records each run's evidence (log, build log, console) and runner facts in a PRIVATE output
directory outside the repository. Labels come from each design's own oracle and are earned
within one qualification campaign: a passing control, fault-specific activation evidence, and
a passing recovery that started after the mutant finished. Prints only case IDs, states and
counts: never log text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parent
REPO = CORPUS.parent.resolve()
SIDE = "windows" if sys.platform == "win32" else "wsl"
FORMAT = "dviscope.corpus-private/2"
BUILD_TIMEOUT_S = 3600
RUN_TIMEOUT_S = 600
GRACE_S = 10


def die(msg: str):
    print(f"corpus: {msg}", file=sys.stderr)
    sys.exit(1)


def load_toml(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_json(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------------------------------
# private output confinement

def outside_repo(path: Path) -> Path:
    """The resolved path (links and junctions followed); dies if it lies in the repository."""
    r = path.resolve()
    if r == REPO or REPO in r.parents:
        die(f"{path} resolves into the repository; private data must live outside it")
    return r


class Private:
    """Every private write goes through here: the destination must resolve inside the private
    root (no link or junction may redirect it) and outside the repository."""

    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.root = outside_repo(root)
        for sub in ("fixtures", "runs"):
            d = self.root / sub
            d.mkdir(exist_ok=True)
            if d.is_symlink() or d.resolve() != d:
                die(f"private directory {sub} is redirected")

    def path(self, *parts: str) -> Path:
        p = self.root.joinpath(*parts)
        r = p.resolve()
        if self.root not in r.parents:
            die(f"private path {'/'.join(parts)} escapes the private root")
        outside_repo(p)
        return p

    def write_bytes(self, data: bytes, *parts: str) -> Path:
        p = self.path(*parts)
        p.write_bytes(data)
        return p

    def write_text(self, text: str, *parts: str) -> Path:
        return self.write_bytes(text.encode("utf-8"), *parts)

    def copy_in(self, src: Path, *parts: str) -> Path:
        p = self.path(*parts)
        shutil.copyfile(src, p)
        return p


class Config:
    """Private configuration: sources, work and output directories per side."""

    def __init__(self, path: Path):
        c = load_toml(path)
        side = c.get("side", {}).get(SIDE, {})
        self.sources = {k: Path(v).expanduser() for k, v in side.get("sources", {}).items()}
        # {source name: [{from = <path>, to = <path relative to the checkout>}]}: untracked
        # dependencies (UVM, SVUnit) copied into the private checkout.
        self.copy_into = side.get("copy_into", {})
        self.work = Path(side["work"]).expanduser()
        self.work.mkdir(parents=True, exist_ok=True)
        self.work = outside_repo(self.work)
        for sub in ("src", "builds", "lists", "tmp"):
            (self.work / sub).mkdir(exist_ok=True)
            self.work_dir(sub)
        self.out = Private(Path(side["out"]).expanduser())
        self.env_path_prepend = side.get("path_prepend", [])
        self.extra_env = side.get("env", {})
        self.python = side.get("python", "python3")

    def work_dir(self, *parts: str) -> Path:
        """A path under the work root that no link or junction redirects (simulator outputs
        and build logs are written there)."""
        p = self.work.joinpath(*parts)
        r = p.resolve()
        if self.work not in r.parents:
            die(f"work path {'/'.join(parts)} escapes the work root")
        outside_repo(p)
        return p

    def env(self) -> dict:
        env = dict(os.environ)
        if self.env_path_prepend:
            env["PATH"] = os.pathsep.join(self.env_path_prepend + [env.get("PATH", "")])
        for k, v in self.extra_env.items():
            env[k] = v.replace("{work}", self.work.as_posix())
        env["MSYS_NO_PATHCONV"] = "1"
        return env


def designs() -> dict:
    return load_toml(CORPUS / "designs.toml")["design"]


def mutations() -> tuple[dict, dict]:
    m = load_toml(CORPUS / "mutations.toml")
    return m.get("mutation", {}), m.get("fault", {})


def groups() -> list[dict]:
    return load_toml(CORPUS / "cases.toml")["group"]


def group_by_id(gid: str) -> dict:
    return next((g for g in groups() if g["id"] == gid), None) or die(f"no group {gid}")


# ---------------------------------------------------------------------------------------
# runs of a group

def parse_list_line(line: str) -> dict:
    parts = [p.strip() for p in line.split("|")]
    return {
        "test": parts[0],
        "seed": parts[1] if len(parts) > 1 else "",
        "plusargs": parts[2].split() if len(parts) > 2 and parts[2] else [],
        "verdict": parts[3] if len(parts) > 3 and parts[3] else None,
        "expect": parts[4].split() if len(parts) > 4 and parts[4] else [],
    }


def design_list(cfg: Config, design: dict) -> list[dict]:
    src = cfg.work / "src" / design["source"]
    out = []
    for line in (src / design["list"]).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(parse_list_line(line))
    return out


def group_runs(cfg: Config, group: dict) -> list[dict]:
    d = designs()[group["design"]]
    spec = group["runs"]
    if spec in ("list", "list+extra"):
        runs = design_list(cfg, d)
        if spec == "list+extra":
            runs += [parse_list_line(x) | {"verdict": "PASSED"} for x in group.get("extra", [])]
        return runs
    if spec == "all":
        src = cfg.work / "src" / d["source"] / "quirks"
        return [{"test": p.name, "seed": "", "plusargs": [], "verdict": None, "expect": []}
                for p in sorted(src.iterdir()) if p.is_dir()]
    return [parse_list_line(x) for x in spec]


def case_id(group: dict, sim: str, n: int) -> str:
    return f"{group['id']}-{sim}-{n:02d}"


def run_key(run: dict) -> str:
    return f"{run['test']}|{run['seed']}|{' '.join(run['plusargs'])}"


def definitions_digest() -> str:
    """The corpus definitions (designs, mutations, cases, matrix): label results made under
    other definitions are not accepted by the manifest."""
    h = hashlib.sha256()
    for name in ("designs.toml", "mutations.toml", "cases.toml", "matrix.toml"):
        h.update(name.encode() + b"\0" + (CORPUS / name).read_bytes() + b"\0")
    return h.hexdigest()


def definition_digest(group: dict, sim: str, run: dict) -> str:
    """Everything that defines a case: a change makes its stored evidence stale."""
    d = designs()[group["design"]]
    muts, faults = mutations()
    variant = group["variant"]
    return digest_json({
        "group": group, "sim": sim, "side": d["sim"][sim]["side"], "run": run,
        "design": {k: v for k, v in d.items() if k != "sim"}, "simdef": d["sim"][sim],
        "mutation": muts.get(variant.split(":", 1)[1]) if variant.startswith("mutant:") else None,
        "fault": faults.get(group.get("fault", "")),
    })


# ---------------------------------------------------------------------------------------
# bounded process execution

class WinJob:
    """A Windows job object that owns a process and all its descendants; terminating it ends
    the whole tree, whatever the processes did with their handles."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.CreateJobObjectW.restype = wintypes.HANDLE
        self.k.OpenProcess.restype = wintypes.HANDLE
        self.handle = self.k.CreateJobObjectW(None, None)

        class Limits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class Io(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

        class Extended(ctypes.Structure):
            _fields_ = [("Basic", Limits), ("Io", Io), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = Extended()
        info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        self.k.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info))

    def assign_and_resume(self, pid: int) -> bool:
        """Assigns a process created suspended, then resumes it: it cannot start a child
        before it belongs to the job. False (process left suspended) if either step fails."""
        import ctypes
        # PROCESS_TERMINATE | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME
        h = self.k.OpenProcess(0x0001 | 0x0100 | 0x0800, False, pid)
        if not h:
            return False
        try:
            if not self.k.AssignProcessToJobObject(self.handle, h):
                return False
            ntdll = ctypes.WinDLL("ntdll")
            return ntdll.NtResumeProcess(h) == 0
        finally:
            self.k.CloseHandle(h)

    def terminate(self) -> None:
        self.k.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        self.k.CloseHandle(self.handle)


def run_bounded(cmd: list[str], cwd: Path, env: dict, timeout: float, capture: Path,
                kill_signal: str = "TERM", rlimit_as_kb: int | None = None) -> dict:
    """Runs a command in its own process group/session with a deadline. Output goes to a
    file (`capture`), never a pipe, so no reader can block on a descendant that keeps the
    stream open. On expiry the group is signalled (WSL) or the tree killed (Windows), given
    GRACE_S, then killed; a process that still survives is reported as `unreaped` and left
    behind rather than waited for."""
    def preexec():
        if rlimit_as_kb:
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (rlimit_as_kb * 1024, rlimit_as_kb * 1024))

    if SIDE == "wsl":
        kwargs = {"start_new_session": True, "preexec_fn": preexec if rlimit_as_kb else None}
    else:
        # Created suspended, put into the job, then resumed (WinJob.assign_and_resume).
        kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004}
    started = time.time()
    t0 = time.monotonic()
    usage0 = None
    if SIDE == "wsl":
        import resource
        usage0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    job = WinJob() if SIDE == "windows" else None
    with open(capture, "wb") as fh:
        try:
            p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=fh, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, **kwargs)
        except OSError as e:
            if job:
                job.close()
            return {"termination": "not_started", "reason": type(e).__name__, "stdout": b"",
                    "started_at": started, "finished_at": time.time(), "wall_s": "0.000"}
        in_job = False
        if job:
            in_job = job.assign_and_resume(p.pid)
            if not in_job:
                # Fail closed: without ownership of the tree the attempt does not run.
                p.kill()
                p.wait()
                job.close()
                capture_text = b""
                return {"termination": "not_started", "reason": "job_assignment_failed",
                        "stdout": capture_text, "started_at": started, "finished_at": time.time(),
                        "wall_s": "0.000"}
        termination = "exited"
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            termination = "timeout" if kill_signal == "TERM" else "terminated_by_runner"
            for sig in ([kill_signal, "KILL"] if kill_signal == "TERM" else ["KILL"]):
                if SIDE == "wsl":
                    try:
                        os.killpg(p.pid, signal.SIGKILL if sig == "KILL" else signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                else:
                    if in_job:
                        job.terminate()
                    try:
                        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=GRACE_S)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                    if sig == "KILL":
                        p.kill()
                try:
                    p.wait(timeout=GRACE_S)
                    break
                except subprocess.TimeoutExpired:
                    continue
            else:
                termination = "unreaped"
    if job:
        if in_job:
            job.terminate()  # no descendant outlives the attempt
        job.close()
    out = capture.read_bytes()
    cleanup = {}
    try:
        capture.unlink(missing_ok=True)
    except OSError:
        # A descendant still holds the file: keep it, report it, and record the attempt.
        kept = capture.with_name(f"{capture.name}.{int(time.time() * 1000)}.kept")
        try:
            capture.rename(kept)
        except OSError:
            pass
        cleanup = {"cleanup": "capture_held_open"}
    wall = time.monotonic() - t0
    rc = p.returncode
    res = {"termination": termination, "stdout": out, "started_at": started,
           "finished_at": time.time(), "wall_s": f"{wall:.3f}", **cleanup}
    if job is not None:
        res["process_tree"] = "job"
    if rc is not None and rc < 0:
        res["posix_signal"] = -rc
        if termination == "exited":
            res["termination"] = "terminated_externally"
    elif rc is not None:
        res["exit_code"] = rc
    if usage0 is not None:
        import resource
        u = resource.getrusage(resource.RUSAGE_CHILDREN)
        res["cpu_s"] = f"{(u.ru_utime - usage0.ru_utime) + (u.ru_stime - usage0.ru_stime):.3f}"
        res["cpu_scope"] = "process_and_waited_children"
    return res


# ---------------------------------------------------------------------------------------
# prepare, campaign, mutate, build

def git(args: list[str], cwd: Path) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return r.stdout.decode().strip()


def prepare(cfg: Config) -> None:
    (cfg.work / "src").mkdir(parents=True, exist_ok=True)
    wanted = {d["source"]: d.get("tag") for d in designs().values() if d["source"] in cfg.sources}
    for name, tag in wanted.items():
        dest = cfg.work / "src" / name
        if not dest.exists():
            git(["clone", "--quiet", "--no-hardlinks", str(cfg.sources[name]), str(dest)], cfg.work)
        if tag:
            git(["checkout", "--quiet", "--force", tag], dest)
        for c in cfg.copy_into.get(name, []):
            s, t = Path(c["from"]).expanduser(), dest / c["to"]
            if not s.exists():
                die(f"copy_into source for {name} is missing")
            if not t.exists():
                shutil.copytree(s, t, symlinks=True)
        print(f"prepared {name} ({tag or 'HEAD'})")


def campaign_id(cfg: Config) -> str:
    p = cfg.out.path("campaign.json")
    if not p.exists():
        die("no campaign; run 'corpus.py campaign' first")
    return json.loads(p.read_text(encoding="utf-8"))["id"]


def cmd_campaign(cfg: Config) -> None:
    cid = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"-{SIDE}"
    cfg.out.write_text(json.dumps({"id": cid, "started_at": time.time()}), "campaign.json")
    print(f"campaign {cid}")


def apply_variant(cfg: Config, design: dict, variant: str) -> str:
    """Resets the private checkout and applies the variant; returns the source revision."""
    src = cfg.work / "src" / design["source"]
    git(["checkout", "--quiet", "--", "."], src)
    rev = git(["rev-parse", "HEAD"], src)
    if variant == "clean":
        return rev
    kind, mid = variant.split(":", 1)
    if kind != "mutant":
        die(f"unknown variant {variant}")
    for e in mutations()[0][mid]["edits"]:
        p = src / e["file"]
        text = p.read_text(encoding="utf-8")
        if text.count(e["find"]) != 1:
            die(f"mutation {mid}: anchor found {text.count(e['find'])} times in {e['file']}")
        p.write_text(text.replace(e["find"], e["replace"]), encoding="utf-8", newline="\n")
    return rev


def subst(arg: str, values: dict) -> list[str]:
    if arg == "{plusargs}":
        return list(values.get("plusargs", []))
    for k, v in values.items():
        if isinstance(v, str):
            arg = arg.replace("{" + k + "}", v)
    return [arg]


def expand(cmd: list[str], values: dict) -> list[str]:
    out = []
    for a in cmd:
        out += subst(a, values)
    return out


def as_list(v) -> list:
    return [] if v is None else [v] if isinstance(v, str) else list(v)


def build_dir(cfg: Config, design_id: str, sim: str, variant: str, test: str = "") -> Path:
    name = f"{design_id}-{sim}-{variant.replace(':', '-')}" + (f"-{test}" if test else "")
    return cfg.work_dir("builds", name)


def do_build(cfg: Config, design_id: str, sim: str, variant: str, test: str = "") -> dict:
    """Builds one variant. States: ok, compile_failed (the design's own compile failed, by
    its marker), failed (a build command failed; meaningful where exit status is), and
    infra_failed (a tool did not start, timed out, or success could not be proven)."""
    d = designs()[design_id]
    simdef = d["sim"][sim]
    bdir = build_dir(cfg, design_id, sim, variant, test)
    if bdir.is_symlink():
        die(f"build directory {bdir.name} is a link")
    if bdir.exists():
        shutil.rmtree(bdir, ignore_errors=True)
    bdir.mkdir(parents=True)
    cfg.work_dir("builds", bdir.name)
    src = cfg.work / "src" / d["source"]
    # A one-run list for builds through a combined build-and-run target, outside the build
    # directory (such a target may delete and recreate it).
    one = cfg.work_dir("lists", "one-run-list.txt")
    one.write_text("hexk_ref_pass_test | 1 | +ref_mode=mixed | PASSED |\n", encoding="utf-8", newline="\n")
    values = {"src": src.as_posix(), "build": bdir.as_posix(), "test": test, "one_run_list": one.as_posix(),
              "corpus": CORPUS.as_posix()}
    rev = apply_variant(cfg, d, variant)
    started = time.time()
    out_bytes = b""
    state = "ok"
    exit_meaningful = simdef.get("build_exit_meaningful", True)
    for cmd in simdef.get("build", []):
        cwd = Path(subst(simdef.get("build_cwd", "{build}"), values)[0])
        r = run_bounded(expand(cmd, values), cwd, cfg.env(), BUILD_TIMEOUT_S, cfg.work_dir("tmp", "build.out"))
        out_bytes += r["stdout"]
        if r["termination"] != "exited":
            state = "infra_failed"
            break
        if exit_meaningful and r.get("exit_code") != 0:
            state = "failed"
            break
    if "build_failed_if" in simdef and re.search(simdef["build_failed_if"].encode(), out_bytes, re.M):
        state = "compile_failed"
    elif state == "ok":
        if "build_ok_if" in simdef and not re.search(simdef["build_ok_if"].encode(), out_bytes, re.M):
            state = "infra_failed"
        missing = [a for a in as_list(simdef.get("build_ok")) if not Path(subst(a, values)[0]).exists()]
        if missing:
            state = "infra_failed"
    (bdir / "build-output.txt").write_bytes(out_bytes)
    return {"state": state, "dir": bdir.as_posix(), "started_at": started, "finished_at": time.time(),
            "source_rev": rev, "output_sha256": hashlib.sha256(out_bytes).hexdigest()}


# ---------------------------------------------------------------------------------------
# run one case with runner facts

_TOOL_VERSIONS: dict = {}

TOOL_VERSION = {
    "questa": (["vlog", "-version"], r"vlog (\d[\w.]*)"),
    "vcs": (["vcs", "-full64", "-ID"], r"script version\s*:\s*(\S+)"),
    "verilator": (["verilator", "--version"], r"Verilator (\S+)"),
}


def tool_version(cfg: Config, sim: str) -> str:
    if sim not in _TOOL_VERSIONS:
        cmd, pattern = TOOL_VERSION[sim]
        try:
            r = subprocess.run(cmd, env=cfg.env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            m = re.search(pattern, r.stdout.decode("utf-8", "replace"))
            _TOOL_VERSIONS[sim] = m.group(1) if m else "unknown"
        except (OSError, subprocess.TimeoutExpired):
            _TOOL_VERSIONS[sim] = "unavailable"
    return _TOOL_VERSIONS[sim]


def run_case(cfg: Config, campaign: str, group: dict, sim: str, n: int, run: dict, build: dict) -> dict:
    d = designs()[group["design"]]
    simdef = d["sim"][sim]
    _, faults = mutations()
    fault = faults.get(group.get("fault", ""), {})
    cid = case_id(group, sim, n)
    for suffix in (".log", ".build.log", ".stdout"):
        p = cfg.out.path("fixtures", cid + suffix)
        if p.exists():
            p.unlink()
    facts = {"format": FORMAT, "case": cid, "campaign": campaign, "group": group["id"], "sim": sim, "side": SIDE,
             "run": run_key(run), "variant": group["variant"], "fault": group.get("fault"),
             "definition": definition_digest(group, sim, run), "tool_version": tool_version(cfg, sim),
             "build": {k: v for k, v in build.items() if k != "dir"}}
    cfg.out.copy_in(Path(build["dir"]) / "build-output.txt", "fixtures", f"{cid}.build.log")
    if build["state"] != "ok":
        facts["runner"] = {"termination": "not_run", "reason": f"build {build['state']}"}
        return facts
    test = fault.get("replace_test", run["test"])
    plusargs = run["plusargs"] + fault.get("extra_plusargs", [])
    log = cfg.out.path("fixtures", f"{cid}.log")
    values = {"src": (cfg.work / "src" / d["source"]).as_posix(), "build": build["dir"], "test": test,
              "seed": run["seed"], "plusargs": plusargs, "log": log.as_posix()}
    log_from = simdef.get("log_from")
    candidates = [] if log_from in (None, "stdout") else as_list(log_from)
    for cand in candidates:  # never pick up the log of an earlier run
        Path(subst(cand, values)[0]).unlink(missing_ok=True)
    r = run_bounded(expand(simdef["run"], values), Path(subst(simdef.get("run_cwd", "{build}"), values)[0]),
                    cfg.env(), fault.get("timeout_s", RUN_TIMEOUT_S), cfg.work_dir("tmp", "run.out"),
                    fault.get("signal", "TERM"), fault.get("ulimit_v_kb") if SIDE == "wsl" else None)
    stdout = r.pop("stdout")
    if log_from == "stdout":
        cfg.out.write_bytes(stdout, "fixtures", f"{cid}.log")
    else:
        cfg.out.write_bytes(stdout, "fixtures", f"{cid}.stdout")
        for cand in candidates:
            src_log = Path(subst(cand, values)[0])
            if src_log.exists():
                cfg.out.copy_in(src_log, "fixtures", f"{cid}.log")
                break
    facts["runner"] = r
    facts["evidence"] = {}
    for stream, suffix in (("log", ".log"), ("build_log", ".build.log"), ("stdout", ".stdout")):
        p = cfg.out.path("fixtures", cid + suffix)
        if p.exists():
            facts["evidence"][stream] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    facts["log_exists"] = facts["evidence"].get("log", {}).get("bytes", 0) > 0
    return facts


def finish_facts(cfg: Config, facts: dict) -> None:
    if "evidence" not in facts:
        p = cfg.out.path("fixtures", f"{facts['case']}.build.log")
        facts["evidence"] = {"build_log": {"sha256": sha256_file(p), "bytes": p.stat().st_size}}
        facts["log_exists"] = False
    cfg.out.write_text(json.dumps(facts, indent=1), "runs", f"{facts['case']}.json")


# ---------------------------------------------------------------------------------------
# oracles (independent of DVIScope)

SEEN = re.compile(r"(\S+):([WEF]) seen (\d+)")
BANNER = re.compile(r"SIMULATION (PASSED|FAILED)")
QUIRK_CRASH = re.compile(
    r"internal error|segmentation fault|sigsegv|core dumped|assertion .* failed|stack trace|pt\.c:"
    r"|null pointer dereferenced", re.IGNORECASE)
QUIRK_RESULT = re.compile(r"^\s*(?:#\s*)?QUIRK_RESULT:\s*(AS_EXPECTED|DIFFERS)", re.MULTILINE)


def read_fixture(cfg: Config, cid: str, suffix: str) -> str:
    p = cfg.out.path("fixtures", cid + suffix)
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def oracle_hexk(cfg: Config, design: dict, facts: dict, entry: dict) -> dict:
    log = cfg.out.path("fixtures", f"{facts['case']}.log")
    script = cfg.work / "src" / design["source"] / "scripts" / "hexk_check_run.py"
    verdict = entry.get("verdict") or "PASSED"
    if not facts.get("log_exists"):
        return {"as_expected": False, "verdict": None, "seen": {}}
    runner = facts["runner"]
    rc_exit = runner.get("exit_code", 1) if runner["termination"] == "exited" else 124
    r = subprocess.run([cfg.python, str(script), "--exit-status", str(rc_exit), str(log), verdict,
                        *entry.get("expect", [])], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    text = r.stdout.decode("utf-8", "replace")
    seen = {f"{m.group(1)}:{m.group(2)}": int(m.group(3)) for m in SEEN.finditer(text)}
    m = None
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        m = BANNER.search(line) or m
    return {"as_expected": r.returncode == 0, "verdict": m.group(1) if m else "NONE", "seen": seen}


def oracle_line(cfg: Config, facts: dict, pattern: str) -> dict:
    """Last verdict line of the log (the SVUnit runner summary, the self-check program)."""
    v = None
    for line in read_fixture(cfg, facts["case"], ".log").splitlines():
        m = re.search(pattern, line)
        v = m.group(1) if m else v
    return {"verdict": v}


def oracle_quirk(cfg: Config, design: dict, facts: dict, run: dict) -> dict:
    """Same rules as hexk-sv-sim-quirks' runner (sqrun.py), for the trigger build only."""
    expected = load_toml(cfg.work / "src" / design["source"] / "quirks" / run["test"] / "quirk.toml")
    want = expected.get("expected", {}).get(facts["sim"])
    legal = expected.get("trigger_legal", True)
    runner = facts.get("runner", {})
    state = facts["build"]["state"]
    build_text = read_fixture(cfg, facts["case"], ".build.log")
    result_line = False
    if facts["sim"] in expected.get("skip", []):
        got, want = "n/a", want or "n/a"
    elif state == "infra_failed":
        got = "infra"
    elif state != "ok" and QUIRK_CRASH.search(build_text):
        got = "crash"
    elif state != "ok":
        got = "ok" if not legal else "rejects"
    elif not legal:
        got = "accepts"
    elif expected.get("kind") == "compile":
        got = "ok"
    elif runner.get("termination") not in ("exited", "terminated_externally"):
        got = "infra"
    else:
        text = read_fixture(cfg, facts["case"], ".log")
        m = QUIRK_RESULT.search(text)
        result_line = bool(m)
        if m:
            got = "ok" if m.group(1) == "AS_EXPECTED" else "differs"
        elif "posix_signal" in runner or (runner.get("exit_code") or 0) >= 0xC0000000 or QUIRK_CRASH.search(text):
            got = "crash"
        else:
            got = "no-result"
    return {"expected": want, "observed": got, "result_line": result_line}


def apply_oracle(cfg: Config, d: dict, facts: dict, run: dict, entry: dict) -> dict:
    if d["oracle"] == "hexk_check_run":
        return oracle_hexk(cfg, d, facts, entry)
    if d["oracle"] == "svunit":
        return oracle_line(cfg, facts, r"\[testrunner\]: (PASSED|FAILED)")
    if d["oracle"] == "selfcheck":
        return oracle_line(cfg, facts, r"^SELFCHECK (PASSED|FAILED)")
    if d["oracle"] == "quirk":
        return oracle_quirk(cfg, d, facts, run)
    return die(f"unknown oracle {d['oracle']}")


# ---------------------------------------------------------------------------------------
# judging: fault-specific evidence, never just "something failed"

def mentions(text: str, needle: str) -> bool:
    return needle.lower() in text.lower()


def judge(cfg: Config, expect, facts: dict, o: dict) -> tuple[bool, list[str]]:
    r = facts["runner"]
    state = facts["build"]["state"]
    cid = facts["case"]
    exited = r.get("termination") == "exited" and "posix_signal" not in r
    why: list[str] = []
    if expect == "list":
        if state != "ok":
            why.append(f"build {state}")
        if not exited:
            why.append(f"run {r.get('termination')}")
        if not o.get("as_expected"):
            why.append("oracle reports a difference from the list")
        return not why, why
    if "quirk" in expect:
        ok = o["observed"] == o["expected"] and o["observed"] != "infra"
        return ok, [] if ok else [f"observed {o['observed']}, expected {o['expected']}"]
    if expect.get("build") == "fail":
        if state != "compile_failed":
            why.append(f"build {state}, not a compile failure")
        if "mentions" in expect and not mentions(read_fixture(cfg, cid, ".build.log"), expect["mentions"]):
            why.append("compile errors do not name the mutated file")
        return not why, why
    if "build_or_runs" in expect:
        if state == "compile_failed":
            if "mentions" in expect and not mentions(read_fixture(cfg, cid, ".build.log"), expect["mentions"]):
                why.append("compile errors do not name the mutated file")
        elif state == "ok":
            text = read_fixture(cfg, cid, ".log")
            if not exited:
                why.append(f"run {r.get('termination')}")
            if not mentions(text, expect["run_marker"]):
                why.append("run did not fail to load the design")
            if "mentions" in expect and not mentions(text, expect["mentions"]):
                why.append("load errors do not name the mutated file")
        else:
            why.append(f"build {state}")
        return not why, why
    if "runner" in expect:
        want = expect["runner"]
        if state != "ok":
            why.append(f"build {state}")
        elif want == "timeout" and r.get("termination") != "timeout":
            why.append(f"run {r.get('termination')}, not the runner's timeout")
        elif want == "killed" and not (r.get("termination") == "terminated_by_runner"
                                       and (SIDE == "windows" or r.get("posix_signal") == 9)):
            why.append(f"run {r.get('termination')}, not killed by the runner")
        return not why, why
    # Verdict expectations: a completed run of a good build, then the oracle's answer.
    if state != "ok":
        why.append(f"build {state}")
    if not exited:
        why.append(f"run {r.get('termination')}")
    want = expect.get("verdict")
    if want is not None and o.get("verdict") != want:
        why.append(f"verdict {o.get('verdict')} != {want}")
    if want == "PASSED" and r.get("exit_code") != 0:
        why.append("passing run exited non-zero")
    for inc in expect.get("include", []):
        if o.get("seen", {}).get(inc, 0) <= 0:
            why.append(f"{inc} not seen")
    if expect.get("oracle_fails") and o.get("as_expected"):
        why.append("oracle did not fail")
    if expect.get("exit") == "nonzero" and r.get("exit_code") in (None, 0):
        why.append("no non-zero exit status")
    if expect.get("log") == "partial" and not facts.get("log_exists"):
        why.append("no log")
    if "mentions_any" in expect:
        text = read_fixture(cfg, cid, ".log") + read_fixture(cfg, cid, ".stdout")
        if not any(mentions(text, w) for w in expect["mentions_any"]):
            why.append("no fault-specific message")
    return not why, why


def classify_data_dependent(expect: dict, facts: dict, o: dict) -> tuple[bool | None, list[str]]:
    """A run of a data-dependent mutant is either activated (a completed failing run with the
    declared diagnostics) or a clean pass; anything else is not labelled."""
    r = facts["runner"]
    exited = r.get("termination") == "exited" and "posix_signal" not in r
    if facts["build"]["state"] != "ok" or not exited:
        return None, [f"build {facts['build']['state']} / run {r.get('termination')}"]
    if o.get("verdict") == "FAILED" and all(o.get("seen", {}).get(i, 0) > 0 for i in expect.get("include", [])):
        return True, []
    if o.get("verdict") == "PASSED" and o.get("as_expected"):
        return False, []
    return None, ["neither an activated failure nor a clean pass"]


# ---------------------------------------------------------------------------------------
# commands

def cmd_run(cfg: Config, gid: str, sims: list[str] | None) -> None:
    campaign = campaign_id(cfg)
    group = group_by_id(gid)
    d = designs()[group["design"]]
    runs = group_runs(cfg, group)
    for sim in group["sims"]:
        if sims and sim not in sims:
            continue
        if d["sim"][sim]["side"] != SIDE:
            print(f"{gid} {sim}: runs on the {d['sim'][sim]['side']} side; skipped here")
            continue
        per_test = any("{test}" in " ".join(c) for c in d["sim"][sim].get("build", []))
        build = None
        if not per_test:
            build = do_build(cfg, group["design"], sim, group["variant"])
            print(f"{gid} {sim}: build {build['state']}")
        for n, run in enumerate(runs, 1):
            b = do_build(cfg, group["design"], sim, group["variant"], run["test"]) if per_test else build
            facts = run_case(cfg, campaign, group, sim, n, run, b)
            finish_facts(cfg, facts)
            print(f"{facts['case']}: {facts['runner'].get('termination')} build={b['state']}")
        apply_variant(cfg, d, "clean")


def finished_at(facts: dict) -> float:
    return facts["runner"].get("finished_at") or facts["build"]["finished_at"]


def cmd_label(cfg: Config) -> None:
    """Applies the oracles and earns labels within the current campaign; writes the private
    label results (`manifest-<side>.json`)."""
    campaign = campaign_id(cfg)
    ds = designs()
    facts_by_case = {}
    for p in cfg.out.path("runs").glob("*.json"):
        f = json.loads(p.read_text(encoding="utf-8"))
        if f.get("format") == FORMAT and f.get("campaign") == campaign:
            facts_by_case[f["case"]] = f
    revs = {}
    results = {}
    for group in groups():
        d = ds[group["design"]]
        src = cfg.work / "src" / d["source"]
        if not src.exists() or not any(d["sim"][s]["side"] == SIDE for s in group["sims"]):
            continue
        revs.setdefault(d["source"], git(["rev-parse", "HEAD"], src))
        runs = group_runs(cfg, group)
        entries = {run_key(r): r for r in design_list(cfg, d)} if "list" in d else {}
        expect = group["expect"]
        data_dependent = isinstance(expect, dict) and expect.get("any_fails")
        for sim in group["sims"]:
            if d["sim"][sim]["side"] != SIDE:
                continue
            for n, run in enumerate(runs, 1):
                cid = case_id(group, sim, n)
                f = facts_by_case.get(cid)
                if not f:
                    results[cid] = {"group": group["id"], "sim": sim, "state": "not_run", "why": ["not run"]}
                    continue
                stale = []
                if f["definition"] != definition_digest(group, sim, run):
                    stale.append("case definition changed since the run")
                if f["build"]["source_rev"] != revs[d["source"]]:
                    stale.append("source revision changed since the run")
                o = apply_oracle(cfg, d, f, run, entries.get(run_key(run)) or run)
                activated = None
                if data_dependent:
                    activated, why = classify_data_dependent(expect, f, o)
                    ok = activated is not None
                else:
                    ok, why = judge(cfg, expect, f, o)
                results[cid] = {"group": group["id"], "sim": sim, "run": run_key(run), "oracle": o,
                                "facts_digest": digest_json(f),
                                "judged": ok and not stale, "why": stale + why, "run_activated": activated,
                                "facts": f}
        if data_dependent:
            for sim in group["sims"]:
                mine = [r for r in results.values()
                        if r.get("group") == group["id"] and r.get("sim") == sim and "judged" in r]
                if mine and not any(r.get("run_activated") for r in mine):
                    for r in mine:
                        r["judged"] = False
                        r["why"].append("no run of the group activated the mutant")
    # Earned labels: control passed, activation, recovery started after the mutant finished.
    for cid, r in results.items():
        if "judged" not in r:
            continue
        group = group_by_id(r["group"])
        label = r["judged"]
        reasons = list(r["why"])
        links = {}
        for rel in ("control", "recovery"):
            if rel not in group:
                continue
            other_id, other = find_same_run(results, group[rel], r["sim"], r["run"])
            links[rel] = other_id
            if not other or not other.get("judged"):
                label = False
                reasons.append(f"{rel} {group[rel]} not passed for this run")
            elif rel == "recovery" and other["facts"]["build"]["started_at"] < finished_at(r["facts"]):
                label = False
                reasons.append("recovery started before the mutant finished")
        r["labelled"] = label
        r["reasons"] = reasons
        r["links"] = links
    out = {"format": FORMAT, "side": SIDE, "campaign": campaign, "definitions": definitions_digest(),
           "source_revs": revs, "cases": results}
    cfg.out.write_text(json.dumps(out, indent=1), f"manifest-{SIDE}.json")
    total = sum(1 for r in results.values() if "labelled" in r)
    good = sum(1 for r in results.values() if r.get("labelled"))
    print(f"label: {good}/{total} cases labelled; {sum(1 for r in results.values() if r.get('state') == 'not_run')} not run (campaign {campaign})")
    for cid, r in sorted(results.items()):
        if "labelled" in r and not r["labelled"]:
            print(f"  {cid}: unlabelled ({'; '.join(r['reasons'])})")


def find_same_run(results: dict, gid: str, sim: str, key: str) -> tuple[str | None, dict | None]:
    for cid, r in results.items():
        if r.get("group") == gid and r.get("sim") == sim and r.get("run") == key:
            return cid, r
    return None, None


def cmd_ids(cfg: Config) -> None:
    """Prints the case IDs (structural: group, simulator, index); never names or log text."""
    print("# Public case IDs that simulator-backed tests may print.")
    print("# Generated by 'corpus/harness/corpus.py --config ... ids'; do not edit.")
    for g in groups():
        print(g["id"])
        count = len(group_runs(cfg, g))
        for sim in g["sims"]:
            for n in range(1, count + 1):
                print(case_id(g, sim, n))


# ---------------------------------------------------------------------------------------
# corpus manifest (D.12: dviscope.corpus/1) and applicability matrix

def case_classes(group: dict) -> list[str]:
    """Fault classes a case covers: its mutation's and its runtime fault's (or control)."""
    muts, faults = mutations()
    out = []
    if group["variant"].startswith("mutant:"):
        out.append(muts[group["variant"].split(":", 1)[1]]["class"])
    if group.get("fault"):
        out.append(faults[group["fault"]]["class"])
    return out or ["control"]


def toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return f"{v:.3f}"
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{toml_key(k)} = {toml_value(x)}" for k, x in v.items() if x is not None) + " }"
    return json.dumps(str(v), ensure_ascii=False)


def toml_key(k: str) -> str:
    return k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k)


def required_evidence(facts: dict, simdef: dict) -> list[str]:
    """Evidence streams each attempt must have: the build log always; for a run, its console
    (or the log, when the log is the console), and the log whenever one was recorded."""
    need = ["build_log"]
    if facts["runner"].get("termination") != "not_run":
        need.append("log" if simdef.get("log_from") == "stdout" else "stdout")
        if facts.get("log_exists"):
            need.append("log")
    return sorted(set(need))


def cmd_manifest(cfg: Config, sides: dict[str, Path], out: Path, partial: bool) -> None:
    """Merges the sides' label results into the corpus manifest and validates it: the full
    case inventory (every case present once and labelled), applicability (every case in an
    applicable cell, every applicable cell covered, a reason for every other cell), and the
    digests of every evidence stream (the replay manifest)."""
    if out.is_symlink():
        die("--out is a link")
    outside_repo(out)
    outside_repo(out.parent)
    matrix = load_toml(CORPUS / "matrix.toml")
    ds = designs()
    errors = []
    side_data = {}
    for side, d in sides.items():
        f = d / f"manifest-{side}.json"
        if not f.exists():
            errors.append(f"no label results for side {side}")
            continue
        data = json.loads(f.read_text(encoding="utf-8"))
        if data.get("format") != FORMAT:
            errors.append(f"label results of side {side} have an old format")
            continue
        current = json.loads((d / "campaign.json").read_text(encoding="utf-8"))["id"] \
            if (d / "campaign.json").exists() else None
        if data.get("campaign") != current:
            errors.append(f"label results of side {side} are not from its current campaign")
        if data.get("definitions") != definitions_digest():
            errors.append(f"label results of side {side} were made under other corpus definitions; run label again")
        side_data[side] = data
    cells = {}
    for pair in matrix["pair"]:
        for cls in matrix["classes"]:
            key = (pair["design"], pair["sim"], cls)
            if "deferred" in pair:
                cells[key] = ("deferred", pair["deferred"])
            elif cls in pair.get("apply", []):
                cells[key] = ("apply", "")
            else:
                reason = pair.get("reasons", {}).get(cls) or pair.get("default_reason")
                if not reason:
                    errors.append(f"cell {key} is neither applicable nor has a reason")
                cells[key] = ("unsupported", reason or "")
    for did, d in ds.items():
        for sim in d.get("sim", {}):
            if not any(k[0] == did and k[1] == sim for k in cells):
                errors.append(f"design {did} on {sim} is missing from matrix.toml")
    # The required inventory, independent of what was run.
    required = {}
    for g in groups():
        d = ds[g["design"]]
        n_runs = len(group_runs(cfg, g))
        for sim in g["sims"]:
            for n in range(1, n_runs + 1):
                required[case_id(g, sim, n)] = (g, sim, d["sim"][sim]["side"])
    for side in sorted({side for _, _, side in required.values()} - set(side_data)):
        msg = f"side {side} not supplied: its required cases and cells are not validated"
        if partial:
            print(f"  partial: {msg}")
        else:
            errors.append(msg)
    seen = {}
    for side, data in side_data.items():
        for cid, r in data["cases"].items():
            if cid in seen:
                errors.append(f"{cid}: present on {seen[cid]} and {side}")
            seen[cid] = side
    for cid, (g, sim, side) in required.items():
        if side not in side_data:
            continue
        r = side_data[side]["cases"].get(cid)
        if r is None or "labelled" not in r:
            errors.append(f"{cid}: missing or not run")
        elif not r["labelled"]:
            errors.append(f"{cid}: not labelled")
    for cid in seen:
        if cid not in required:
            errors.append(f"{cid}: not in cases.toml")
    cases = []
    covered = set()
    for side, data in side_data.items():
        for cid, r in sorted(data["cases"].items()):
            if "labelled" not in r:
                continue
            g = group_by_id(r["group"])
            f = r["facts"]
            classes = case_classes(g)
            spec = required.get(cid)
            if spec:
                runs_now = group_runs(cfg, g)
                n = int(cid.rsplit("-", 1)[1])
                if f.get("definition") != definition_digest(g, r["sim"], runs_now[n - 1]):
                    errors.append(f"{cid}: case definition changed since the run")
            if f.get("campaign") != data.get("campaign"):
                errors.append(f"{cid}: evidence from another campaign")
            current = sides[side] / "runs" / f"{cid}.json"
            if not current.exists() or r.get("facts_digest") != digest_json(json.loads(current.read_text(encoding="utf-8"))) \
                    or r.get("facts_digest") != digest_json(f):
                errors.append(f"{cid}: run facts changed since labelling; run label again")
            simdef = ds[g["design"]]["sim"][r["sim"]]
            for stream in required_evidence(f, simdef):
                if stream not in f.get("evidence", {}):
                    errors.append(f"{cid}: required evidence {stream} missing")
            for cls in classes:
                cell = (g["design"], r["sim"], cls)
                state = cells.get(cell, ("missing", ""))[0]
                if state != "apply":
                    errors.append(f"{cid}: cell {cell} is {state}")
                data_dependent = isinstance(g["expect"], dict) and g["expect"].get("any_fails")
                if r["labelled"] and (not data_dependent or r.get("run_activated")):
                    covered.add(cell)
            evidence = {}
            for stream, ev in f.get("evidence", {}).items():
                suffix = {"log": ".log", "build_log": ".build.log", "stdout": ".stdout"}[stream]
                p = sides[side] / "fixtures" / f"{cid}{suffix}"
                if not p.exists():
                    errors.append(f"{cid}: {stream} missing")
                elif sha256_file(p) != ev["sha256"]:
                    errors.append(f"{cid}: {stream} digest differs")
                evidence[stream] = {"sha256": ev["sha256"], "location": f"private:{side}/fixtures/{cid}{suffix}"}
            o = r["oracle"]
            run = f["runner"]
            cases.append({
                "id": cid, "side": side, "campaign": f["campaign"], "design": g["design"], "sim": r["sim"],
                "tool_version": f["tool_version"], "source_rev": f["build"]["source_rev"],
                "definition": f["definition"], "classes": classes, "variant": g["variant"], "group": g["id"],
                "run_key": r["run"], "build_state": f["build"]["state"], "evidence": evidence,
                "runner": {k: v for k, v in run.items()
                           if k in ("termination", "exit_code", "posix_signal", "wall_s", "cpu_s", "cpu_scope", "reason")},
                "links": r.get("links", {}),
                "label": {
                    "earned": r["labelled"],
                    "observed_verdict": o.get("verdict") or o.get("observed") or "",
                    "expected": json.dumps(g["expect"], sort_keys=True),
                    "completion": {"termination": run.get("termination"),
                                   "verdict_line": o["result_line"] if "result_line" in o
                                   else o.get("verdict") not in (None, "NONE")},
                    "run_activated": r.get("run_activated"),
                    "families": o.get("seen", {}),
                },
                "expectation_ref": "",
            })
    for cell, (state, _) in cells.items():
        side_of = ds.get(cell[0], {}).get("sim", {}).get(cell[1], {}).get("side")
        if state == "apply" and cell not in covered and side_of in side_data:
            errors.append(f"applicable cell {cell} has no labelled (activated) case")
    lines = ["# DVIScope corpus manifest (PRIVATE: generated by corpus.py manifest; never committed).",
             'schema = "dviscope.corpus/1"', f"repetitions = {matrix['repetitions']}", ""]
    for (design, sim, cls), (state, reason) in sorted(cells.items()):
        lines += ["[[cell]]", f"design = {toml_value(design)}", f"sim = {toml_value(sim)}",
                  f"class = {toml_value(cls)}", f"state = {toml_value(state)}"]
        if reason:
            lines.append(f"reason = {toml_value(reason)}")
        lines.append("")
    for c in cases:
        lines.append("[[case]]")
        for k, v in c.items():
            if v is not None:
                lines.append(f"{toml_key(k)} = {toml_value(v)}")
        lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    load_toml(out)  # the written manifest must parse
    applicable = {k for k, v in cells.items() if v[0] == "apply"}
    print(f"manifest: {len(cases)} cases, {sum(1 for c in cases if c['label']['earned'])} labelled, "
          f"{len(required)} required; {len(applicable)} applicable cells, {len(covered & applicable)} covered; "
          f"{len(cells) - len(applicable)} cells with a reason")
    for e in errors:
        print(f"  error: {e}")
    if errors:
        sys.exit(1)
    if partial and set(side_data) != {side for _, _, side in required.values()}:
        print("manifest: PARTIAL validation; this is not a qualification of the corpus")
        sys.exit(3)


# ---------------------------------------------------------------------------------------
# extract-check: structural expectations per case, checked by `dviscope rules
# check`, then cross-case pairs. Expectations come from the oracles and runner facts (and
# structure.toml), never from the extractor. Prints case IDs and structural differences only.

EXPECT_FORMAT = "dviscope.expect/1"
FIRST_ERROR = re.compile(r"^(?:# )?First error: @ [\d.]+\w* \[([^\]]+)\]", re.M)
QUESTA_END_TIME = re.compile(r"^(?:# )?End time: \d\d:\d\d:\d\d on ", re.M)
QUESTA_ERRORS = re.compile(r"^# Errors: (\d+), Warnings: \d+\s*$", re.M)
VCS_ERRORS = re.compile(r'^(?:Error-\[|Error: "[^"]+", \d+: \S+: at time |Fatal: "|\[MEM-OUT\] |'
                        r'An unexpected termination)', re.M)
SVUNIT_CHECK = re.compile(r"^ERROR: \[\d+\]\[[^\]]+\]: (\w+):", re.M)
SVUNIT_FAILED = re.compile(r"^INFO:  \[\d+\]\[[^\]]+\]: \w+::FAILED$", re.M)
VERILATOR_RUNTIME = re.compile(r"^\[\d+\w*\] %(?:Error|Fatal)", re.M)


def read_private(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def expectation(group: dict, cid: str, r: dict, fixtures: Path, structure: dict) -> dict:
    """Structural expectation of one case, from its oracle, runner facts and structure.toml."""
    facts = r.get("facts") or {}
    o = r.get("oracle") or {}
    sim = r["sim"]
    design = group["design"]
    term = facts.get("runner", {}).get("termination")
    x = {"format": EXPECT_FORMAT, "simulator": sim, "log": f"{cid}.log"}
    exp = group.get("expect")
    if term == "not_run":
        x.update(subject="build", log=f"{cid}.build.log")
        if isinstance(exp, dict) and exp.get("mentions"):
            x["failure_anchored_in"] = [exp["mentions"]]
        return x
    log = read_private(fixtures / f"{cid}.log")
    if design == "hexk-ref":
        seen = o.get("seen") or {}
        x["failures"] = {f"uvm:{k.split(':')[0]}": n for k, n in seen.items() if k.endswith((":E", ":F"))}
        verdict = o.get("verdict")
        if seen or verdict != "FAILED":
            # Run-list negative tests are judged by verdict and counts only (no IDs).
            x["exact_prefixes"] = ["uvm:"]
        fatal = [k.split(":")[0] for k in seen if k.endswith(":F")]
        if term == "exited" and verdict in ("PASSED", "FAILED"):
            x.update(completion="complete", mode="normal", design_loaded="true",
                     verdicts={"banner": "pass" if verdict == "PASSED" else "fail"})
        elif term == "exited" and verdict == "NONE" and fatal:
            x.update(completion="complete", mode="early_fatal", design_loaded="true")
        elif (
            term == "exited"
            and sim == "questa"
            and isinstance(exp, dict)
            and exp.get("run_marker")
            and exp["run_marker"] in log
            and QUESTA_ERRORS.search(log)
            and QUESTA_END_TIME.search(log)
        ):
            # A design that does not load stops the run (Questa: the group's load-failure
            # marker, its error summary and end time): complete through an early fatal.
            x.update(completion="complete", mode="early_fatal")
        elif not log:
            x["completion"] = "missing"
        else:
            x["completion"] = "incomplete"
        if isinstance(exp, dict) and exp.get("run_marker") and exp["run_marker"] in log:
            x["design_loaded"] = "false"
            x["failure_anchored_in"] = [exp["mentions"]]
        if sim == "questa":
            m = QUESTA_ERRORS.findall(log)
            if m:
                x["simulator_errors"] = int(m[-1])
        elif sim == "vcs":
            x["simulator_errors"] = len(VCS_ERRORS.findall(log))
        first = FIRST_ERROR.search(log)
        if fatal:
            x["primary"] = f"uvm:{fatal[0]}"
        elif first and x["failures"]:
            x["primary"] = f"uvm:{first.group(1)}"
        x["max_unclaimed"] = 0
    elif design == "hexk-unit":
        failures: dict[str, int] = {}
        for check in SVUNIT_CHECK.findall(log):
            failures[f"svunit:{check}"] = failures.get(f"svunit:{check}", 0) + 1
        if SVUNIT_FAILED.findall(log):
            failures["svunit:test_failed"] = len(SVUNIT_FAILED.findall(log))
        if VERILATOR_RUNTIME.findall(log):
            failures["sv:severity_task"] = len(VERILATOR_RUNTIME.findall(log))
        x.update(failures=failures, failures_exact=True, completion="complete", mode="normal",
                 verdicts={"svunit_runner": "pass" if o.get("verdict") == "PASSED" else "fail"},
                 max_unclaimed=0)
    elif design == "ibex":
        failed = o.get("verdict") == "FAILED"
        # The design's log holds the program's output only; the simulator trailer is on the
        # console, so the log alone is incomplete.
        x.update(failures={"selfcheck:failed": 1} if failed else {}, failures_exact=True,
                 completion="incomplete")
        if not failed:
            x["verdicts"] = {"test_result": "pass"}
    elif design == "quirks" and o.get("result_line"):
        x["completion"] = "complete"
    x.update(structure.get("group", {}).get(group["id"], {}))
    return x


def evidence_fp(ev: dict, diag_id: str) -> set[str]:
    return {f["fingerprint"] for f in ev.get("families", []) if f["diag_id"] == diag_id}


def event_family(ev: dict, e: dict) -> str:
    """The family fingerprint of an example event (through its bucket)."""
    for b in ev.get("buckets", []):
        if e["ordinal"] in (b.get("example_ordinal"), b.get("first_ordinal")):
            return b["family"]
    return "?"


def required_inventory(cfg: Config) -> dict[str, tuple[dict, str, str]]:
    """Every case the corpus definitions require (independent of what was run or labelled):
    case ID -> (group, simulator, side)."""
    ds = designs()
    required = {}
    for g in groups():
        d = ds[g["design"]]
        n_runs = len(group_runs(cfg, g))
        for sim in g["sims"]:
            for n in range(1, n_runs + 1):
                required[case_id(g, sim, n)] = (g, sim, d["sim"][sim]["side"])
    return required


def cmd_extract_check(cfg: Config, sides: dict[str, Path], dviscope: str, packs: list[str],
                      roots: list[str], work: Path) -> None:
    structure = load_toml(CORPUS / "structure.toml")
    required = required_inventory(cfg)
    work.mkdir(parents=True, exist_ok=True)
    priv = Private(work)
    ok = True
    evidence: dict[str, dict] = {}
    for side in sorted({side for _, _, side in required.values()} - set(sides)):
        print(f"side {side} not supplied: its required cases are not checked")
        ok = False
    for side, out in sides.items():
        data = json.loads((out / f"manifest-{side}.json").read_text(encoding="utf-8"))
        for cid in sorted(c for c, (_, _, sd) in required.items() if sd == side and c not in data["cases"]):
            print(f"  {cid}: required by the corpus definitions but absent from the label results")
            ok = False
        fixtures = (out / "fixtures").resolve()
        exp_dir = priv.path(side, "expect")
        if exp_dir.exists():
            shutil.rmtree(exp_dir)
        exp_dir.mkdir(parents=True)
        n = 0
        written = []
        for cid, r in sorted(data["cases"].items()):
            if not r.get("labelled"):
                # Every case of the inventory must be labelled and checked (no silent skip).
                print(f"  {cid}: not labelled; run the campaign and label first")
                ok = False
                continue
            written.append(cid)
            x = expectation(group_by_id(r["group"]), cid, r, fixtures, structure)
            x["log"] = str(fixtures / x["log"])
            priv.write_text(json.dumps(x, indent=1), side, "expect", f"{cid}.expect.json")
            n += 1
        ev_dir = priv.path(side, "evidence")
        if ev_dir.exists():
            shutil.rmtree(ev_dir)
        binary = str(Path(dviscope).resolve()) if Path(dviscope).exists() else dviscope
        cmd = [binary, "rules", "check", "--sample", str(exp_dir), "--evidence-out", str(ev_dir)]
        for p in packs:
            cmd += ["--pack", p]
        for root in roots:
            cmd += ["--source-root", root]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if res.returncode not in (0, 1):
            die(f"rules check failed on side {side}: exit {res.returncode} {res.stderr.strip()[:300]}")
        report = json.loads(res.stdout)
        ok &= res.returncode == 0
        print(f"side {side}: {report['cases_passed']}/{report['cases']} cases hold their structural "
              f"expectations ({n} written); pack self-test failures: {len(report['self_test_failures'])}")
        secs = sum(c["seconds"] for c in report["results"])
        mb = sum(c["bytes"] for c in report["results"]) / 1e6
        print(f"  extraction: {mb:.1f} MB in {secs:.2f} s ({mb / secs if secs else 0:.1f} MB/s)")
        for c in report["results"]:
            if not c["ok"]:
                print(f"  {c['case']}: " + "; ".join(c["differences"]))
        checked = {c["case"] for c in report["results"]}
        if checked != set(written):
            print(f"  cases written but not checked: {sorted(set(written) - checked)}")
            ok = False
        for cid in written:
            f = ev_dir / f"{cid}.evidence.json"
            if f.exists():
                evidence[cid] = json.loads(f.read_text(encoding="utf-8"))
            else:
                print(f"  {cid}: no evidence produced")
                ok = False
    sims = sorted({c.split("-")[-2] for c in evidence})
    for m in structure.get("merge", []):
        for sim in (sims if any("{sim}" in c for c in m["cases"]) else [None]):
            cases = [c.format(sim=sim) for c in m["cases"]]
            if not all(c in required for c in cases):
                continue  # the pair's groups do not run on this simulator (cases.toml)
            if not all(c in evidence for c in cases):
                print(f"merge {m['diag_id']} {' = '.join(cases)}: CASE MISSING")
                ok = False
                continue
            fps = [evidence_fp(evidence[c], m["diag_id"]) for c in cases]
            same = len(fps[0]) == 1 and all(f == fps[0] for f in fps)
            ok &= same
            print(f"merge {m['diag_id']} {' = '.join(cases)}: {'ok' if same else 'DIFFERENT'}")
    for s in structure.get("separate_by_field", []):
        classes: dict[str, set[str]] = {}
        for ev in evidence.values():
            for e in ev.get("events", []):
                if e["diag_id"] == s["diag_id"]:
                    cls = e.get("significant", {}).get(s["field"], "missing")
                    classes.setdefault(cls, set()).add(event_family(ev, e))
        keys = sorted(classes)
        shared = set()
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                shared |= classes[a] & classes[b]
        good = not shared and len(keys) >= 2
        ok &= good
        print(f"separate {s['diag_id']} by {s['field']}: classes {keys}: {'ok' if good else 'NOT SEPARATED'}")
    merged_sites = 0
    for ev in evidence.values():
        sites: dict[str, set] = {}
        for b in ev.get("buckets", []):
            if b["diag_id"] == "sv:severity_task":
                sites.setdefault(b["family"], set()).add(b.get("site"))
        merged_sites += sum(1 for v in sites.values() if len(v) > 1)
    ok &= merged_sites == 0
    print(f"distinct $error sites in distinct families: {'ok' if merged_sites == 0 else f'{merged_sites} merged'}")
    if not ok:
        sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prepare")
    sub.add_parser("campaign")
    sp = sub.add_parser("run")
    sp.add_argument("--group", required=True)
    sp.add_argument("--sim", action="append")
    sub.add_parser("label")
    sub.add_parser("ids")
    sp = sub.add_parser("manifest")
    sp.add_argument("--side", action="append", required=True, metavar="SIDE=OUT_DIR",
                    help="label results of a side, e.g. wsl=/path/to/out-wsl")
    sp.add_argument("--out", type=Path, required=True)
    sp.add_argument("--partial", action="store_true",
                    help="validate the supplied sides only (exit status 3: not a qualification)")
    sp = sub.add_parser("extract-check")
    sp.add_argument("--side", action="append", required=True, metavar="SIDE=OUT_DIR")
    sp.add_argument("--dviscope", required=True, help="dviscope binary")
    sp.add_argument("--pack", action="append", default=[])
    sp.add_argument("--source-root", action="append", default=[])
    sp.add_argument("--work", type=Path, required=True, help="private directory for expectations and evidence")
    a = ap.parse_args()
    sys.stdout.reconfigure(newline=chr(10))  # LF output on Windows too (public-ids.txt)
    cfg = Config(a.config)
    if a.cmd == "extract-check":
        sides = dict(x.split("=", 1) for x in a.side)
        cmd_extract_check(cfg, {k: Path(v) for k, v in sides.items()}, a.dviscope, a.pack, a.source_root, a.work)
        return
    if a.cmd == "prepare":
        prepare(cfg)
    elif a.cmd == "campaign":
        cmd_campaign(cfg)
    elif a.cmd == "run":
        cmd_run(cfg, a.group, a.sim)
    elif a.cmd == "label":
        cmd_label(cfg)
    elif a.cmd == "ids":
        cmd_ids(cfg)
    elif a.cmd == "manifest":
        sides = dict(x.split("=", 1) for x in a.side)
        cmd_manifest(cfg, {k: Path(v) for k, v in sides.items()}, a.out, a.partial)


if __name__ == "__main__":
    main()
