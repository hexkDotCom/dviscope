"""Stale Questa library locks (finding F22).

A Questa run that is killed leaves ``_lock``/``_opt*__lock`` files in its library
directory, each naming its owner as ``user@HOST, pid = N``. The next run of the same build
waits on them and times out in turn. Before a run, locks held by a process of this host
that no longer exists are removed. A lock of another host, an unreadable lock, or one
whose process still runs (or might: a reused PID is not told apart) is left alone and
reported, never guessed away.
"""

from __future__ import annotations

import os
import re
import socket
import sys
from pathlib import Path

_OWNER = re.compile(r"^\s*(?P<user>[^@\s]+)@(?P<host>[^,\s]+),\s*pid\s*=\s*(?P<pid>\d+)\s*$")


def pid_alive(pid: int) -> bool:
    """Whether a process with this ID exists on this host."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        ERROR_ACCESS_DENIED = 5
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            # Access denied means it exists; anything else (invalid parameter) means not.
            return ctypes.get_last_error() == ERROR_ACCESS_DENIED
        try:
            code = ctypes.c_ulong()
            if not k.GetExitCodeProcess(h, ctypes.byref(code)):
                return True
            return code.value == STILL_ACTIVE
        finally:
            k.CloseHandle(h)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stale_locks(
    work: Path, host: str | None = None, alive=pid_alive
) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Locks under `work` held by dead processes of this host, and the locks left alone
    with the reason."""
    host = (host or socket.gethostname()).lower()
    stale, kept = [], []
    if not work.is_dir():
        return stale, kept
    for p in sorted(work.iterdir()):
        if not (p.name == "_lock" or (p.name.startswith("_opt") and p.name.endswith("__lock"))):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as e:
            kept.append((p, f"unreadable: {e.strerror}"))
            continue
        m = _OWNER.match(text)
        if not m:
            kept.append((p, "owner not recognized"))
        elif m["host"].lower() != host:
            kept.append((p, f"held on another host {m['host']}"))
        elif alive(int(m["pid"])):
            kept.append((p, f"pid {m['pid']} is running"))
        else:
            stale.append(p)
    return stale, kept


def remove_stale_locks(work: Path, host: str | None = None, alive=pid_alive) -> dict:
    """Removes the stale locks of `work`; returns what was removed and what was kept."""
    stale, kept = stale_locks(work, host, alive)
    removed = []
    for p in stale:
        try:
            p.unlink()
            removed.append(p.name)
        except FileNotFoundError:
            pass
        except OSError as e:
            kept.append((p, f"cannot remove: {e.strerror}"))
    return {"removed": removed, "kept": [{"lock": p.name, "why": why} for p, why in kept]}
