"""Status publisher: posts DVIScope readiness as an advisory commit status.

A published status is a snapshot ("as of <time>, valid until <time>"), never a live gate:
the merge gate is a live ``dviscope verdict`` run. While this publisher runs it keeps
statuses fresh:

* ``publish`` evaluates a regression for a commit through the DVIScope server, which stores
  a publication receipt (or records a refresh when nothing changed), posts the status and
  records the host's acceptance (which retires the receipts it replaced).
* ``monitor`` (one pass, or ``--loop``) resumes from the server's open receipts: it posts
  receipts the host has not accepted yet, re-evaluates statuses hourly and when their
  ``valid_until`` passes, and ends monitoring: an undated success becomes *pending:
  monitoring ended* and is retired only after the host accepted that update.

It never posts success on an unreachable server or malformed output: when a re-evaluation
fails, a success becomes *pending: re-evaluation needed*. Only the standard library is used.
Tokens are read from files and never printed. Status text carries no log text, paths or
host names: verdict, times and a digest prefix.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import ipaddress
import os
import json
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

REFRESH_SECONDS = 3600
ENDED = "Monitoring ended; run the verdict again to refresh"
NEEDED = "Re-evaluation needed"


class PublishError(Exception):
    """A request failed (unreachable, refused or malformed); `status` is the HTTP status."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class _PartialList(PublishError):
    """The inventory could not be read to its end; `partial` holds the completed pages."""

    def __init__(self, message: str, partial: list):
        super().__init__(message)
        self.partial = partial


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follows a redirect: the bearer token must not travel to another origin or
    over a downgraded scheme (a 3xx answer is an error)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _loopback(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and _loopback(url)):
        return url.rstrip("/")
    raise PublishError("endpoints are https (plain http only on loopback, for tests)")


def _token(path: str) -> str:
    t = Path(path).read_text(encoding="utf-8").strip()
    if not t or "\n" in t:
        raise PublishError(f"the token file holds one token: {path}")
    return t


class Http:
    """A JSON client with a bearer token; errors never include the token or bodies."""

    def __init__(self, base: str, token: str, ca_file: str | None = None, timeout: float = 30):
        self.base = _check_url(base)
        self._token = token
        self.timeout = timeout
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ctx)
        )

    def call(self, method: str, path: str, body: Any = None, extra: dict[str, str] | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "dviscope-publish-status")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (extra or {}).items():
            req.add_header(k, v)
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            code = ""
            try:
                code = str(json.loads(e.read() or b"{}").get("code", ""))
            except Exception:  # noqa: BLE001 - the error body is a hint only (may be truncated)
                pass
            finally:
                e.close()
            raise PublishError(
                f"{method} {path.split('?')[0]}: HTTP {e.code} {code}".strip(), e.code
            ) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
            # Unreachable, reset, or a truncated or garbled response (IncompleteRead ...).
            raise PublishError(f"{method} {path.split('?')[0]}: unreachable ({type(e).__name__})") from None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            raise PublishError(f"{method} {path.split('?')[0]}: malformed response") from None


class GitHub:
    """Commit statuses (fine-grained token, ``Commit statuses: write``, one repository)."""

    def __init__(self, http: Http):
        self.http = http

    def post(self, repo: str, commit: str, state: str, description: str, context: str, target_url: str | None) -> None:
        if state not in ("success", "failure", "pending", "error"):
            raise PublishError(f"not a status state: {state}")
        body = {"state": state, "description": description[:140], "context": context}
        if target_url:
            body["target_url"] = target_url
        out = self.http.call(
            "POST",
            f"/repos/{repo}/statuses/{commit}",
            body,
            {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        )
        if not isinstance(out, dict) or out.get("state") != state:
            raise PublishError("status not accepted")


def _target_of(receipt: Any) -> dict | None:
    """The target of a (possibly malformed) inventory entry, when it can be identified."""
    try:
        t = receipt["target"]
        # Any context the server accepts (`|` included: the ledger key stays unambiguous, as
        # the repository and commit never contain it and the context is its last part).
        if all(isinstance(t[k], str) and t[k] for k in ("repository", "commit", "context")):
            return {k: t[k] for k in ("repository", "commit", "context")}
    except (KeyError, TypeError, IndexError):
        pass
    return None


def _canonical_keys(targets: dict) -> dict:
    """Entries keyed as this version keys them (targets compare without case: review
    r18). An entry under an older spelling of a key is re-keyed; when the canonical key
    exists too, the canonical entry (written by this version) wins and the alias is
    dropped. Entries that do not name their server, project and target keep their key
    (legacy entries are adopted elsewhere)."""
    out: dict = {}
    aliases: list[tuple[str, dict]] = []
    for k, e in targets.items():
        try:
            ck = "|".join((e["server"], e["project"], _key(e["target"])))
        except (KeyError, TypeError, AttributeError):
            ck = k
        if ck == k:
            out[k] = e
        else:
            aliases.append((ck, e))
    for ck, e in aliases:
        out.setdefault(ck, e)
    return out


def _key(target: dict) -> str:
    # GitHub compares repositories, commits and contexts without case.
    return "|".join((target["repository"], target["commit"], target["context"])).lower()


_HELD: dict[str, list] = {}
_HELD_GUARD = threading.Lock()


class _FileLock:
    """An exclusive OS file lock (released by the system if the process dies, so a live
    writer's lock is never stolen), reentrant within a process (a transition may hold it
    while it repairs, which writes again)."""

    def __init__(self, path: Path):
        self.path = path
        self.key = str(path.absolute())

    def __enter__(self) -> "_FileLock":
        with _HELD_GUARD:
            held = _HELD.setdefault(self.key, [threading.RLock(), 0, None])
        held[0].acquire()
        if held[1] == 0:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            if os.name == "nt":
                import msvcrt

                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)  # retries for 10 s itself
                        break
                    except OSError:
                        continue
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
            held[2] = fd
        held[1] += 1
        return self

    def __exit__(self, *exc) -> bool:
        held = _HELD[self.key]
        held[1] -= 1
        if held[1] == 0 and held[2] is not None:
            fd, held[2] = held[2], None
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)
        held[0].release()
        return False


class Ledger:
    """The publisher's durable record of each target's desired status: whether the code
    host acknowledged it, and for a status taken from a receipt whether the server
    confirmed that receipt as current. Shared by publisher processes through an OS lock."""

    def __init__(self, path: Path | None):
        self.path = path

    def lock(self):
        if not self.path:
            import contextlib

            return contextlib.nullcontext()
        return _FileLock(self.path.with_name(self.path.name + ".lock"))

    def read(self) -> dict:
        if not self.path or not self.path.exists():
            return {"targets": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data.get("targets"), dict):
                return {"targets": {}}
        except (OSError, ValueError, AttributeError):
            return {"targets": {}}
        data["targets"] = _canonical_keys(data["targets"])
        return data

    def write(self, data: dict) -> None:
        if not self.path:
            return
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    def update(self, key: str, fn: Callable[[dict], None]) -> dict:
        with self.lock():
            data = self.read()
            entry = data["targets"].setdefault(key, {})
            fn(entry)
            self.write(data)
            return dict(entry)

    def entries(self) -> dict:
        with self.lock():
            return self.read()["targets"]


@dataclass
class Publisher:
    project: str
    dv: Http
    gh: GitHub
    ui_base: str
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc)
    state_file: Path | None = None

    @property
    def ledger(self) -> Ledger:
        return Ledger(self.state_file)

    def _p(self, rest: str) -> str:
        return f"/api/v1/projects/{urllib.parse.quote(self.project, safe='')}{rest}"

    def _link(self, receipt: dict) -> str:
        return self.ui_base + receipt["receipt_path"]

    def _k(self, target: dict) -> str:
        """Ledger key: the server and project own the entry (never recovered by another)."""
        return "|".join((self.dv.base, self.project, _key(target)))

    def _mine(self, e: dict) -> bool:
        return e.get("server") == self.dv.base and e.get("project") == self.project

    def _host(self, target: dict, state: str, description: str, url: str | None,
              info: dict | None = None, digest: str | None = None) -> str:
        """Every status write, serialized per ledger (the lock is held across the host call,
        so the ledger's desired status is the host's last write): recorded as desired
        before it is sent, acknowledged once the host accepted it. A status taken from a
        receipt (`digest`) stays unconfirmed until the server accepts it as current."""
        # A unique generation per write: a confirmation applies to its own write only.
        desired = {"state": state, "description": description[:140], "url": url, "digest": digest,
                   "gen": os.urandom(8).hex()}
        key = self._k(target)
        ledger = self.ledger
        with ledger.lock():
            data = ledger.read()
            e = data["targets"].setdefault(key, {})
            e["server"], e["project"] = self.dv.base, self.project
            e["target"] = target
            e["desired"] = desired
            e["acked"] = False
            e["confirmed"] = digest is None
            if info is not None:
                e["info"] = info
            ledger.write(data)
            self.gh.post(target["repository"], target["commit"], state, description, target["context"], url)
            data = ledger.read()
            e = data["targets"].setdefault(key, {})
            if e.get("desired") == desired:
                e["acked"] = True
            ledger.write(data)
        return desired["gen"]

    def _confirm(self, target: dict, gen: str, info: dict) -> None:
        def conf(e: dict) -> None:
            if (e.get("desired") or {}).get("gen") == gen:
                e["confirmed"] = True
                e["info"] = info

        self.ledger.update(self._k(target), conf)

    @staticmethod
    def _info(receipt: dict) -> dict:
        return {k: receipt.get(k) for k in (
            "digest", "regression", "producer", "expect_source", "valid_until", "last_refresh_at",
            "posted_at", "published_at", "monitor_until")}

    def _posted(self, receipt: dict) -> dict:
        out = self.dv.call(
            "POST",
            self._p(f"/readiness/publications/{urllib.parse.quote(receipt['digest'], safe='')}/posted"),
            {"state": receipt["status"]["state"]},
        )
        if not _well_formed(out):
            raise PublishError("malformed confirmation")
        # The answer must be about this receipt: the ledger records it under its target.
        want = receipt.get("target")
        if out["digest"] != receipt["digest"] or out["status"]["state"] != receipt["status"]["state"] or (
            want is not None and _key(out["target"]) != _key(want)
        ):
            raise PublishError("confirmation for another receipt")
        return out

    def _post_receipt(self, receipt: dict) -> dict:
        t, st = receipt["target"], receipt["status"]
        target = {"repository": t["repository"], "commit": t["commit"], "context": t["context"]}
        # One transition under the lock: host write, then the server's confirmation (a
        # retirement can never interleave; a fenced write is repaired by the caller).
        with self.ledger.lock():
            gen = self._host(target, st["state"], st["description"], self._link(receipt),
                             self._info(receipt), digest=receipt["digest"])
            out = self._posted(receipt)
            self._confirm(target, gen, self._info(out))
            return out

    def _pending(self, target: dict, why: str, receipt: dict | None) -> None:
        stamp = self.now().strftime("%Y-%m-%d %H:%MZ")
        self._host(target, "pending", f"{why} (as of {stamp})",
                   self._link(receipt) if receipt else None)

    def _retire(self, target: dict, receipt: dict) -> None:
        """Monitoring ended (undated): one transition under the lock: an old success becomes
        pending, then the receipt is retired."""
        with self.ledger.lock():
            if receipt["status"]["state"] == "success":
                self._pending(target, ENDED, receipt)
            self.dv.call(
                "POST",
                self._p(f"/readiness/publications/{urllib.parse.quote(receipt['digest'], safe='')}/retire"),
                {"reason": "monitoring_ended"},
            )

    def _repair(self, target: dict, info: dict) -> str:
        """An obsolete status may be on the host: evaluate again and post the newest."""
        # Only the same producer's regression may be evaluated again; without a recorded
        # producer (an older ledger) the identity cannot be established: fail closed.
        if info.get("regression") and info.get("expect_source") and info.get("producer"):
            out = self.publish(info["regression"], info["expect_source"], target, info["producer"])
            return out["receipt"]["status"]["state"]
        self._pending(target, NEEDED, None)
        return "pending"

    def _adopt_legacy(self) -> list[str]:
        """Entries written before entries named their server and project cannot be
        attributed: fail closed. A status that may be green becomes pending (re-evaluation
        needed) before the entry is dropped; an unsent pending is sent; the rest is dropped."""
        log: list[str] = []
        ledger = self.ledger
        with ledger.lock():
            for key, e in list(ledger.read()["targets"].items()):
                if "server" in e and "project" in e:
                    continue
                d = e.get("desired") or {}
                try:
                    # A success, or any write the host never acknowledged (an earlier
                    # success may still be visible): pending, acknowledged before dropping.
                    if d.get("state") == "success" or not e.get("acked"):
                        self._pending(e["target"], NEEDED + " (publisher upgraded)", None)
                        log.append(f"legacy entry {key}: set to pending")
                    data = ledger.read()
                    data["targets"].pop(key, None)
                    ledger.write(data)
                except (PublishError, KeyError, TypeError) as err:
                    log.append(f"legacy entry {key} kept for retry: {err}")
        return log

    def _overdue(self, info: dict) -> bool:
        """A receipt's deadlines (validity, monitoring, hourly refresh) have passed."""
        now = self.now()
        try:
            valid_until = _ts(info.get("valid_until"))
            monitor_until = _ts(info.get("monitor_until"))
            last = _ts(info.get("last_refresh_at") or info.get("posted_at") or info.get("published_at"))
        except (ValueError, TypeError, AttributeError):
            return True  # deadlines that cannot be read cannot be vouched for
        return (
            (valid_until is not None and now >= valid_until)
            or (monitor_until is not None and now >= monitor_until)
            or last is None
            or (now - last).total_seconds() >= REFRESH_SECONDS
        )

    def _retry(self, server_up: bool = True) -> list[str]:
        """Resolves outstanding writes: a pending is re-sent; a status from a receipt is
        never re-sent blindly but reconciled with the server first (it may be obsolete)."""
        log: list[str] = []
        for key, e in self.ledger.entries().items():
            try:
                log += self._retry_entry(key, e, server_up)
            except Exception as err:  # noqa: BLE001 - one entry never stops the others
                log.append(f"retry failed for {key}: {type(err).__name__}")
                log += self._fail_closed(key, e)
        return log

    def _fail_closed(self, key: str, e: dict) -> list[str]:
        """What an entry shows can no longer be vouched for: a possible success becomes
        pending (the host must acknowledge it; the ledger keeps the obligation)."""
        d = e.get("desired") or {}
        if d.get("state") != "success" or not isinstance(e.get("target"), dict):
            return []
        try:
            self._pending(e["target"], NEEDED, None)
            return [f"pending {key}: cannot be vouched for"]
        except Exception as err:  # noqa: BLE001
            return [f"pending failed for {key}: {type(err).__name__}"]

    def _retry_entry(self, key: str, e: dict, server_up: bool) -> list[str]:
        log: list[str] = []
        d = e.get("desired")
        if not d or not self._mine(e):
            return log
        if d.get("digest") is None:
            if e.get("acked"):
                return log
            try:
                self._host(e["target"], d["state"], d["description"], d.get("url"))
                log.append(f"re-sent {d['state']} for {key}")
            except PublishError as err:
                log.append(f"re-send failed for {key}: {err}")
            return log
        if e.get("confirmed") and e.get("acked"):
            return log
        if not server_up:
            return log  # the outage path downgrades unconfirmed successes
        info = e.get("info") or {}
        if d.get("state") == "success" and self._overdue(info):
            # Never replay a success past its deadlines: evaluate again (with its own
            # producer) or set pending.
            try:
                log.append(f"re-evaluated {key}: {self._repair(e['target'], info)}")
            except PublishError as err:
                log.append(f"re-evaluation failed for {key}: {err}")
            return log
        try:
            with self.ledger.lock():
                gen = d.get("gen", "")
                if not e.get("acked"):
                    # Host first, then the confirmation (a fenced write is repaired).
                    gen = self._host(e["target"], d["state"], d["description"], d.get("url"),
                                     info, digest=d["digest"])
                out = self._posted({"digest": d["digest"], "status": {"state": d["state"]},
                                    "target": e["target"]})
                self._confirm(e["target"], gen, self._info(out))
            log.append(f"confirmed {d['digest'][:19]} for {key}")
        except PublishError as err:
            if err.status in (404, 409):
                try:
                    log.append(f"repaired {key}: {self._repair(e['target'], info)}")
                except PublishError as err2:
                    log.append(f"repair failed for {key}: {err2}")
            else:
                log.append(f"reconcile failed for {key}: {err}")
                if d.get("state") == "success":
                    # An unconfirmed success the server cannot confirm: pending.
                    try:
                        self._pending(e["target"], NEEDED + ": not confirmed", None)
                        log.append(f"pending {key}: not confirmed")
                    except PublishError as err3:
                        log.append(f"pending failed for {key}: {err3}")
        return log

    def publish(self, regression: str, expect_source: str, target: dict, producer: str | None = None,
                _repair: bool = True) -> dict:
        """Evaluates and posts one status. The receipt's status is (re-)asserted on every
        evaluation, so an obsolete status written by a concurrent or interrupted publisher
        is repaired. On a failed evaluation the target's status becomes pending, never
        success."""
        body = {"regression": regression, "expect_source": expect_source, "target": target}
        if producer:
            body["producer"] = producer
        try:
            out = self.dv.call("POST", self._p("/readiness/publications"), body)
            receipt = out["receipt"]
            action = out["action"]
            if action not in ("post", "unchanged") or not _well_formed(receipt):
                raise PublishError("malformed publication")
        except (PublishError, KeyError, TypeError, ValueError, AttributeError) as e:
            self._pending(target, NEEDED, None)
            raise PublishError(f"evaluation failed; status set to pending: {e}") from None
        try:
            receipt = self._post_receipt(receipt)
        except PublishError as e:
            # Fenced: a newer receipt of the target is the host's state; the status just
            # written is obsolete, so evaluate again and post the newest (once).
            if e.status == 409 and _repair:
                # The retry evaluates the receipt's own producer, never an unqualified one.
                if not receipt.get("producer"):
                    self._pending(target, NEEDED + " (producer unknown)", None)
                    raise PublishError("fenced and the producer is unknown: status set to pending",
                                       409) from None
                return self.publish(regression, expect_source, target, receipt["producer"],
                                    _repair=False)
            if receipt["status"]["state"] == "success":
                # The server could not confirm this success: it must not stand unconfirmed.
                self._pending(target, NEEDED + ": not confirmed", None)
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            if receipt["status"]["state"] == "success":
                self._pending(target, NEEDED + ": not confirmed", None)
            raise PublishError(f"malformed confirmation ({type(e).__name__}); status set to pending") from None
        return {"action": action, "receipt": receipt}

    def _outage(self, error: str) -> list[str]:
        """The server cannot be asked: statuses that may be green without the server's
        confirmation become pending: unconfirmed successes, and confirmed ones whose
        freshness cannot be established (a refresh is due, or their validity ended)."""
        log = [f"cannot list open publications: {error}"] + self._adopt_legacy() + self._retry(server_up=False)
        now = self.now()
        for key, e in self.ledger.entries().items():
            try:
                d, info = e.get("desired") or {}, e.get("info") or {}
                if d.get("state") != "success" or not self._mine(e):
                    continue
                if e.get("confirmed") and e.get("acked") and not self._overdue(info):
                    continue
                self._pending(e["target"], NEEDED + ": server unreachable", None)
                log.append(f"downgraded {key} to pending (server unreachable)")
            except Exception as err:  # noqa: BLE001 - one entry never stops the others
                log.append(f"downgrade failed for {key}: {type(err).__name__}")
        return log

    def _register(self, receipt: dict) -> None:
        """Records a posted receipt of a target (so an outage can still downgrade it); its
        status is taken as the host's unless a write of this publisher is outstanding."""
        t, st = receipt["target"], receipt["status"]
        target = {"repository": t["repository"], "commit": t["commit"], "context": t["context"]}

        def reg(e: dict) -> None:
            e["server"], e["project"] = self.dv.base, self.project
            e["target"] = target
            e["info"] = self._info(receipt)
            if not e.get("desired") or (e.get("acked") and e.get("confirmed")):
                e["desired"] = {"state": st["state"], "description": st["description"][:140],
                                "url": self._link(receipt), "digest": receipt["digest"],
                                "gen": "registered"}
                e["acked"] = True
                e["confirmed"] = True

        self.ledger.update(self._k(target), reg)

    def _list(self) -> list[dict]:
        """Every page of the open-publications inventory."""
        out: list[dict] = []
        after: str | None = None
        for _ in range(10_000):
            path = self._p("/readiness/publications")
            if after:
                path += "?after=" + urllib.parse.quote(after, safe="")
            try:
                page = self.dv.call("GET", path)
                items = page["publications"]
                if not isinstance(items, list):
                    raise PublishError("malformed list")
                after = page.get("next")
                if after is not None and not isinstance(after, str):
                    raise PublishError("malformed list")
            except Exception as e:  # noqa: BLE001 - what earlier pages showed is kept
                raise _PartialList(str(e) if isinstance(e, PublishError) else type(e).__name__, out) from None
            out += items
            if not after:
                return out
        raise PublishError("the inventory does not end")

    def monitor(self, force: bool = False) -> list[str]:
        """One monitoring pass; returns what it did (log lines without secrets). It never
        raises for a server outage: it downgrades what it can no longer vouch for."""
        try:
            open_ = self._list()
        except Exception as e:  # noqa: BLE001 - an unreadable inventory is an outage
            # Receipts on the pages read before the failure are recorded first, so the
            # outage path can downgrade them (the ledger may not know them: a restart).
            known = self._record_partial(getattr(e, "partial", []))
            return known + self._outage(str(e) if isinstance(e, PublishError) else type(e).__name__)
        log: list[str] = self._adopt_legacy() + self._retry()
        now = self.now()
        # The newest receipt per target is the only one ever posted (an older unposted one
        # is obsolete and retired when the newest is accepted).
        valid: list[dict] = []
        suspect: dict[str, tuple[dict, list]] = {}  # targets of rejected entries
        unknown = 0  # rejected entries without an identifiable target
        for r in open_:
            if _well_formed(r):
                valid.append(r)
            elif (t := _target_of(r)) is not None:
                suspect.setdefault(_key(t), (t, []))[1].append(r)
            else:
                unknown += 1
        newest: dict[str, dict] = {}
        for r in valid:
            key = _key(r["target"])
            if key in suspect:
                continue  # a malformed receipt of this target may be its newest
            if key not in newest or _ts(r["published_at"]) > _ts(newest[key]["published_at"]):
                newest[key] = r
        for key, (t, seen) in suspect.items():
            # Whatever the target shows (possibly a success posted before a restart, unknown
            # to the ledger) cannot be vouched for: pending, retried through the ledger.
            log.append(f"malformed inventory entry for {key}")
            log += self._downgrade_seen(t, seen, NEEDED + ": malformed receipt")
        if unknown:
            # An entry without a target may be any target's receipt: successes this
            # publisher recorded that no valid entry vouches for become pending.
            log.append(f"{unknown} malformed inventory entries set aside")
            for lkey, e in self.ledger.entries().items():
                t = e.get("target")
                if not self._mine(e) or not isinstance(t, dict):
                    continue
                if _key(t) in newest or _key(t) in suspect or (e.get("desired") or {}).get("state") != "success":
                    continue
                log += self._fail_closed(lkey, e)
        for key, r in newest.items():
            try:
                log += self._monitor_target(key, r, now, force)
            except Exception as err:  # noqa: BLE001 - one target never stops the others
                # A malformed answer: what the target shows cannot be vouched for.
                log.append(f"malformed receipt for {key}: {type(err).__name__}")
                try:
                    self._pending(r["target"], NEEDED, None)
                except (PublishError, KeyError, TypeError) as err2:
                    log.append(f"pending failed for {key}: {err2}")
        return log

    def _downgrade_seen(self, target: dict, seen: list, why: str) -> list[str]:
        """Sets the target pending because of inventory entries `seen`. Repeated passes over
        the same entries write once (the mark is their fingerprint); anything newly seen, or
        a later write of this publisher, makes it write again. Retried through the ledger."""
        key = self._k(target)
        mark = hashlib.sha256(
            json.dumps(sorted(json.dumps(r, sort_keys=True, default=str) for r in seen)).encode()
        ).hexdigest()[:32]
        e = self.ledger.entries().get(key) or {}
        d = e.get("desired") or {}
        if e.get("seen") == mark and d.get("state") == "pending" and d.get("digest") is None and e.get("acked"):
            return []
        try:
            self._pending(target, why, None)
        except Exception as err:  # noqa: BLE001 - one target never stops the others
            return [f"pending failed for {_key(target)}: {type(err).__name__}"]

        def note(e: dict) -> None:
            if (e.get("desired") or {}).get("state") == "pending" and e.get("acked"):
                e["seen"] = mark

        self.ledger.update(key, note)
        return [f"pending {_key(target)}: {why}"]

    def _record_partial(self, partial: list) -> list[str]:
        """What an incomplete inventory showed, before the outage path runs. It cannot show
        what replaced a receipt (that may be on a later page), so the ledger is not trusted
        over it: every target with a success that is unconfirmed (never posted) or overdue,
        or with a malformed entry, becomes pending. Nothing is published from here."""
        log: list[str] = []
        trigger: dict[str, tuple[dict, list]] = {}
        unknown = 0
        for r in partial:
            t = _target_of(r)
            if t is None:
                unknown += 1
                continue
            if _well_formed(r):
                if r["status"]["state"] != "success":
                    continue
                if r.get("posted_at") and not self._overdue(self._info(r)):
                    continue
            trigger.setdefault(_key(t), (t, []))[1].append(r)
        for _key_, (t, seen) in trigger.items():
            log += self._downgrade_seen(t, seen, NEEDED + ": inventory incomplete")
        if unknown:
            for lkey, e in self.ledger.entries().items():
                t = e.get("target")
                if not self._mine(e) or not isinstance(t, dict) or _key(t) in trigger:
                    continue
                if (e.get("desired") or {}).get("state") == "success":
                    log += self._fail_closed(lkey, e)
        return log

    def _monitor_target(self, key: str, r: dict, now: dt.datetime, force: bool) -> list[str]:
        log: list[str] = []
        t = r["target"]
        target = {"repository": t["repository"], "commit": t["commit"], "context": t["context"]}
        r_valid = _ts(r.get("valid_until"))
        r_end = _ts(r["monitor_until"])
        r_last = _ts(r.get("last_refresh_at") or r.get("posted_at") or r["published_at"])
        overdue = (
            (r_valid is not None and now >= r_valid)
            or (r_end is not None and now >= r_end)
            or r_last is None
            or (now - r_last).total_seconds() >= REFRESH_SECONDS
        )
        if not r.get("posted_at") and r["status"]["state"] == "success" and overdue:
            # Never replay a cached success past its deadlines: evaluate again (or
            # pending when that is not possible).
            try:
                log.append(f"re-evaluated {key}: {self._repair(target, self._info(r))}")
            except PublishError as e:
                log.append(f"re-evaluation failed for {key}: {e}")
            return log
        if not r.get("posted_at"):
            try:
                r = self._post_receipt(r)
                log.append(f"posted {r['digest'][:19]} {r['status']['state']}")
            except PublishError as e:
                if e.status != 409 and r["status"]["state"] == "success":
                    # Written but not confirmed: it must not stand.
                    try:
                        self._pending(target, NEEDED + ": not confirmed", r)
                        log.append(f"pending {key}: not confirmed")
                    except PublishError as e3:
                        log.append(f"pending failed for {key}: {e3}")
                    return log
                if e.status == 409:
                    # Fenced (another publisher moved on, the receipt may be retired):
                    # what was just written is obsolete; evaluate again and post that.
                    try:
                        log.append(f"repaired {key}: {self._repair(target, self._info(r))}")
                    except PublishError as e2:
                        log.append(f"repair failed for {key}: {e2}")
                else:
                    log.append(f"post failed {r['digest'][:19]}: {e}")
                return log
        self._register(r)
        monitor_until = _ts(r["monitor_until"])
        valid_until = _ts(r.get("valid_until"))
        last = _ts(r.get("last_refresh_at") or r.get("posted_at") or r["published_at"])
        ended = monitor_until is not None and now >= monitor_until
        if ended and valid_until is None:
            # Undated: an old success must not linger; retire after the host accepted.
            try:
                self._retire(target, r)
                log.append(f"monitoring ended {r['digest'][:19]}")
            except PublishError as e:
                log.append(f"retire failed {r['digest'][:19]}: {e}")
            return log
        # A posted success whose validity ended (an exception expired, say) is re-evaluated
        # at once, never left green until the hourly refresh.
        expired = valid_until is not None and now >= valid_until
        due = (force or ended or expired or last is None
               or (now - last).total_seconds() >= REFRESH_SECONDS)
        if due and not r.get("producer"):
            # A receipt without its producer cannot be re-evaluated safely.
            try:
                self._pending(target, NEEDED + " (producer unknown)", r)
                log.append(f"pending {key}: producer unknown")
            except PublishError as e:
                log.append(f"pending failed for {key}: {e}")
            return log
        if due:
            try:
                out = self.publish(r["regression"], r["expect_source"], target, r.get("producer"))
                r = out["receipt"]
                log.append(f"{out['action']} {r['digest'][:19]} {r['status']['state']}")
            except PublishError as e:
                log.append(f"re-evaluation failed for {t['repository']}@{t['commit'][:12]}: {e}")
        return log


def _well_formed(receipt: Any) -> bool:
    """Every field a status needs is present and of the right kind."""
    try:
        t, st = receipt["target"], receipt["status"]
        return (
            isinstance(receipt["digest"], str)
            and all(isinstance(t[k], str) and t[k] for k in ("repository", "commit", "context"))
            and st["state"] in ("success", "failure", "pending", "error")
            and isinstance(st["description"], str)
            and isinstance(receipt["receipt_path"], str)
            and _ts(receipt["published_at"]) is not None
            and all(_ts(receipt.get(k)) is not None or receipt.get(k) is None
                    for k in ("valid_until", "monitor_until", "posted_at", "last_refresh_at"))
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _ts(s: str | None) -> dt.datetime | None:
    """An RFC 3339 time with its offset; anything else raises ValueError."""
    if s is None or s == "":
        return None
    if not isinstance(s, str):
        raise ValueError("not a time")
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError("a time without its offset")
    return t


def source_digest(dviscope_bin: str, repos: list[str]) -> str:
    """``dviscope source digest --repo NAME=PATH ...`` (refuses dirty checkouts)."""
    args = [dviscope_bin, "source", "digest"]
    for r in repos:
        args += ["--repo", r]
    out = subprocess.run(args, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise PublishError("dviscope source digest failed")
    try:
        return json.loads(out.stdout)["source_digest"]
    except (ValueError, KeyError):
        raise PublishError("dviscope source digest: malformed output") from None


def _publisher(a: argparse.Namespace) -> Publisher:
    dv = Http(a.server, _token(a.token_file), a.ca_file)
    gh = GitHub(Http(a.github_api, _token(a.github_token_file)))
    return Publisher(project=a.project, dv=dv, gh=gh, ui_base=_check_url(a.ui_base or a.server),
                     state_file=Path(a.state_file).expanduser())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="publish_status", description=__doc__.splitlines()[0])
    p.add_argument("--server", required=True, help="DVIScope server URL")
    p.add_argument("--ui-base", help="URL users open for receipt links (default: --server)")
    p.add_argument("--ca-file", help="CA of the DVIScope server")
    p.add_argument("--token-file", required=True, help="DVIScope personal token (triager)")
    p.add_argument("--github-api", default="https://api.github.com")
    p.add_argument("--github-token-file", required=True, help="fine-grained token, commit statuses: write")
    p.add_argument("--project", required=True)
    p.add_argument("--state-file", default="~/.local/state/dviscope/publisher-state.json",
                   help="last known statuses (used to downgrade them when the server is unreachable)")
    sub = p.add_subparsers(dest="cmd", required=True)
    pub = sub.add_parser("publish", help="evaluate a regression for a commit and post the status")
    pub.add_argument("--regression", required=True)
    pub.add_argument("--producer")
    pub.add_argument("--repo", required=True, help="owner/name of the status target")
    pub.add_argument("--commit", required=True)
    pub.add_argument("--context", default="dviscope/merge")
    src = pub.add_mutually_exclusive_group(required=True)
    src.add_argument("--expect-source", help="the candidate's source digest")
    src.add_argument("--source", action="append", metavar="NAME=PATH", help="local checkout(s)")
    pub.add_argument("--dviscope", default="dviscope", help="dviscope binary (for --source)")
    mon = sub.add_parser("monitor", help="refresh and retire open statuses")
    mon.add_argument("--force", action="store_true", help="re-evaluate everything now (after a nightly)")
    mon.add_argument("--loop", type=float, metavar="SECONDS", help="repeat every SECONDS")
    a = p.parse_args(argv)
    try:
        pb = _publisher(a)
        if a.cmd == "publish":
            expect = a.expect_source or source_digest(a.dviscope, a.source)
            out = pb.publish(a.regression, expect, {"repository": a.repo, "commit": a.commit, "context": a.context}, a.producer)
            r = out["receipt"]
            print(json.dumps({"action": out["action"], "digest": r["digest"], "state": r["status"]["state"],
                              "description": r["status"]["description"]}))
            return 0
        while True:
            try:
                for line in pb.monitor(force=a.force):
                    print(line, flush=True)
            except (PublishError, OSError, ValueError, KeyError, TypeError) as e:
                # A loop survives a bad pass; the next one retries.
                print(f"publish_status: monitoring pass failed: {type(e).__name__}", file=sys.stderr, flush=True)
                if not a.loop:
                    return 4
            if not a.loop:
                return 0
            a.force = False
            time.sleep(a.loop)
    except PublishError as e:
        print(f"publish_status: {e}", file=sys.stderr)
        return 4
    except (OSError, ValueError) as e:
        print(f"publish_status: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
