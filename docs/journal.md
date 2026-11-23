# Delivery journal (`dviscope.journal/1.0-dev.3`)

The journal is the one authority for what a collector did and what it must still deliver: *at-least-once delivery, exactly-once server effects*. Every operation is an
immutable entry written durably **before** it is attempted; delivery outcomes are appended
later; the spool is simply the entries that have no outcome yet. This page is the format
contract and the crash-state table.

## Layout

One private directory per journal (per regression and side), on a local disk
(`%LOCALAPPDATA%\dviscope\journals\...` or `$XDG_STATE_HOME/dviscope/journals/...`;
`/mnt/*`, UNC and `\\wsl.localhost` paths are refused). It is created owner-only from the
first byte (Linux mode 0700, files 0600; Windows a protected DACL granting only the owner
and SYSTEM, inherited by everything inside), and a journal directory with broader access
is refused when opened:

```
journal.json            header: {schema, journal_id, created_at}
lock                    writer lock (LockFileEx / flock, released on process death)
entries/00000001.json   immutable entries, numbered under the writer lock
payloads/00000004.json  large payloads (evidence envelopes), reclaimable after commit
outcomes/00000001.json  one delivery outcome per entry (committed | rejected | blocked)
tmp/                    files being written; anything left here at startup is removed
```

Every file is written to `tmp/` (created exclusively), flushed and fsynced, then renamed
into place (`MoveFileExW` with `MOVEFILE_WRITE_THROUGH` on Windows; `rename` plus a
directory fsync on Linux). A file in `entries/`, `payloads/` or `outcomes/` is therefore
complete or absent, never torn.

## Entries

```json
{"schema": "dviscope.journal/1.0-dev.3", "seq": 4, "kind": "launch",
 "record": {...}, "depends_on": [2], "payload": {"file": "00000004.json",
 "sha256": "...", "bytes": 1234}, "created_at": "2026-11-08T10:00:00Z",
 "checksum": "sha256:..."}
```

- `seq`: allocated under the writer lock as the highest existing entry + 1; never reused.
- `kind`: `regression_create`, `manifest_chunk`, `manifest_seal`, `manifest_amend`,
  `slot_mark`, `launch` (attempt identity before the child starts: `slot_ref`,
  `attempt_ref`, `attempt_seq`; sent as `attempt_started`), `child` (pid and start time
  after the spawn), `runner_result` (runner facts after exit, or `unknown` after
  recovery), `envelope` (the simulation attempt record with its evidence), `build_launch`,
  `build_result`, `closure` (launch closure with its watermark), `participant` (a journal
  registered with this coordinator), `finish`.
- `record`: the wire record to deliver (none for `child`; `runner_result` is merged into
  its envelope by the collector).
- `depends_on`: entries that must be **committed** before this one is sent (a report
  depends on the manifest chunk declaring its slot; `finish` on every committed start up
  to each journal's watermark and on every closure).
- `checksum`: SHA-256 of the canonical JSON of the entry without `checksum`. An entry
  whose checksum does not verify is **corrupt**: it is never delivered, its dependents
  are blocked, and `journal status` reports it (corruption is never repaired silently).
  Lifecycle operations fail closed while any entry is corrupt: no launch (sequence
  allocation), no closure, no finish, no recovery — a corrupt fact is never treated as
  absent. A payload that is missing or fails its hash rejects its own entry locally
  (`E_LOCAL_CORRUPT`) and blocks its dependents; unrelated entries keep flowing. A payload
  that cannot be read right now (a sharing violation, an I/O error) is not damage: the
  entry stays pending, `spool flush` lists it under `deferred`, and the next flush retries.
  The same holds for an entry file: only a missing file or one that fails to parse or
  verify is corrupt; a read that may pass fails the whole operation (flush, closure,
  recovery) without recording anything, so no dependent is ever blocked by it.
- Unknown fields in `record.result.runner` from a newer collector are preserved verbatim
  (the server validates them).

`attempt_seq` of a launch is allocated under the same lock: one higher than the highest
`attempt_seq` of that slot in the journal.

## Outcomes

```json
{"seq": 4, "outcome": "committed", "receipt": {...}, "at": "..."}
{"seq": 5, "outcome": "rejected", "error": {"code": "E_...", "status": 409}, "at": "..."}
{"seq": 6, "outcome": "blocked_by_dependency", "dependency": 5, "at": "..."}
```

`sent` is never stored. After a crash an entry without an outcome is pending and is
replayed with its original identity, revision and payload; the server answers a replay
with the original receipt. A `committed` outcome is recorded only for a well-formed
receipt of the record sent: the same identity and digest, `revision` exactly 1 (journal
records are first revisions), `result` `committed` or `duplicate`, and a non-empty
`server_ids` object; anything else (a missing or malformed member included) leaves it
pending as an ambiguous answer. A payload file is deleted only after its `committed` outcome is
durable; a reclaim interrupted by a crash is resumed at the next flush. The entry
(metadata, digest) stays.

A flush holds the writer lock only to read the journal and to record outcomes, never
during transport I/O, so launches and supervision are not delayed by delivery.

Status handling while flushing: 2xx receipt → `committed`; 400, 409, 410 → `rejected`
with the server error, and every entry depending on it (transitively) →
`blocked_by_dependency`; 401, 403 → stop flushing and report; 429, 503, 507, network
errors, and lost or malformed responses → leave pending and back off (replay is safe).

## Launches, closure and finish

- A `launch` entry is durable before the child process exists and records the
  supervisor's PID and **start identity** (Linux boot ID and `/proc` start time; Windows
  process creation time); `child` records the child's PID and start identity after the
  spawn; `runner_result` after it ends (with `unreaped` when the forced stop could not be
  confirmed). Recovery compares start identities, so a reused PID is never taken for the
  original process. A launch is refused when the supervisor's own start identity cannot
  be read. On Windows the child is created directly inside its kill-on-close job: if the
  supervisor dies at any point, the job closes and ends the whole tree.
- The `child` entry is written by a helper thread: a flush holding the writer lock never
  delays timeout enforcement. It is joined before `runner_result`, which therefore always
  follows it.
- Everything a launch derives is validated before the launch: the report identity
  (`simulation_attempt:<report_id>`, where `report_id` is `<attempt_ref>:r1`, or, for a
  reference too long for that or already shaped like the shortened form, its first 160
  characters, `+`, 32 hex digits of its SHA-256 and `:r1`, so two references never share
  a report ID), and the log and console paths: the attempt creates each exclusively
  under the launch lock (refused if it exists; one attempt may use one path for both), so
  no earlier or concurrent execution, as log or as console capture, can write the file
  that becomes this attempt's evidence; a tool that never writes its log leaves it empty
  (no log).
- **Closure**: `journal close` writes a `closure` entry with the **watermark** (the highest
  `launch`/`build_launch` seq). After it the journal refuses new launches; the closure
  survives restarts.
- **Participants**: one coordinator journal per regression. Another journal joins it at
  creation (`dviscope journal init --dir SIDE --id ID --coordinator COORD`), in three
  durable steps: the participant is created **dormant** (its header names the
  coordinator; it refuses launches), the coordinator records a `participant` entry (ID
  and absolute directory) under its lock, and the participant is **activated**. A finish
  therefore either sees the participant (and waits for its closure) or refuses its
  registration, and a dormant journal never launches. A finished coordinator accepts no
  participant (the empty dormant journal is then removed). Activation runs under the
  participant's writer lock, and re-running the same `journal init` resumes an
  interrupted initialization (an existing registration of the same ID and directory is
  reused; another journal at that place is refused).
- **Finish barrier** (`dviscope journal finish --dir COORD --regression REF`): refused
  until every registered participant and the coordinator (if it launched anything) has a
  closure, no launch (`launch` or `build_launch`) after its watermark, and a committed
  start for every launch up to it. A registered participant that cannot be opened blocks
  the finish (never presumed empty). `--participant DIR` may name participants
  explicitly; each must be registered. The finish entry records each participant's journal ID and watermark.
  Once `finish` is written, no launch is accepted.

## Recovery

At startup, under the writer lock:

| State found | Meaning | Action |
|---|---|---|
| files in `tmp/` | a write was interrupted before its rename | removed |
| `launch` without `child` | the supervisor died before or during the spawn | `runner_result` with termination `unknown` (*interrupted; outcome not recoverable*) |
| `launch` + `child`, no `runner_result`, child process alive | live orphan | left alone; `doctor` reports it; never assumed stopped |
| `launch` without `runner_result`, its supervisor (pid in the launch) alive | still launching or running | left alone |
| `launch` + `child`, no `runner_result`, child gone | the supervisor died during the run or before journalling the facts | `runner_result` with termination `unknown` |
| `runner_result` with `unreaped`, child still alive | the forced stop was not confirmed | reported as a live orphan |
| a launch or child record without its start identity | liveness cannot be verified (a reused PID would look alive) | left alone and reported as `unverifiable`; never presumed alive or gone |
| `runner_result` without `envelope` | extraction or the envelope write was interrupted | the envelope is built from the runner facts with the evidence of a missing log (outcome `error`, `NO_LOG`; never a pass) |
| entry checksum fails | corrupt entry | never delivered; dependents blocked; reported |
| `committed` outcome, payload file gone | payload reclaimed | nothing to do (metadata kept) |
| entry pending | crash before or during delivery | replayed as is |

Recovery never relaunches anything and never turns an interrupted run into a pass: the
way to get a result is a new attempt (next `attempt_seq`). A launch that cannot be
recovered (an unreadable record) is reported under `errors` and does not stop the
recovery of the others.

## Crash points (tested)

Deterministic crash points, each followed by recovery and a flush to a receipt endpoint
that records every effect, must lose and duplicate nothing: before and after each rename,
after the spawn before the `child` entry, after the child's exit before `runner_result`,
after the server commit before the response is read, and after the receipt before the
outcome (and the payload reclaim) is written.

## Receipts

Every committed record gets a receipt, stored in its `committed` outcome:

```json
{"identity": "simulation_attempt:a17:r1", "revision": 1,
 "digest": "<sha256 of the canonical record>", "result": "committed",
 "server_ids": {"attempt": "01J...", "report": "01J..."}}
```

- `identity` and `revision` name the record (B.3 idempotency); `digest` is the SHA-256 of
  its canonical JSON as the client sent it.
- `result`: `committed` the first time; a replay of the same identity, revision and digest
  returns the **original** receipt with `result: duplicate` (no second effect). The same
  identity and revision with another digest is 409 `E_REVISION_CONFLICT`; a revision below
  the head that was never seen is 409 `E_STALE_REVISION`; a replay older than the
  deduplication horizon is 410 `E_REPLAY_EXPIRED` (all three are `rejected` outcomes).
- `server_ids`: the server's opaque IDs of what the record created, for `journal
  reconcile` and support.

The local stand-in endpoint (`--endpoint dir:PATH`) implements the same fields with
the identity's revision fixed at 1.
