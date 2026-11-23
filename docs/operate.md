# Operating the server

How to provision and run `dviscope-server` against PostgreSQL. The API it serves is in
[api.md](api.md); the collector's journal in [journal.md](journal.md).

## Configuration

`dviscope-server.toml` (or `--config` / `DVISCOPE_SERVER_CONFIG`); unknown keys are
rejected, `DVISCOPE_SERVER_*` variables override the file:

```toml
listen = "0.0.0.0:8443"
public_origin = "https://127.0.0.1:8443"
ui_dir = "/opt/dviscope/ui"                 # the built web UI (optional)
request_body_timeout_s = 60                 # a request body arrives within this time

[tls]
cert_file = "/run/dviscope/tls/server.pem"
key_file = "/run/dviscope/tls/server.key"

[database]
url_file = "/run/secrets/dviscope-db-url"   # or DVISCOPE_SERVER_DATABASE_URL
pool_size = 16
statement_timeout_ms = 30000
```

The database URL (it holds the password) is never written in the configuration file:
it comes from `DVISCOPE_SERVER_DATABASE_URL` or from the file named by `url_file`. Without
a `[database]` section the server answers health, readiness and capabilities only.

### Web UI

The web UI is a static app in `web/`. Build it with Node.js 20 or later:

```sh
cd web
npm ci
npm run build        # writes web/dist
```

and point `ui_dir` (or `DVISCOPE_SERVER_UI_DIR`) at `web/dist`. The server then answers
`GET`/`HEAD` for the app's files and returns `index.html` for app routes (paths without a
file extension); `/api/…` paths are never answered with the app, and no file outside
`ui_dir` is served (symbolic links that leave it are refused). Fingerprinted `assets/`
files are cached as immutable, `index.html` is revalidated. Without `ui_dir` no UI is
served. Users sign in with a password (`dviscope-server admin create-user`); the UI keeps
the session cookie and sends its CSRF token on every change.

## Migrations

```sh
dviscope-server migrate
```

Migrations are forward-only and embedded in the binary; they run under an exclusive
advisory lock, and an applied migration whose text changed is an error. The server
refuses to start, and `/readyz` answers 503, while the schema is not the binary's own.
The wire schemas carry a development version (`1.0-dev.N`) and a server accepts only its
own: upgrade the server and the collectors together, after their journals are flushed (a
record of the other version is refused with its schema named). A source manifest declared again by reference
after the upgrade, unchanged but for its development schema label, is a duplicate, not a
conflict, for the revisions reviewed as compatible; every other record is compared exactly
(re-send it under a new reference or revision).
Identity bindings (an attempt reference names one slot, a report ID one attempt, for good)
are backfilled at upgrade from the retained data. A producer whose regressions retention
removed before the binding backfill completed is **retired** by the upgrade (its lost references could
otherwise be reused): its records are refused with 410, and you create a new producer and
token for it. Tombstones written before deletion times were recorded reliably cannot be
ordered against that backfill, so their producers are retired too. Back up the database
before upgrading; rolling back is restoring that backup with the previous binary. From
schema 19 on that is `dviscope-server backup`; a database before schema 19 (a version
without `backup`) is backed up with `pg_dump --format=custom` and rolled back with
`pg_restore` into an empty database for the previous binary (`backup` refuses such a
database, since `restore` could not take its archive). A new version may classify with a different pipeline digest (its shipped
packs changed): its results are not eligible, never a pass, until you accept the new digest
(`dviscope rules check` prints it; `admin accept-pipeline`, or a rules activation).

## Provisioning

Every command prints JSON on stdout and writes an audit row.

| Command | What it does |
|---|---|
| `admin create-project --name NAME [--policy strict\|retry-pass-accepted]` | a project (names: lower-case letters, digits, `-`, `_`) |
| `admin create-producer --project P --name NAME` | a producer namespace (the `producer_id` of its records) |
| `admin issue-token --project P --producer NAME --out FILE [--scope S]... [--days N] [--label L]` | a collector token, written to a new owner-only `FILE` on a Linux file system (never printed; an existing file, Windows, or a Windows drive under WSL is refused, before issuing); default scopes: all collector scopes; at most 366 days |
| `admin revoke-token --id ID` | revokes a token at once |
| `admin quarantine-token --id ID --since TIME` | revokes the token, and every revision it delivered since `TIME` (RFC 3339) becomes a settlement barrier (never a pass) until released |
| `admin release-token --id ID` | ends the quarantine (the token stays revoked) |
| `admin accept-pipeline --project P --digest sha256:…` | accepts a pipeline digest (from `dviscope rules check`); results of other pipelines are not eligible |
| `admin withdraw-pipeline --project P --digest sha256:…` | withdraws it: results classified under it stop settling (a barrier, B.9.5) |
| `admin create-user --username U [--password-file F]` | a local user; the password (≥ 12 characters) is read from the file or standard input, never from the command line |
| `admin set-member --project P --username U --role viewer\|triager\|admin` | a membership; a role change applies to the user's sessions and personal tokens at once |

Collector scopes: `regression:create`, `manifest:declare`, `manifest:seal`,
`manifest:amend`, `ingest:submit`, `regression:finish`. A collector token belongs to one
project and one producer; store it in the collector's `token_file`.

## Retention

```sh
dviscope-server retention --preview          # what would expire, per regression; changes nothing
dviscope-server retention                    # apply, as of now
dviscope-server retention --every 24         # the service: apply every 24 hours
```

`--preview` (alias `--dry-run`) takes no lock a writer waits on; the real run decides again
under its locks, so a preview is advice, not a promise. Besides each regression's action it
lists the impact: feature-readiness candidates whose newest evidence a removal expires
(branch, test, regression) and monitored publications (receipts not retired) of removed
regressions. The admin page shows the project's
preview (`GET /api/v1/projects/{project}/admin/retention`). The compose file runs a
`retention` service (`--every 24`); a run is skipped, and logged, while the server is in
maintenance or the schema is not the binary's, and a failed run is retried at the next tick.

Payloads of all-pass regressions expire after 30 days, of the others after 90; the facts
of all-pass regressions after 90 days, of the others after 2 years; receipts after the
120-day deduplication horizon. A regression is *all-pass* only when every slot settles
passed (or skipped, cancelled) at the time of the run — a quarantined or withdrawn pass, a
failed build or a missing result keeps it in the long-lived cohort. Each regression is
decided and removed under its head lock. Removed regressions, receipts and builds leave
tombstones: a late record is answered 410 (`E_EXPIRED`, `E_REPLAY_EXPIRED`), never taken as
new. A build stays while any retained attempt, report revision or slot needs it.

## Backup and restore

In the compose recipe the `ops` service (profile `ops`: the server binary beside the
PostgreSQL 17 client tools) runs these commands; archives land in `deploy/backups`
(created by `provision-db.sh`, owned by the service account, owner-only):

```sh
docker compose run --rm ops backup --out /backups/dviscope-2026-11-09.dump
docker compose stop server retention
docker compose run --rm ops restore /backups/dviscope-2026-11-09.dump
docker compose run --rm ops restore-verify /backups/dviscope-2026-11-09.dump
docker compose start server retention       # maintenance: reads and logins only
docker compose run --rm ops admin reenable-token --id ID      # or issue new tokens
docker compose run --rm ops maintenance off --reason "restore verified"
```

Without containers the same commands are `dviscope-server backup|restore|restore-verify|
maintenance`, on a Linux host. The PostgreSQL tools address exactly the database the
server's own connection does: the host, port, user and database it resolves from the URL
(a part the URL omits comes from `PGPORT`, `PGHOST`, ... for both alike; every other
inherited `PG*` variable is removed, except credential and certificate files). A query
parameter other than `sslmode` is refused, before anything connects or is written. Backups
refuse to be written where file modes do not protect
them: on Windows, and on a Windows drive seen from WSL (`/mnt/*` or any DrvFS mount, also
through a symlink).

`backup` runs `pg_dump` (custom format; the PostgreSQL client tools come from `PATH`, or
from the directory in `DVISCOPE_PG_BIN_DIR`: from PostgreSQL 17 on, tools of a major version
at least the server's; for a server before 17, the tools of the server's own major version,
both for `backup` (a newer `pg_dump` writes an archive format that server's `pg_restore`
cannot read) and for `restore` (a newer `pg_restore` sets `transaction_timeout`, which those
servers reject). `backup` and `restore` refuse other pairings before writing or touching
anything; the manifest records the `pg_dump` version, and `restore` needs a `pg_restore` at
least as new) into a new private file (owner-only; it never
overwrites) and writes `<archive>.manifest.json` beside it: the archive's SHA-256, the schema
version, the row count of every table (except sessions, the audit log, login throttling and
restore bookkeeping) and the readiness of the 20 most recent finished regressions. The
recorded values and the dump come from one database snapshot (`pg_dump --snapshot`), so
writes during a backup are in both or in neither.

`restore` refuses an archive whose digest is not its manifest's, or one older than schema
19 (the first with a safe restore), then restores it into the configured database in **one
transaction** together with the safe state: `psql` (it comes with the client tools)
receives `BEGIN`, the archive's script and, only once `pg_restore` has succeeded, the safe
state and `COMMIT`. No client ever sees the restored data before it is safe, and a restore
that fails or is interrupted at any point ends inside the open transaction, which the
server rolls back: the database stays as it was.
Stop the server first. The restored database is **safe**: maintenance mode on (every write is refused with 503 `E_UNAVAILABLE`, reads
and logins still work, `/readyz` answers 503), every session deleted, every collector and
personal token disabled until re-enabled (`admin reenable-token`) or replaced — a restored
token may have leaked with the backup. `restore-verify` compares the row counts and the
recorded readiness with the manifest and fails on any difference. Then end maintenance.

**Rolling an upgrade back**: restore the backup taken before the upgrade into a **new,
empty** database and point the server (of the version that wrote the backup) at it. A
restore over a database already at a newer schema is refused before anything changes.

`maintenance on|off [--reason TEXT]` sets maintenance by hand (audited). Maintenance is a
fence: every write transaction holds a shared gate and checks the flag; `maintenance on`
takes the gate exclusively, so when it returns every write that started before has
committed and every later one is refused (`E_UNAVAILABLE`). In maintenance the HTTP API
refuses writes, `retention` (except `--preview`) and `demo` are refused, and of the `admin`
commands only credential recovery runs (`issue-token`, `issue-personal-token`,
`reenable-token`, `revoke-token`, `quarantine-token`, `release-token`).

## Commit statuses (advisory)

`python -m dviscope_hexk.publish_status` posts readiness as a commit status. A status is
an **advisory snapshot**: its description says when the evaluation was made and until when
it is valid; the merge gate is a live `dviscope verdict` run. The publisher needs a
DVIScope personal token of a triager (`admin issue-personal-token`) and a fine-grained
code-host token limited to one repository with *Commit statuses: write*; both are read
from files and never printed.

```sh
# after a nightly: evaluate the regression for the commit and post the status
python -m dviscope_hexk.publish_status --server https://127.0.0.1:8443     --ca-file dviscope-ca.pem --token-file dviscope.token     --github-token-file status.token --project p1     publish --regression nightly-2026-11-08 --repo owner/name --commit <sha>     --source rtl=/path/to/checkout
# keep statuses fresh while the machine runs (hourly, and at each valid_until)
python -m dviscope_hexk.publish_status ... monitor --force --loop 300
```

Each publication stores an immutable receipt (its log-free summary) on the server; the
status links to the receipt page, which shows it next to a current evaluation. An
unchanged evaluation only records a refresh. The code host's acceptance retires the
receipts it replaced. A success never lingers: when its `valid_until` passes it is
re-evaluated, when a re-evaluation fails it becomes *pending: re-evaluation needed*, and
an undated success becomes *pending: monitoring ended* after 14 days and is retired only
once the code host accepted that update. A restarted publisher resumes from the server's
open receipts and posts only the newest receipt of each target; every evaluation re-asserts
the current status (repairing one written by an interrupted or concurrent run), and the
server refuses to record an obsolete receipt as posted. When the server cannot be reached,
the publisher keeps running and turns successes it can no longer vouch for (a refresh is
due or their validity ended) into *pending*, from its last known inventory (`--state-file`).
It never follows redirects (tokens stay with their origin). Its staleness bound (one hour)
holds only while it runs.

## Health dashboard and hierarchy

The web UI's **Health** page (`/p/<project>/health`) shows, per regression stream (one
producer's suite on one repository-qualified branch), the latest regression against its
predecessor (the most recent earlier finished one): readiness, a trend badge, required-slot
counts and pass rate with their change, new and no-longer-seen signatures, runtime and CPU.
Run each independently scheduled simulator in its own suite, so a stream compares like
with like.

The **Tests** column and KPI give the required runs of the latest regression with their
change since the predecessor: fewer reads as worse, and a stream whose latest regression
has no required test is marked **0 tests** (an emptied or broken run list), also on every
node above it. **Columns** above each table hides or shows its columns; the choice is kept
by your browser. **Test growth**, below the tables, draws the node's required runs and
distinct tests per day over the last 7 to 365 days (each stream counts with its latest
regression by that day), so a drop and the progression of new tests both show.

Without a hierarchy every stream is listed at the project level. To group streams by SoC,
subsystem and block, import a hierarchy (project admins):

```yaml
# hierarchy.yaml (dviscope.hierarchy/1)
nodes:
  - {path: soc, title: Demo SoC}
  - {path: soc/cpu_ss}
  - {path: soc/cpu_ss/dma}
  - {path: soc/dsp_ss}
streams:              # each stream has exactly one home node
  - {node: soc/cpu_ss, producer: ci, suite: cpu-nightly, branch: soc/main, cadence: nightly}
  - {node: soc/cpu_ss/dma, producer: ci, suite: dma-nightly, branch: soc/main}
links:                # a reused block: shown here too, counted once in every roll-up
  - {node: soc/dsp_ss, stream: {producer: ci, suite: dma-nightly, branch: soc/main}}
```

```bash
dviscope hierarchy import --project soc --dry-run hierarchy.yaml   # validate locally
dviscope hierarchy import --project soc hierarchy.yaml
```

A node may have its own streams, children, or both, and this can change over the
project's life: re-import the file (each change is a new revision). Streams not in the
tree appear under **Unassigned**. A `cadence` (`nightly`, `weekly`, `<N>h`) marks a stream
**overdue** once its latest regression is older than the cadence plus a grace of a quarter
of it (at least 2 h).

Runtime and CPU come from the collector's runner measurements, kept as retained facts
(they survive payload expiry). A CPU change is shown only when both regressions measured
every deciding attempt with the same scope; a missing measurement is shown as unknown,
never as zero.

Health reads are bounded: a page covering more than 200 streams, or regressions with more
than 32,000 slots (40,000 attempts, 60,000 diagnostic buckets, …) in total, answers
`E_TOO_LARGE` — open a lower node, or a shorter history on a stream's page (down to the
latest regression only). A read that takes longer than 20 s answers `E_UNAVAILABLE` (retry).
Within these limits a page answers in under two seconds (benchmark: `health_benchmark`).

## Rules activation

A project's pipeline is the shipped packs plus its own packs (suppressions, project
patterns). Changing it is checked against an **activation sample** of real logs with their
expected structural results, on the client and again on the server:

```sh
# build a private sample: each case is a log and an expectation to review
dviscope corpus capture --log night/run3.log --case mismatch-3 --dir sample/ --exit-code 1
dviscope sample upload --project p1 --dir sample/        # chunked, resumable
dviscope rules import --project p1 --sample sample/ --pack proj.yaml   # project admins
```

`rules import` compares the active pipeline with the new one over every case: the
expectation, failures listed in `must_survive`, lines in `must_remain_distinct` that would
share a family, and differences not declared in `expect_changes`. A failing check is never
sent (exit 3). The server re-runs the same check and refuses a stale or different result.
Collectors then extract with the same `--pack` arguments; their evidence names the new
digest. Evidence is never relabelled: earlier runs keep their pipeline.

## Importing and ledgers

- `dviscope import folder --root DIR --manifest runs.csv --regression R --producer P
  --repository REPO --branch B --revision V` previews a folder of logs from a finished
  regression (columns `slot,test,seed,log,exit_code[,started_at,finished_at,required]`;
  the CSV is the expected set: a row without a log did not report); `--submit --journal
  DIR` journals and delivers it. Logs are read only beneath the root (no symlink escapes,
  regular files only).
- `dviscope collect --journal DIR --launch FILE --log FILE --exit-code N --started-at T`
  journals one run that ended elsewhere.
- `dviscope ledger export --project P --out FILE` (private: notes may name people) and
  `dviscope ledger import --project Q FILE [--mapping map.json] [--dry-run]` move triage
  decisions and exceptions between projects or installations.

## CI and checks

- `dviscope verdict --wait-processed --deadline 15m` re-evaluates while waiting can change
  the answer (collection open, attempts running, server unreachable); `--summary markdown`
  writes the log-free summary as escaped Markdown; `--publish-receipt --target-repository
  R --target-commit C` stores a publication receipt.
- `dviscope spool flush --wait committed --deadline 10m` retries until delivered (exit 4 if
  records are still pending).
- `dviscope doctor --pilot --server` checks the state location and its privacy, the token
  file, the runner's prerequisites, CA trust and the clock offset to the server;
  `--assurance P` prints each producer's assurance profile; `--reconcile DIR` (repeatable)
  adds each journal's reconciliation and fails when one disagrees.
- `dviscope journal reconcile --dir COORD` compares the journal and its participants with
  the server, changing nothing: records committed but missing on the server (`lost`, for
  example after restoring an older backup) or different there (`conflicts`), records never
  delivered (`undelivered`: run `spool flush`), and regressions where the server counts
  fewer started or reported slots than the journal committed. Records past the
  deduplication horizon and regressions past retention are not compared. Exit 0 when they
  agree, 10 when they do not.

## The demo project

```sh
dviscope-server demo --project demo --member ada
```

creates a separate project of invented records (nothing from a real simulation): three
nightlies on `demo-rtl/main`, the last of which (`nightly-3`) fails with every kind of
trouble a triager meets: a scoreboard mismatch repeated since `nightly-2` with its triage
case, a watchdog failure whose exception expired a week ago, a test with no result, and two
tests blocked by a failed build. The decisions are authored by a user `<project>-demo` that
has no usable password; the generator's collector token is revoked when it is done.
`--member` makes an existing user a viewer of it. An existing project is refused.

```sh
dviscope-server demo --soc --member ada
```

creates the **demo SoC** (project `demo-soc`) for the health dashboard: a hierarchy
`soc` → CPU subsystem (its own regression and the blocks core, l2cache and dma), DSP
subsystem (blocks only: mac_array, fft, and dma shared from the CPU subsystem), I/O
subsystem (its own regression, no blocks) and peripheral subsystem (a weekly regression,
now overdue), with 14 invented nightly runs per nightly stream plus two weekly runs: a core hazard that failed four nights and
was fixed, an assigned dma failure that persists, a new mac_array overflow on the last
night, two missing I/O results, a core run still in progress, tests added over the first
nights (**Test growth**) and three fft tests dropped from its run list on the last night
(the **Tests** column). Open **Health** in the project. It takes seconds and needs no
simulator.

## A first setup

```sh
dviscope-server migrate
dviscope-server admin create-project --name rtl
dviscope-server admin create-producer --project rtl --name nightly-runner
dviscope-server admin issue-token --project rtl --producer nightly-runner --label pilot-pc \
  --out ./collector.token        # written owner-only, never printed
dviscope-server admin accept-pipeline --project rtl --digest sha256:...   # printed by `dviscope rules check`
dviscope-server admin create-user --username alice --password-file ./alice.pw
dviscope-server admin set-member --project rtl --username alice --role triager
```
