# A first afternoon

From an installed server ([install.md](install.md)) to a nightly you can triage, in the
order a pilot usually goes. Commands are in [cli.md](cli.md); operations in
[operate.md](operate.md).

**With the compose recipe**, every `dviscope-server` command below runs through the `ops`
service, in `deploy/` (it has the server binary and the database secret; build it once
with `docker compose --profile ops build ops`): write `docker compose run --rm ops` where a
command says `dviscope-server`. A password goes on standard input (`-T`, never on the
command line) and a token file under `/backups` (the service's writable directory), which
you then move to the collector's state directory:

```sh
docker compose run --rm -T ops admin create-user --username alice < alice.pw
docker compose run --rm ops demo --project demo --member alice
docker compose run --rm ops admin create-project --name rtl
docker compose run --rm ops admin create-producer --project rtl --name nightly-runner
docker compose run --rm ops admin issue-token --project rtl --producer nightly-runner \
  --label pilot-pc --out /backups/collector.token
sudo install -o "$USER" -m 0600 backups/collector.token ~/.local/state/dviscope/collector.token
sudo rm backups/collector.token
```

## 1. Look at the demo (10 minutes)

```sh
dviscope-server admin create-user --username alice --password-file ./alice.pw   # or the password on stdin
dviscope-server demo --project demo --member alice
```

Sign in as `alice` and open project `demo`, regression `nightly-3`: a repeated scoreboard
failure with its triage case, a watchdog failure whose exception has expired, a test with
no result and two tests blocked by a failed build. Open each blocker, its signature and the
collection repair list. Every record in it is invented.

## 2. Your project (15 minutes)

```sh
dviscope-server admin create-project --name rtl
dviscope-server admin create-producer --project rtl --name nightly-runner
dviscope-server admin issue-token --project rtl --producer nightly-runner --label pilot-pc \
  --out ./collector.token        # written owner-only, never printed
dviscope-server admin set-member --project rtl --username alice --role triager
```

Point the collector's `token_file` at the token file (it is owner-only; the token is never
printed) and configure the collector ([install.md](install.md#collector)); `dviscope doctor --server --pilot` must
pass. Then accept the shipped rules for the project:

```sh
dviscope rules check            # prints the pipeline digest
dviscope-server admin accept-pipeline --project rtl --digest sha256:...
```

Results classified under a pipeline the project has not accepted are not eligible.

## 3. Bring existing results (optional, 30 minutes)

Results you already have (log folders of earlier nightlies) come in with
`dviscope import folder --root DIR --manifest runs.csv` (plus the regression, producer,
repository, branch and revision it belongs to; see [cli.md](cli.md)): it previews by
default, `--submit --journal DIR` journals and delivers. It shows how your logs classify
before you change any script. A Verilator model with its own C++ main takes a `main`
column (`model`) and a `console` column with its console capture beside its program log
([packs.md](packs.md#verilator-models-with-their-own-main)).

## 4. The first nightly (an hour)

One journal per regression on the machine that runs it. The bodies are small JSON files
your nightly script writes:

```sh
J=~/.local/state/dviscope/journals/nightly-2026-11-10
dviscope journal init --dir $J --id nightly-2026-11-10
dviscope source-manifest --journal $J --body sm.json      # repositories and revisions
dviscope regression create --journal $J --body regression.json
dviscope manifest declare --journal $J --regression nightly-2026-11-10 --chunk 1 --body slots.json
dviscope manifest seal --journal $J --regression nightly-2026-11-10
```

The four bodies, complete and consistent with each other, are in
[examples/](examples/) (`sm.json`, `regression.json`, `slots.json` and the launch file
`uart_tx.launch.json`; a test checks them against this version), and their JSON Schemas in
`schemas/` (`source-manifest.json`, `regression-create.json`, `manifest-chunk.json`). The
regression, for example:

```json
{"schema": "dviscope.ingest/1.0-dev.3", "producer_id": "nightly-runner",
 "regression_ref": "nightly-2026-11-10", "suite": "nightly",
 "branch": {"repository": "rtl", "name": "main"},
 "source_manifest_ref": "sm-2026-11-10", "trigger": {"kind": "nightly"},
 "started_at": "2026-11-10T01:00:00Z"}
```

A launch file names the attempt before it starts (`producer_id`, `regression_ref`,
`slot_ref`, a new `attempt_ref`, `source_manifest_ref` and the slot's exact `execution`
inputs; see [examples/uart_tx.launch.json](examples/uart_tx.launch.json)).

Then each test runs under the collector, which supervises it, extracts its log and spools
the attempt (a test that ends by other means is journalled with `dviscope collect`):

```sh
dviscope run --journal $J --launch uart_tx.launch.json --log uart_tx.log --simulator vcs -- ./run_test.sh uart_tx
```

At the end, deliver, close and finish:

```sh
dviscope spool flush --dir $J --wait committed --deadline 10m
dviscope journal close --dir $J
dviscope journal finish --dir $J --regression nightly-2026-11-10
dviscope spool flush --dir $J
dviscope journal reconcile --dir $J        # the server holds what was sent
```

Give each independently scheduled simulator its own `suite` (`nightly-vcs`,
`nightly-questa`): a regression is compared with the previous finished one of the same
producer, suite and branch, so one suite shared by two simulators compares a VCS night with
a Questa night (the regression page then warns that the baseline is on another simulator).

A test that never reports stays `missing` (never a pass); `finish` makes that final. The
schema identifiers in the bodies are the ones the server lists (`GET /api/v1/capabilities`,
`schemas`); the slot list uses the manifest schema (`dviscope.manifest/...`).

## 5. The morning (15 minutes)

Open the regression: the verdict, its blockers (each with a clearing action), the slots.
Each signature row names its diagnostic; select the rows of one cause (**Select all needing
decision**, or **select all** of one diagnostic) and triage them together: one owner, note
and state for all, saved in one step or not at all.
For a failure, open its signature: where else it occurs, its triage case on your branch
(owner, notes, bug links) and exceptions. An exception needs a reason and expires (at most
180 days); an expired one covers nothing. Copy the collection repair list for the slots that
need a re-run.

## 6. A merge gate in CI

A verdict is read with a person's token: a collector token can only deliver results. Issue
one for a project member (with compose: `--out /backups/alice.token`, then move it) and give
it to the gate:

```sh
dviscope-server admin issue-personal-token --username alice --label ci-gate --out ./alice.token
```

```sh
set -eo pipefail
export DVISCOPE_TOKEN_FILE=./alice.token
SRC=$(dviscope source digest --repo rtl=. | jq -er .source_digest)   # sha256:...
dviscope verdict --project rtl --regression nightly-2026-11-10 --expect-source "$SRC" \
  --summary markdown --summary-file verdict.md
```

`source digest` prints JSON (the digest and each repository's revision); the gate needs
its `source_digest` alone, and a failure to compute it stops the script. Exit 0 is a pass
for exactly that candidate; 10 a failure; 11 not enough evidence. The
summary carries IDs and counts, never log text. Commit statuses are advisory snapshots
([operate.md](operate.md#commit-statuses-advisory)); the gate is the live `verdict` run.
