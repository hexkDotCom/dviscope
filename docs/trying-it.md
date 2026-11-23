# Trying DVIScope on your own logs

This release is an **alpha**. The most useful thing you can do is run it on real regression
logs and tell us where its answer differs from what you know to be true.

**Your logs stay with you.** DVIScope has no telemetry and no cloud service. Steps 1 and 2
run on one machine without a server. Step 3 stores results in a server and database that you
run. Nothing is sent anywhere else unless you configure it.

**Never post log text, file paths, test names or design names in a public issue.** The
[trial report](https://github.com/hexkDotCom/dviscope/issues/new?template=trial-report.yml)
asks only for counts, simulator versions and a description of what went wrong.

Supported in this alpha: logs from **Questa, VCS and Verilator**, with UVM and SVUnit output.
The server runs on Linux x86-64; the collector on Linux or Windows x86-64. Other simulators
have no shipped rules yet: please tell us which one you use.

## 1. Preview a regression (10 minutes, no server)

Download the archive for your platform from the
[releases page](https://github.com/hexkDotCom/dviscope/releases), verify it
([install.md](install.md#verify-the-download)) and unpack it. Nothing needs installing:
`bin/dviscope` is one static binary.

Describe one finished regression in a CSV, one row per job that *should* have run, with log
paths relative to the log folder:

```csv
slot,test,seed,log,exit_code
uart_tx.s1,uart_tx,1,uart_tx_1.log,0
uart_rx.s1,uart_rx,1,uart_rx_1.log,1
dma_burst.s7,dma_burst,7,,
```

An empty `log` means the job never reported. Leave `exit_code` empty when you do not know
it. Optional columns: `started_at`, `finished_at` (RFC 3339) and `required` (`yes`/`no`).

Then preview it. This reads the logs, writes nothing and contacts nothing:

```sh
bin/dviscope import folder --root /path/to/logs --manifest runs.csv \
  --regression trial-1 --producer trial --repository rtl --branch main --revision unknown \
  --simulator questa     # or vcs, verilator; leave out to detect it
```

Compare the JSON it prints with what you know about that regression:

| Field | Should match |
|---|---|
| `rows` | the jobs in your CSV |
| `with_log` / `expected_without_log` | jobs that did / did not leave a log |
| `unreadable` | should be empty |
| `failures_without_diagnostics` | jobs that failed with nothing recognized in their log: **each one is a gap we want to hear about** |
| `missing_metadata` | logs without an exit code or start time in your CSV |

## 2. Check single logs (optional)

To see how one log is classified:

```sh
bin/dviscope extract --simulator questa one_test.log --out evidence.json
bin/dviscope rules explain --simulator questa --log one_test.log --line 1234
```

`evidence.json` **contains excerpts of your log**: keep it private. The most valuable cases
to look for, most serious first:

1. A run you know **failed** that DVIScope treats as passed. Please report this right away.
2. A run you know **passed** that is reported as failed or incomplete.
3. Different root causes grouped into one signature, or one cause split into many.

## 3. Triage with the server (an afternoon)

Follow [A first afternoon](first-afternoon.md): install the server, look at the demo and
create your project, producer and collector token. Then load the regression with your
producer's name and the commit it ran on, open the morning triage page, and ask for a merge
verdict for that commit:

```sh
REV=$(git -C /path/to/rtl rev-parse HEAD)     # the commit the regression ran on
bin/dviscope import folder --root /path/to/logs --manifest runs.csv \
  --regression trial-1 --producer nightly-runner --repository rtl --branch main \
  --revision "$REV" --simulator questa --submit --journal ~/dviscope-journals/trial-1
bin/dviscope journal reconcile --dir ~/dviscope-journals/trial-1

# A verdict is read with a person's token (a collector token can only deliver results).
dviscope-server admin issue-personal-token --username alice --label verdict --out ./alice.token
SRC=$(bin/dviscope source digest --repo rtl=/path/to/rtl | jq -er .source_digest)
DVISCOPE_TOKEN_FILE=./alice.token \
  bin/dviscope verdict --project rtl --regression trial-1 --expect-source "$SRC"
echo "verdict exit code: $?"      # 0 pass, 10 fail, 11 not enough evidence
```

The checkout at `/path/to/rtl` must be at the same commit.

Treat verdicts as advisory for now: do not make DVIScope your only merge gate during the
alpha. Wire formats and the database may still change between alpha versions, so keep your
original logs; you may need to import them again.

## 4. Tell us how it went

[Open a trial report](https://github.com/hexkDotCom/dviscope/issues/new?template=trial-report.yml),
even if everything worked or you stopped at step 1. If a problem can only be shown with
confidential logs, describe its *shape* (for example "a fatal message wrapped over two
lines") and we will work out a synthetic reproduction with you.

Security problems go through [private reporting](../SECURITY.md), not an issue.
