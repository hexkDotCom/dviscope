# Corpus harness

The corpus is the set of real simulator runs that DVIScope's extraction and outcome rules are
qualified against (plan §4.4, D.3). **No logs live here**: this directory holds only the
harness, the design and mutation definitions and the case expectations. The logs are
generated on the maintainer's machine into a private directory outside the repository and
never committed or uploaded (CONTRIBUTING.md, publication rules).

| File | What |
|---|---|
| `designs.toml` | designs, where their sources come from, and how each simulator builds and runs them |
| `mutations.toml` | fault injections: structured edits applied to a private copy of a design |
| `cases.toml` | corpus cases: design × simulator × variant × run, with the expected oracle result |
| `matrix.toml` | applicability matrix: design x simulator x fault class, with a reason for every cell that does not apply |
| `public-ids.txt` | case IDs that tests may print (generated from `cases.toml`) |
| `designs/ibex/selfcheck/` | self-checking program for the Ibex simple system (synthetic) |
| `harness/corpus.py` | the harness |

## Labels are earned, not assumed

A case's label comes from the **design's own oracle**, never from DVIScope:

- hexk-sv-lib reference testbench: `scripts/hexk_check_run.py` (verdict and exact counts per
  report ID);
- SVUnit suites: the runner summary;
- hexk-sv-sim-quirks: the `QUIRK_RESULT` line, judged like the repository's own runner;
- Ibex simple system: the result line of `designs/ibex/selfcheck`.

A mutant case is labelled only when, **within one campaign**, its **control** (the same run
without the mutation) passed, the mutant run shows **fault-specific activation evidence**
(the declared failure and IDs; for compile faults the design's own compile-failure marker
naming the mutated file; for runtime faults the runner's own timeout or kill), and the
**recovery** run (mutation removed again) passed with its build started after the mutant
finished. Every verdict label also needs a good build and a run that ended by itself. A
data-dependent mutant's runs are each either an activated failure or a clean pass. Evidence
is bound to its case definition and source revision; a change makes it stale. Anything else
leaves the case unlabelled, and the harness says why.

## Running (maintainer only)

```bash
corpus.py --config <private>/corpus-local.toml prepare
corpus.py --config <private>/corpus-local.toml campaign
corpus.py --config <private>/corpus-local.toml run --group ref-clean [--sim vcs]
corpus.py --config <private>/corpus-local.toml label
corpus.py --config <private>/corpus-local.toml ids > corpus/public-ids.txt
corpus.py --config <private>/corpus-local.toml manifest --side windows=<out-windows> --side wsl=<out-wsl> --out <private>/corpus-manifest.toml
```

`campaign` starts a qualification campaign; `run` builds the group's variant (applying its
mutation to the private copy) and runs every case of the group on the simulators of the
current side (`windows` or `wsl`), with bounded timeouts for builds and runs. Run the groups
in label order: controls, mutants and faults, recovery last. `label` applies the oracles to
the current campaign and writes the private label results (`manifest-<side>.json`). Every
private write is checked to resolve inside the private output directory and outside the
repository.

The private configuration names the source checkouts, the work and output directories and
the simulator environments; it is never committed.

`manifest` merges the label results of both sides into the corpus manifest
(`dviscope.corpus/1`, private) and fails unless every case of `cases.toml` is present once
and labelled, every case lies in an applicable cell of `matrix.toml`, every applicable cell
has a labelled (for data-dependent mutants: activated) case, every other cell has a reason,
and every evidence stream (log, build log, console) still has its recorded digest.

## Structural expectations of the extraction engine

```bash
corpus.py --config <private>/corpus-local.toml extract-check --side windows=<out-windows> --side wsl=<out-wsl> \
  --dviscope <dviscope binary> --pack builtin:hexk-report-server \
  --pack corpus/packs/hexk-sim-quirks.yaml --pack corpus/packs/ibex-selfcheck.yaml \
  --source-root <work-windows>/src --source-root <work-wsl>/src --work <private>/extract
```

For every labelled case, `extract-check` writes a private structural expectation
(`dviscope.expect/1`, see `docs/packs.md`) derived from the case's oracle result and runner
facts (failing IDs and counts from the design's own check script, the simulator's own error
total, completion from the runner's termination, the primary from the design's "First
error" line) plus the hand-written `structure.toml`. It then runs `dviscope rules check`
over them and checks the cross-case pairs of `structure.toml` (families that must merge or
stay separate) on the private evidence. It prints case IDs and structural differences
only. `structure.toml` is not part of the corpus definitions digest.

`packs/` holds the corpus's own project packs (quirk probe results, the Ibex self-check).
