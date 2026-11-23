# Contributing

Thank you for helping. DVIScope is always free and open source (Apache-2.0); there is no
paid tier.

## Ground rules

- **No real simulator logs or output in this repository**: nothing copied from a run of a
  commercial or free simulator, and no design data. Short examples written by hand in a
  tool's message format are allowed to test its recognizers (class 1b); their content is
  invented, and only fixed strings of the format itself, such as summary counters, may
  equal real output. `cargo xtask publication-check` is a backstop; the fixture classes
  below are the rule.
- Changes to wire contracts (`crates/dviscope-model`, `schemas/`) need a schema version
  bump and a note in the pull request.
- Results must never look better than their evidence. Any change to outcome derivation,
  settlement or readiness needs a test proving it cannot turn a failure green.

## Fixture classes

| Class | What | Where |
|---|---|---|
| 1. Toy formats | Invented, non-simulator log formats that exercise the extraction engine | public tests |
| 1b. Short format examples | A few invented lines in a simulator's message format, to test its recognizers | pack self-tests, unit tests, demo |
| 2. Structural expectations | IDs, counts, outcomes, spans, digests; no simulator text | public tests, snapshots |
| 3. Generated free-simulator output | Verilator runs produced at test time | never committed or uploaded |
| 4. Commercial-simulator fixtures | Questa, VCS logs | private, outside the repository |

Simulator-backed tests run through `cargo xtask sim-test`, which keeps the raw output in a
private temporary file and prints only the case ID and lines starting with
`DVISCOPE-STRUCT:`. `cargo xtask sentinel` proves that nothing else leaks.

## The private gate

Pattern packs for commercial simulators are qualified by a private corpus gate that the
maintainer runs locally on reviewed commits of `main` (like hexk-sv-lib's Gate 2). Pull
requests from forks never run on machines with simulator licenses or private data.

## Checks before a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask schemas --check
cargo xtask deps-check
cargo xtask publication-check
cargo xtask sentinel
```

## Commits

English, imperative mood, one clear change per commit. AI-assisted contributions follow
[AGENTS.md](AGENTS.md).
