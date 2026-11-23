# Instructions for AI coding assistants

These rules apply to any AI tool working in this repository.

1. **Never add real simulator logs or output** (Questa, VCS, Xcelium, Verilator), or text
   copied from a run. Use invented toy formats, structural expectations, or short invented
   examples in a tool's message format (CONTRIBUTING.md, fixture classes). Run
   `cargo xtask publication-check`.
2. **Keep the layering**: `dviscope-model` and `dviscope-core` do no I/O and read no clock,
   environment or randomness (`cargo xtask deps-check`). In the server, HTTP handlers call
   exactly one application operation; operations own authorization, transactions, history
   and audit; database helpers never commit.
3. **Never make results greener than the evidence.** Exit code 0 is not a pass; incomplete
   evidence never passes; quarantined or withdrawn evidence never exposes an earlier pass;
   exceptions cover identified failures only. Every change to outcome, settlement or
   readiness needs a test that tries to turn a failure green.
4. **Contracts are generated**: change the Rust types, then run `cargo xtask schemas`;
   never edit `schemas/` by hand. Wire changes bump the development schema version.
5. **No secrets** in code, tests, logs or error messages; tokens are `dvis_...` and must
   never be printed.
6. `unsafe` is forbidden except in the reviewed Windows platform module of the CLI.
7. Before finishing: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, and the `xtask` checks listed in CONTRIBUTING.md.
