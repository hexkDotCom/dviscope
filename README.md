# DVIScope

**DV Intelligence for regression triage.** DVIScope collects the results of your simulation
regressions, groups failures into signatures, and tells you what needs a decision, why a
merge is blocked, and what still blocks a feature's sign-off. It is free, open source
(Apache-2.0) and self-hosted, with no telemetry. It is a member of the hexk DVI family,
beside [DVICode](https://github.com/hexkDotCom/dvicode).

> **Status: first public alpha (0.1.0-alpha.1).** Ready to try on real regression logs, not
> yet to rely on: treat verdicts as advisory. Wire formats (`1.0-dev.N`) and the database may
> still change. **[Try it on your own logs](docs/trying-it.md)**: the first step takes ten
> minutes, needs no server, and your logs never leave your machine.

## What 0.1 will do

- **Morning triage**: every current failure group of the latest regression is accounted for
  as *needs decision*, *assigned* or *covered by a valid exception*; missing results are
  visible; known failures are handled without opening raw logs.
- **Blocked merge explained**: `dviscope verdict --mode merge` returns pass, accepted with
  exceptions, fail or insufficient evidence, with each blocker, its owner and the smallest
  clearing action.
- **Feature sign-off blockers**: an imported checklist shows satisfied, failed, missing,
  outdated and unreviewed requirements with owners and the evidence selected.

Results are never greener than the evidence: exit code 0 is not a pass, an incomplete log
never passes, quarantined or withdrawn evidence never exposes an older pass, and exceptions
never cover what was not identified.

## Layout

| Path | What |
|---|---|
| `crates/dviscope-model` | Wire contracts: IDs, canonical JSON (RFC 8785) and digests, schemas, error codes |
| `crates/dviscope-core` | Algorithms (no I/O): execution identity, extraction, settlement, readiness |
| `crates/dviscope-server` | Server: API, ingest, UI hosting |
| `crates/dviscope-cli` | `dviscope` command-line client |
| `crates/dvi-simlog` | Simulator log helpers shared with DVICode |
| `schemas/` | Generated JSON Schemas (checked in) |
| `xtask/` | Development checks (`cargo xtask ...`) |
| `deploy/` | Container image (server and web UI), compose file, provisioning scripts |

## Documentation

| | |
|---|---|
| [Try it on your own logs](docs/trying-it.md) | an offline preview, then how to report what you find |
| [Install](docs/install.md) | release archives, verification, the compose recipe, collectors |
| [A first afternoon](docs/first-afternoon.md) | from an installed server to a nightly you can triage |
| [Operating the server](docs/operate.md) | configuration, migrations, provisioning, retention, backup and restore |
| [Security operations](docs/security.md) | the baseline, and the leaked-token rehearsal |
| [Command reference](docs/cli.md) · [Errors](docs/errors.md) · [HTTP API](docs/api.md) | generated from the binaries and the registry (API: by hand) |
| [Delivery journal](docs/journal.md) · [Pattern packs](docs/packs.md) | formats |

## Building

Rust 1.99 (pinned in `rust-toolchain.toml`):

```bash
cargo build --workspace
cargo test --workspace
cargo xtask schemas --check
cargo xtask deps-check
cargo xtask publication-check
cargo xtask docs --check        # generated reference docs (cli.md, errors.md)
cargo xtask release-dry-run     # static binaries, web UI and the offline bundle (target/dist)
```

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
