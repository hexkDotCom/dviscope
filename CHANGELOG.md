# Changelog

## [0.1.0-alpha.1] - 2026-11-23

First public pre-release, for trying DVIScope on real regression logs and giving feedback.
Start with [Trying DVIScope on your own logs](https://github.com/hexkDotCom/dviscope/blob/main/docs/trying-it.md).
Your logs stay on your machines: there is no telemetry and no cloud service.

**Included**

- Collector (`dviscope`) for Linux and Windows x86-64: supervised runs, a delivery journal,
  and import of existing log folders with an offline preview.
- Log classification for Questa, VCS and Verilator, with UVM and SVUnit output.
- Self-hosted server (`dviscope-server`) with PostgreSQL and a web UI: failure signatures,
  morning triage, exceptions that expire, merge verdicts, feature sign-off checklists,
  health dashboards, retention, backup and safe restore.

**Known limits**

- Alpha: wire formats (`1.0-dev.N`) and the database may change between alpha versions. Keep
  your original logs; you may need to import them again.
- Treat verdicts as advisory. Do not make DVIScope your only merge gate yet.
- Two issues found in internal testing are still open and will be fixed in a later alpha.
- No shipped rules for other simulators (Xcelium, Riviera-PRO, ...).
- Linux x86-64 server; Linux and Windows x86-64 collector. No ARM or macOS builds.
- Tested so far on open-source designs and synthetic faults, not yet on production
  regressions. That is what this release is for.
