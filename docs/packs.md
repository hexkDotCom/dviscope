# Pattern packs (`dviscope.rules/1.0`)

A pattern pack tells the extractor how to turn a simulator log into evidence: which lines
start a diagnostic record, which lines continue it, what the record means, which summary
lines prove the log is complete, and how diagnostics are grouped into signatures. DVIScope
ships packs for UVM, Questa, VCS, Verilator, SVUnit and a generic fallback (`patterns/`);
a project adds its own pack for its own report formats.

This page is the reference for pack authors and the contract of the extraction engine: the grammar, the extractor context, and the bounded-output rules.

- [File format](#file-format)
- [Precedence and record ownership](#precedence-and-record-ownership)
- [Detection and framing](#detection-and-framing)
- [Records](#records)
- [Summaries: markers, counters, verdicts, sections](#summaries)
- [Completion](#completion)
- [Normalization, significance, identity](#normalization-significance-identity)
- [Project rules](#project-rules)
- [Bounded output](#bounded-output)
- [Validation limits](#validation-limits)
- [Self-tests and structural expectations](#self-tests-and-structural-expectations)
- [Commands](#commands)

## File format

Strict YAML: one document, no anchors or aliases, nesting depth ≤ 16, file ≤ 1 MiB, every
mapping rejects unknown keys. Patterns are Rust `regex` syntax.

```yaml
format: dviscope.rules/1.0     # required, exact
pack: my-project                # [a-z0-9_-]+, unique in the pipeline
version: 1.0.0                  # MAJOR.MINOR.PATCH
tier: project                   # project | simulator | uvm | svunit | generic
simulator: vcs                  # simulator packs only
detect: ['^...']                # message forms that show the pack applies
framing: {strip_prefix: '# '}   # simulator packs only
replaces: [uvm_summary]         # summary sections this pack replaces when active
exit_code_meaningful: false     # informational for outcome derivation
boundaries: ['^...']            # lines that end any open record
records: [...]                  # record rules, in precedence order
markers: [...]                  # completion markers (pre-pass)
counters: [...]                 # summary counters (pre-pass)
verdicts: [...]                 # verdict sources (pre-pass)
sections: [...]                 # summary sections built from markers and counters
completion: {profiles: [...], requires_when_active: [...]}
reconcile: [...]                # counter = number of extracted events
normalize: [...]                # default normalizers of this pack's records
rules: [...]                    # suppressions and project patterns (project packs only)
tests: [...]                    # structural self-tests on invented text
```

**Templates** (`diag_id`, `checker_id`, `checker_scope`, `message`, `context`, counter
keys) are literal text with `${capture}` references; `${capture|default}` renders
`default` when the capture is missing. Every referenced capture must exist in the rule
(validation), but a capture may still be absent on a given line (an optional group): it
then renders empty, or its default.

**Mapped values** (`severity`, `kind`, `phase`, counter `role`, verdict `value`) are a
literal or `{from: capture, map: {captured: value}, default: value}`. An unmapped
severity is treated as `error` (conservative).

**Capture types**: every capture is text. `emit.fields` declares typed fields (`text`,
`integer`, `sv_literal`, `time`); `fields_from_message` parses typed fields out of the
rendered message with a pattern that has a group named `v`.

## Precedence and record ownership

Tiers, highest first: project rules → project packs → the detected simulator pack →
`uvm` → `svunit` → `generic`. Within a tier: pack order on the command line, then rule
order in the file (project rules too). A line belongs to at most one record.

Per line:

1. The **protected pre-pass** annotates the line (it never emits events): fixed
   recognizers of authoritative simulator diagnostics (below), and every active pack's
   markers, counters and verdict sources. A line that matches a marker, counter or
   verdict source is **claimed by the pre-pass**: no rule may start a record on it (an
   authoritative one still yields its failure event), and it ends any open record.
2. If a record is open and still has **mandatory** continuation lines: a boundary or an
   annotated line closes it as **cut** (`record_cut`) and the line is offered again;
   otherwise the next mandatory matcher must match (it is tried before any start, so a
   body that looks like another diagnostic stays the body), else the record is cut.
3. If a record is open past its mandatory part, the line closes it (not cut) when it is a
   boundary, an annotated line, a blank line with `until: blank`, or the start of a rule
   of the **same or a higher tier**; lower-tier starts never interrupt. Otherwise the
   first continuation matcher that matches consumes it (`capture`, `append_to`, `once`);
   no match closes the record. After `max_lines` continuation lines, a one-line lookahead
   decides: another matching continuation line means the record was cut.
4. With no record open, the first matching start (precedence order; literal `prefix`
   dispatch first) opens one. A line nobody claims is checked by the error-like
   heuristic (coverage); an unclaimed **authoritative** line still yields a failure
   event (`dviscope:unclaimed_authoritative`).
5. End of input closes the open record; a missing mandatory line is a cut.

Boundaries of every active pack apply to every record (a project pack can end a
simulator record and vice versa).

## Detection and framing

A run that declares its simulator (`--simulator`) selects that simulator pack at once.
Otherwise lines are **buffered** (up to 2,000 lines or 1 MiB) until a line matches a
simulator pack's `detect` pattern, raw or after its framing prefix; the buffered lines are
then processed with that pack's framing. If nothing is detected by the end of the buffer
(or the log), no simulator pack is used, framing is off, and the completion profile is
`unknown` (never complete). Detection uses message forms, never vendor banners.

**Framing** (e.g. Questa's `# `) is removed from every line that carries it before any
pattern runs; spans and excerpts keep the raw line.

Non-simulator packs are always active; their `detect` patterns only decide whether their
`requires_when_active` sections are required.

## Records

```yaml
- id: severity_task
  prefix: ['Error: "', 'Warning: "']        # optional; enables literal dispatch
  start: '^(?P<sev>Error|Warning): "(?P<file>[^"]+)", (?P<line>\d+): (?P<scope>\S+): at time (?P<t>\d+) ?(?P<u>[a-z]+)$'
  continuation:
    max_lines: 1                            # 1..200
    until: blank                            # or never (default)
    lines:
      - {match: '^(?P<msg>.*)$', capture: true, mandatory: true}
  emit:
    framework: simulator                    # uvm simulator assertion svunit display project
    severity: {from: sev, map: {Error: error, Warning: warning}}
    diag_id: 'sv:severity_task'
    checker_id: '${id}'                     # optional checker identity
    checker_scope: '${ctx}'                 # optional, part of the family key
    kind: check                             # check assertion timeout crash build x_z usage resource license other
    phase: run                              # default: compile for builds, run for simulations
    family: assertion                       # uvm-app tool assertion build (default from framework)
    message: '${msg}'
    anchor: {path: file, line: line, form: auto}   # full | truncated | auto (leading .. = truncated)
    sim_time: {value: t, unit: u}
    context: '${scope}'
    identity_fields: [title]                # join the identity template
    display_fields: [detail]                # shown, never part of identity
    fields: [{name: mask, type: text}]
    fields_from_message: [{name: act, match: '\bact=(?P<v>\S+)', type: sv_literal}]
    significance: {act: zero_vs_nonzero}
    normalize: [sv_literal, hex, number, whitespace]   # default: the pack's
    normalize_for: {'uvm:REF_ECC_WORD': [index_fold]}  # opt-in extras per diag_id
    fatal_witness: true                     # a fatal of this rule allows early-fatal completion
```

`prefix` must cover every string the start can match (checked with the pattern's literal
prefixes) and the start must be anchored with `^`. A rule without `emit` claims its record
and drops it (an *ignore* rule), except an authoritative start, which still fails the run.

Continuation matchers: `capture: true` adds the line's named groups to the record (the
first value wins); `append_to: field` appends the line's `text` group (or the whole line)
to a text field, newline-separated, up to 4 KiB; `once` matches at most once.

## Summaries

The pre-pass reads these on every line, whether or not a record owns it; a matched line
also acts as a boundary and cannot start a record. A counter restricted to a section
(`within`) takes part only while that section is open (a marker opening it on the same
line counts): before, it neither claims the line nor ends a record. A summary line cut at the line limit is never read (its numbers may be
truncated), and since a cut line may no longer match the summary pattern it was, **every
cut line makes the log incomplete** (`line_cut`; conservative). Every value of a counter
line must be captured, non-empty, all digits and exact (≤ 39 digits), otherwise the line
is no witness and the log is incomplete (`count_mismatch`). Counters
are one report population: a `domain:key` seen twice is a `count_mismatch` (the last
value is kept); at most 1,024 distinct counters and 64 verdict sources are kept, beyond
that the log is incomplete (`accounting_overflow`).

```yaml
markers:
  - {id: end_time, match: '^End time: ', trailer: true}              # simulator trailer
  - {id: design_load_failed, match: '^Error loading design$', design_loaded: false}
counters:
  - id: errors_line
    domain: sim_tool            # uvm_severity uvm_by_id sim_tool checks svunit banner project
    protected: true             # no rule may claim or suppress it
    within: uvm_summary         # optional: only while that section is open
    match: '^Errors: (?P<e>\d+), Warnings: (?P<w>\d+)$'
    values:
      - {key: errors, from: e, role: failure_count}    # failure_count warning_count success_count info
  - id: severity_row
    domain: uvm_severity
    match: '^(?P<sev>UVM_[A-Z]+) :\s*(?P<n>\d+)$'
    values:
      - key: '${sev}'           # a key with captures declares every key it can produce
        keys: [UVM_INFO, UVM_WARNING, UVM_ERROR, UVM_FATAL]
        from: n
        role: failure_count
verdicts:
  - {id: banner, source: banner, match: '^SIMULATION (?P<v>PASSED|FAILED)', value: {from: v, map: {PASSED: pass, FAILED: fail}}}
sections:
  - id: uvm_summary
    open: uvm_summary_heading                          # a marker of this pack
    requires: ['uvm_severity:UVM_ERROR', ...]          # domain:key counters or markers
    verdict: {source: uvm_summary, fail_if_nonzero: ['uvm_severity:UVM_ERROR', 'uvm_severity:UVM_FATAL']}
reconcile:
  - template: uvm_errors                               # uvm_errors | questa_sim_errors
    counters: ['uvm_severity:UVM_ERROR', 'uvm_severity:UVM_FATAL']   # summed
    frameworks: [uvm]
    severities: [error, fatal]
```

`design_loaded` starts `unknown`; `false` is sticky. Verdict sources record the line's
span.

A counter value must be decimal digits; anything else is a `count_mismatch`. A key built
from captures must render to one of its declared `keys`; any other rendered key is a
`count_mismatch` and is not kept, so a pack can only produce the counters it declares.
A literal key is its own declaration. A `role` given as a map must resolve for every
value it meets (or carry a `default`); an unresolved role is a `count_mismatch`, never a
silent `info` counter.

Marker IDs may not contain `:`, so a requirement names either a marker or a `domain:key`
counter, never both. A section `verdict` with `fail_if_nonzero` names counters of the pack
(never markers) that must also be in the section's `requires` (the pack is rejected
otherwise). The verdict is computed only from stored counts: a section that closes without
one of them yields no verdict and a `count_mismatch`, never a pass read from a missing
count.

**Reconciliation populations**. A template runs when all its counters were
seen; a template whose counters were only partly seen does not hold (`count_mismatch`),
since a partial total is never compared; it sums their last values (*counted*) and counts the extracted events of its
frameworks and observed severities, before suppression or overrides (*extracted*). The
relation is *extracted ≤ counted*, computed exactly (a total that cannot be represented
is a `count_mismatch`, never a substituted value): a summary may count messages it did not print, never
fewer than were printed. A violation makes the log incomplete (`count_mismatch`); counted
> extracted is not a mismatch (outcome derivation adds `UNEXPLAINED_FAILURE`). Every
result is kept in `evidence.reconciliation`.

| Template | Counted | Extracted population | Overlapping summaries |
|---|---|---|---|
| `uvm_errors` | `uvm_severity` `UVM_ERROR` + `UVM_FATAL` of the report summary | framework `uvm` (standard lines and project report-server tables alike), error and fatal | the by-ID counts, a project's own summary table and banner counts are not counted |
| `questa_sim_errors` | `sim_tool` `errors` (the closing `Errors: N`) | frameworks `simulator` and `assertion`, error and fatal | — |

SVUnit has no template: a failing runner summary without failure events is an unexplained
verdict (outcome), and failure events with a passing summary are a contradiction. One log
is one report population: a section opened a second time (concatenated executions) is a
`count_mismatch`.

## Completion

The profile is chosen from the evidence subject (`simulation` or `build`) and the
selected simulator pack. Witnesses are qualified by their pack: a profile's `requires`
names markers, counter rules and sections **of the simulator pack itself**, a section's
`requires` those of its own pack, and the trailer must be a simulator-pack marker; a
project marker of the same name never satisfies them. `a|b` in `requires` accepts either
witness (a Verilator build ends with its report or with its closing error count). A log is **complete** (mode `normal`) when every item of the
profile's `requires` (markers, counter rule IDs or sections) was seen, every section that
an active, detected non-simulator pack `requires_when_active` is complete (unless an
active pack `replaces` it), the design-load state is known if the profile asks for it, a
decisive verdict source (pass or fail; "not applicable" alone is none, and a run whose
only verdict is not applicable never passes) exists if the profile asks for one, and
accounting is exact (no cut
failure record, no cut line inside a failure record, every reconciliation holds).

**Early fatal** (profiles with `early_fatal: true`): complete with mode `early_fatal` when
a fatal witness (a retained, failing fatal event of a `fatal_witness` rule — a suppressed
fatal is none — or a `fatal_witness` marker), the
simulator trailer and every item of the simulator profile were seen, the design-load
rule holds and accounting is exact; sections of other packs and verdict sources may be
missing. A runner crash is never early-fatal.

An empty log is `missing` (`empty_log`); no profile is `incomplete` (`unknown_profile`);
otherwise reasons are `no_end_marker`, `record_cut`, `line_cut`, `count_mismatch` and
`accounting_overflow`.
`sections_seen` lists the required items in the order they were seen.

A profile has `select: default` (the default; the first default profile of the subject is
the simulator's profile) or `select: declared`: chosen only when the run declares it. The
one declared profile is the Verilator pack's `verilator-model-main`; every subject a pack
declares keeps a default profile, and profile names are unique in a pipeline (evidence
records the name; the server resolves the simulator, and whether its exit code means
anything, from it). Rendered templates are bounded to 64 KiB.

### Verilator models with their own main

A Verilator model built with its own C++ main (instead of `--binary`) never prints
Verilator's simulation report, so `verilator-run` can never call it complete, and the log
alone cannot tell such a run from a truncated `--binary` one. The run therefore
**declares** it, and a project pack names the model's console markers:

- The slot's execution inputs carry `extra.tool.main = "model"` (sealed in the manifest;
  any other value is refused). The server refuses evidence whose profile disagrees with the
  slot either way, so a producer cannot switch profile per attempt. The declaration is
  consistency, not attestation: as for every profile, the producer's collector is trusted
  to run the executable its sealed inputs declare, one execution per attempt.
- The collector needs `--log` (the program's own log) and `--console` (stdout and stderr),
  two distinct files it creates exclusively for the attempt; it hands the console handle to
  the child and reads both back through its own handles (a file replaced, moved away or
  deleted during the attempt is refused and the attempt recorded as interrupted; on Windows
  the collector's handles forbid deleting or renaming them). Writers to the two files stay
  trusted and exclusive until the collection ends: an overwrite in place is not detected. The evidence is the program log then
  the console, joined by the collector: `source.segments` records the two streams (byte
  ranges, global line ranges, null lines for an empty segment), and no line or record spans
  the boundary (a record cut there is cut as at the end of a file). `import folder` takes
  the same pair through its `main` and `console` columns.
- A project pack declares the markers (one pack per pipeline):

```yaml
markers:
  - {id: banner, match: '^My model start$'}
  - {id: stats, match: '^My model statistics$'}
  - {id: last, match: '^My model last line'}
completion:
  model_main: {start: banner, trailer: [stats, last]}
```

The run is complete when, **in the console segment**, the start marker, Verilator's
`- file:line: Verilog $finish` line and every trailer marker each appear **exactly once**
and in that order (the last trailer marker is the model's final line, so a cut inside its
statistics is incomplete); none of them appears in the program segment; a verdict source
with a span says `pass` (a not-applicable or producer verdict never does; a console verdict
lies before the finish); Verilator's report is absent; the sections of detected packs are
complete and accounting is exact. There is no early-fatal mode. Reasons:
`segments_missing`, `witness_count`, `witness_order`, `witness_segment`,
`profile_conflict` (a Verilator report, or another simulator), `model_main_undeclared`
(no pack declares the markers), plus the usual ones. A second execution cut before it
prints anything the markers recognize cannot be seen in the console: one execution per
attempt is the producer's contract. `rules explain --log PROGRAM --console CONSOLE` explains
the joined pair (lines are joined lines) and lists the segments and every marker's count and
positions. In an activation sample, a model case's log is the program log followed by the
console, and its expectation says `"model_main": true` and `"console_at": N` (the console's
first byte), so `rules check` extracts it joined.

## Normalization, significance, identity

Normalizers (pure, idempotent; `diag_id` and `checker_id` are never normalized):

| Name | Replaces | With |
|---|---|---|
| `sv_literal` | `8'hff`, `'b10x1`; unbased `'0` `'1` `'x` `'z` | `<SV:h>`, `<SV:bx>`; `<SV:u>`, `<SV:ux>` |
| `hex` | `0x1f`; words of ≥ 6 hex digits with a decimal digit; a value of ≥ 4 hex digits after `=` | `<HEX>` |
| `time` | `12.5 ns`, `30ps` | `<T>` |
| `path` | absolute Windows, WSL and POSIX paths | `<P>/basename` |
| `number` | decimal integers | `<N>` |
| `whitespace` | runs of white space | one space, trimmed |
| `suffix_strip` | every trailing parenthesized group | nothing |
| `index_fold` (opt-in) | `[12]`, `name_12` | `[*]`, `name_*` |

Each event records up to 16 replacements ("why these match"). Replicated-instance
equivalence is never implicit: `index_fold` is opted into per rule or per `diag_id`.

**Significance** of typed fields: `verbatim`, `zero_vs_nonzero` (`zero`, `nonzero`, `x`,
`other`), `x_vs_known`, `class:a|b|c` (`other` outside the list). A declared field missing
from an event has the class `missing`, never equal to a value.

**Identity**: identity template = normalized message plus ` | name=value` for each
identity field. Family key = `(family, diag_id, checker_scope, identity_template,
significant)`, plus the source anchor (path form and line) when the event has no checker
ID. Anchors under a `--source-root` become repository-relative; a truncated anchor is
never treated as resolved. Fingerprint v1 = `sha256(JCS({schema: "fp/1", key}))`.

The pipeline digest covers the extractor version, the fixed-code versions (`protect/1
norm/1 error-like/1 bounded/1`), the fingerprint schema and every pack (ID, version and
the digest of its bytes) in pipeline order.

## Project rules

Project packs may carry rules (precedence above every pack):

```yaml
rules:
  - {id: known-noise, version: 1.0.0, kind: suppression, owner: team, reason: why,
     action: not_an_error, diag_ids: ['display:error'], match: 'optional message pattern'}
  - {id: demote, version: 1.0.0, kind: suppression, owner: team, reason: why,
     action: severity_override, severity: warning, diag_ids: ['uvm:SOME_ID']}
  - {id: my-line, version: 1.0.0, kind: project_pattern, owner: team, reason: why,
     fails_run: true, record: {id: my-line, start: '^MY: (?P<m>.*)$', emit: {...}}}
```

A `fails_run: true` pattern has an `emit` (a record without one is consumed silently) whose
severity is warning or above, every mapped value and its default included (diagnostics below
warning never enter accounting, so a declared failure could otherwise vanish). An
identifier (`diag_id`, `checker_id`, `checker_scope`) that would exceed the 64 KiB render
bound makes the log incomplete (cut, it could equal another one). Every selector a suppression gives (`diag_ids`, `match`) must
match: they constrain each other. A suppression records the rule, the observed severity, the exact count and
the first five spans. **Authoritative** provenance (set by the fixed recognizers on the record's
start line, whatever rule owns it) cannot be suppressed as a failure: an authoritative
error keeps `fails_run` while its presentation (effective severity) changes; other
`not_an_error` events leave accounting. Authoritative warnings are suppressible.

Fixed recognizers (`protect/1`, not configurable): Questa `** Error|Fatal|Warning:`; VCS
`Error-[ID]`, `Warning-[ID]`, `Error|Fatal|Warning: "file", N: scope: at time`, concurrent
assertion failures; Verilator `%Error`, `%Fatal`, `%Warning` (also after `[time]`), except
the closing `%Error: Exiting due to N error(s)`.

## Bounded output

Contract `bounded/1` (limits in `dviscope_model::limits`):

- **Accounting scope**: records of observed severity ≥ warning produce events; info
  records are claimed and counted in reconciliation tallies only.
- **Bucket equality**: same fingerprint, `diag_id`, `checker_id`, site (anchor
  `path:line`), observed and effective severity, framework, phase, kind, provenance and
  `fails_run`. Every bucket's count is exact.
- **Caps**: at most 1,024 buckets and 512 families, and buckets plus families ≤ 256 KiB
  serialized. A new family is created only together with its first bucket. An event that
  would need a bucket or family beyond a cap is counted exactly in `overflow` by
  (framework, phase, kind, observed severity, provenance, `fails_run`); a later event of
  an existing bucket is still counted in it (late new families go to overflow). Any
  overflow makes completion `incomplete` (`accounting_overflow`): the counts stay
  exact, but expectations become unassessable.
- **Examples** (≤ 300 events, ≤ 512 KiB): selection order is the display-primary event,
  then the first 100 failure events, then each bucket's first and last event (bucket
  order); an event already chosen is skipped; an event that would exceed the byte budget
  is skipped and selection continues; the result is sorted by ordinal. Each bucket names
  its first retained example. The **display primary** is the best event by (`fails_run`,
  observed severity), the earliest on ties; the first warning-or-worse event is the
  initial candidate.
- **Excerpt** (≤ 64 KiB serialized, no seeks): the 40 lines before the primary record,
  the primary record (≤ 200 lines), the 20 lines after it, and the last 20 lines of the
  log; segments never overlap (a later segment starts after the previous one's last
  line); every line is cut to 1 KiB on a UTF-8 boundary; the budget counts each line as
  serialized JSON (escapes included) plus per-segment structure; lines beyond it are
  dropped and `truncated` is set.
- **Lines** longer than 16 KiB keep their first 16 KiB, cut on a character boundary; the
  rest is drained without buffering. Any cut line makes the log incomplete (`line_cut`:
  also outside a failure record or a required section, because a cut
  summary line can no longer be recognized); a cut failing record (by the final failure
  predicate, explicit project failures included) is `record_cut`. Records stop
  growing at 256 KiB (cut). Lines are processed as they are cut, whatever the size of the
  chunks the caller pushes.
- **Coverage** (`error-like/1`): an unclaimed line, or a continuation line of a record
  below warning, that has an error/fatal word where a message starts (after optional
  white space, punctuation, a bracketed tag or `**`) or an upper-case `ERROR`, `FATAL`,
  `FAILED` or `FAILURE` word. Exact count, first five spans.
- **Memory** does not grow with the log: detection buffers ≤ 1 MiB, record assembly ≤
  256 KiB, the fingerprint cache ≤ 4,096 entries.

## Validation limits

A pack is rejected whole, with the rule named: unknown keys; bad patterns; a referenced
capture, section (`within`, `requires`) or counter (`reconcile`, section `requires`: a
counter rule of the pack must be able to produce the `domain:key`; a counter key template
uses each capture at most once and at most 8 variables, so this check is exact) that
does not exist; a
`prefix` that is not a literal prefix of `start`, or a start not anchored with `^` on
every alternative; `max_lines` outside 1..200; mandatory lines after optional ones; a
compiled regex program over 256 KiB; per pipeline more than 2,000 rules, 4 MiB of pattern
source or 32 MiB of compiled patterns (every pattern counts: records, continuations,
message fields, counters, verdicts, markers, detection, boundaries, suppressions; charged
before the next is compiled); duplicate IDs; declarations a tier may not make (framing,
profiles, rules).

## Self-tests and structural expectations

Every pack carries `tests` on short invented examples in its tool's message format:

```yaml
tests:
  - name: a missing body at the end cuts the record
    simulator: vcs            # optional; default: detection
    subject: simulation       # or build
    input: |
      Error: "top.sv", 7: top: at time 10 ps
    events: ['sv:severity_task@1']    # diag_id@start line of every emitting record, in order
    record_cuts: 1
    completion: incomplete
```

`dviscope rules check --sample DIR` also runs every `<case>.expect.json` in a private
sample directory (`dviscope.expect/1`): `log`, `subject`, `simulator`, `completion`,
`mode`, `design_loaded`, `verdicts` (`source: value`), `failures` (exact failing counts by
`diag_id`), `failures_exact` / `exact_prefixes`, `simulator_errors`, `families` (count per
`diag_id`), `primary`, `max_unclaimed`, `failure_anchored_in`. The report contains IDs,
counts and states only, never log text.

## Commands

```
dviscope extract LOG [--subject simulation|build] [--simulator S] [--pack FILE|builtin:NAME]...
                     [--no-default-packs] [--source-root PREFIX]... [--out FILE]
dviscope rules check [pack options] [--sample DIR] [--evidence-out DIR]
dviscope rules explain --log FILE --line N [pack options]
```

`rules explain` prints the record covering a line (rule, captures, cut), the rules whose
start matches it (the first claims, the others are shadowed), and the event with its
identity template, normalizations and fingerprint. It prints the line's text: run it on
your own logs only.
