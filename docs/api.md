# HTTP API (`/api/v1`)

Contract of the collection and read API. All requests and
responses are JSON (NDJSON for batches) over TLS. Errors use the error registry
(`dviscope_model::errors`): `{code, message, field?, record?, committed, correlation_id}`.

## Authentication and authorization

- **API**: `Authorization: Bearer dvis_…` (collector or personal token). **Browser**:
  cookie `__Host-dviscope` + `X-DVIScope-CSRF` header on every state-changing request +
  `Origin` equal to the canonical origin. Both at once → 400 `E_MIXED_CREDENTIALS`.
- One table maps every route to an action; `authorize(actor, action, object)` decides.
  Collector tokens are bound to one project and one producer and carry scopes; personal
  tokens and sessions act with the user's current role in the project.

| Action | Collector scope | Role |
|---|---|---|
| `regression.create`, `source_manifest.create` | `regression:create` | — |
| `manifest.chunk` | `manifest:declare` | — |
| `manifest.seal` | `manifest:seal` | — |
| `manifest.amend`, `slot.mark` | `manifest:amend` | — |
| `ingest.submit` | `ingest:submit` | — |
| `regression.finish` | `regression:finish` | — |
| `regression.read`, `comparison.read` | — (denied) | viewer |
| `readiness.read`, `changes.read`, `checklist.read` | — (denied) | viewer |
| `triage.write`, `publication.write` | — (denied) | triager |
| `exception.write`, `admin.read`, `checklist.write` | — (denied) | admin |
| `session.login`, `session.logout` | — | (anyone / own session) |
| anything unmapped | denied | denied |

## Endpoints

| Method and path | Body | Action | Success | Durable effect, idempotency |
|---|---|---|---|---|
| `GET /healthz`, `GET /readyz` | — | none | 200 | — |
| `GET /api/v1/capabilities` | — | none | 200 limits, schemas | — |
| `POST /api/v1/source-manifests` | `SourceManifest` | `source_manifest.create` | 201 / 200 receipt | idempotent by (producer, ref, digest); other digest → 409 |
| `POST /api/v1/regressions` | `RegressionCreate` (the branch's repository name is non-empty without `/`, its name non-empty: `repository/branch` names the branch of triage cases, exceptions and feature candidates) | `regression.create` | 201 / 200 receipt; 400 `E_INVALID` for such a name | idempotent by (producer, ref, digest); other digest → 409 |
| `PUT /api/v1/regressions/{ref}/manifest/chunks/{n}` | `ManifestChunk` | `manifest.chunk` | 200 receipt | see the state table |
| `POST /api/v1/regressions/{ref}/manifest/seal` | `ManifestSeal` | `manifest.seal` | 200 receipt | see the state table |
| `POST /api/v1/regressions/{ref}/manifest/amend` | `ManifestAmend` | `manifest.amend` | 200 receipt | see the state table |
| `POST /api/v1/regressions/{ref}/slots/mark` | `SlotMark` | `slot.mark` | 200 receipt | see the state table |
| `POST /api/v1/regressions/{ref}/finish` | `{}` | `regression.finish` | 200 receipt | idempotent |
| `POST /api/v1/reconcile` | `{identities: [≤ 1,000], regressions: [≤ 100]}` | `ingest.submit` (collector) | 200 for the collector's own producer: each identity's receipts (every revision with its digest, then its aliases: the digest of an equivalent source manifest declared again under a later compatible development label, listed under the same revision; or the retention tombstone's highest revision) and each regression's slot counts (declared, started, reported; or not found / past retention); read-only, also in maintenance | none |
| `POST /api/v1/ingest` | NDJSON of `IngestRecord` (≤ 1,000 records, ≤ 8 MiB encoded, ≤ 32 MiB decoded, gzip ratio ≤ 20) | `ingest.submit` per record | 200 NDJSON of per-record results | each record its own transaction (B.15); records fail independently |
| `GET /api/v1/projects/{project}/regressions/{ref}` | — | `regression.read` | 200 header, slots with derived states; 410 `E_EXPIRED` for a regression retention removed (also its readiness, comparisons and repair list) | none |
| `GET /api/v1/projects/{project}/regressions/{ref}/comparison?baseline={ref\|none}` | — | `comparison.read` | 200 header, signature rows (each with its project `number`, `diag_id` and `identity_template`, triage state and `triage_revision` (the base of an edit), owner, latest note, bug link, exception, `disposition` needs_decision / assigned / covered, and `next_action`; new and undecided first; `group: build \| elaboration` rows for blocked slots without a signature), the `finish` card and the `baseline` used with its reason (default: the most recent earlier finished regression of the same producer, suite and repository-qualified branch), inside `baseline` also `simulators` (`{current, baseline}`: arrays of the simulator names the slots declare or report, `baseline` null without a baseline) and `simulators_differ` (both arrays non-empty and different) | none |
| `GET /api/v1/projects/{project}/regressions/{ref}/repair-list` | — | `regression.read` | 200 slots without an eligible result (missing, or reports rejected by a quarantine or withdrawn pipeline) with reason and recovery, grouped by producer, plus copyable `text` (no paths, hosts or tokens) | none |
| `GET /api/v1/projects/{project}/regressions/{ref}/readiness?expect_source=D` | — | `readiness.read` | 200 `dviscope.verdict/1.0-dev`: verdict, `dig/2` digest, blockers, `proof` (each accepted required slot: accepting attempt, builds, retry, expectation, exceptions), log-free `summary` | none |
| `GET /api/v1/projects/{project}/regressions/{ref}/readiness/preview?signature=N&expires_at=T` | — | `readiness.read` | 200 impact of a hypothetical exception for the regression's branch and suite: slots it covers, slots that stay blocked, simulators, scope, verdict before and after | none (nothing stored) |
| `PUT /api/v1/projects/{project}/triage/{signature}?branch=repo/name` | `{state, owner?, notes, bug_urls}`; `If-Match: "rev"` to edit | `triage.write` | 200 `{id, revision}` + `ETag` | new revision; 412 if `If-Match` is stale |
| `POST /api/v1/projects/{project}/triage?branch=repo/name` | `{signatures: [{number, if_match?}], state, owner?, notes, bug_urls}` (1 to 500 distinct signatures; `if_match` is the case's head revision, absent or 0 for a signature without a case on the branch) | `triage.write` | 200 `{cases: [{signature, id, revision}]}` | one decision for every listed signature in one transaction: each gets a new revision, or nothing is written; 412 naming the first stale signature; an unknown or repeated signature → 400 |
| `POST /api/v1/projects/{project}/exceptions` | `{signature, branch, suite, reason, expires_at}` (≤ 180 days) | `exception.write` | 201 `{id, revision}` | supersedes the live exception of the scope |
| `DELETE /api/v1/projects/{project}/exceptions/{id}` | — | `exception.write` | 204 | revoked |
| `GET /api/v1/projects/{project}/changes?since=N` | — | `changes.read` | 200 `{change_seq, changes[]}` | none |
| `GET /api/v1/projects` | — | `regression.read` (people only) | 200 projects the user has a role in | none |
| `GET /api/v1/projects/{project}/regressions?before=C&limit=L` | — | `regression.read` | 200 page (default 100, ≤ 500; ordered by start then id) + opaque `next` cursor for `before` | none |
| `GET /api/v1/projects/{project}/signatures/{signature}` | — | `regression.read` | 200 signature, occurrences (each with its regression and that regression's `producer`, slot, attempt), triage per branch, current exceptions (not revoked or superseded; `expired: true` once past `expires_at`, when it covers nothing) | none |
| `GET /api/v1/projects/{project}/regressions/{ref}/slots/{slot}/attempts/{seq}?producer=NAME` | — | `regression.read` | 200 revisions, diagnostics, evidence (or the expired-excerpt note) | none |
| `GET /api/v1/projects/{project}/admin` | — | `admin.read` | 200 members, collector-token metadata (never secrets), producers with their integration assurance profile (counting, build provenance, merge gating — from what each producer sends; a source manifest naming no repository counts as none), pipelines; read-only (changes: `dviscope-server admin`) | none |
| `GET /api/v1/projects/{project}/rules` | — | `rules.read` | 200 active pipeline digest, its packs (names), the activation sample (cases, bytes, digest) and the latest activations | none |
| `GET /api/v1/projects/{project}/rules/definition` | — | `rules.read` | 200 `{digest, definition: dviscope.pipeline/1, sample}`: the active definition with its pack texts (none activated: the shipped default) | none |
| `GET /api/v1/projects/{project}/rules/sample/files/{sha256}` | — | `rules.write` | 200 `{sha256, size, received, complete}` (resume point) | none |
| `PUT /api/v1/projects/{project}/rules/sample/files/{sha256}?size=N&offset=O` | raw bytes (≤ 4 MiB) | `rules.write` | 200 upload state | appends at `offset` (else 400 naming where to resume); the last chunk is verified against the digest (a mismatch discards the file, 422) |
| `POST /api/v1/projects/{project}/rules/sample` | `dviscope.sample/1` manifest (≤ 200 cases, ≤ 64 MiB) | `rules.write` | 201 `{digest, cases}` | becomes the project's activation sample (every log uploaded and complete) |
| `POST /api/v1/projects/{project}/rules/activations` | `{definition, check}` (`dviscope.rule_check/1` structural result) | `rules.write` | 201 activation | the server re-runs the check over the stored sample: no sample → 400 (`sample`); a check bound to another active pipeline, definition or sample → 409 `E_STALE_REVISION`; a different or failing result → 422; else the new digest is accepted |
| `GET /api/v1/projects/{project}/admin/retention` | — | `admin.read` | 200 what retention would expire in the project as of the database clock: the policy in days and a dry-run report (each regression with its cohort, end and action; build and receipt counts; its impact: feature-readiness candidates whose newest evidence a removal expires, and monitored publications of removed regressions); takes no lock a writer waits on | none |
| `GET /api/v1/projects/{project}/ledger` | — | `admin.read` | 200 `dviscope.ledger/1.0`: current triage cases and live exceptions keyed by signature fingerprint, with original authors | none |
| `POST /api/v1/projects/{project}/ledger` | `{ledger, mapping?, dry_run?}` | `triage.write` (exceptions need `exception.write`) | 200 per-record outcomes (`applied`, `would_apply`, `exists`, `unmatched`, `expired`, `not_permitted`, `invalid: …`) | applied through the ordinary triage and exception paths; existing decisions kept; the importer acts, the original author is recorded |
| `POST /api/v1/projects/{project}/readiness/publications` | `{regression, producer?, expect_source, target: {repository, commit, context}}` | `publication.write` | 200 `{action: unchanged \| post, receipt}`; the receipt carries the status `state` (success only for pass / accepted with exceptions) and `description` (verdict, evaluation time, validity, digest prefix) | a refresh of the posted receipt, or a new immutable receipt |
| `GET /api/v1/projects/{project}/readiness/publications` | — | `publication.write` | 200 receipts not retired (what a restarting publisher resumes) | none |
| `POST /api/v1/projects/{project}/readiness/publications/{digest}/posted` | `{state}` (the receipt's own) | `publication.write` | 200 receipt | posted; older receipts of the target retired (`superseded`) |
| `POST /api/v1/projects/{project}/readiness/publications/{digest}/retire` | `{reason: monitoring_ended \| superseded}` | `publication.write` | 200 receipt | retired (idempotent) |
| `GET /api/v1/projects/{project}/readiness/receipts/{digest}` | — | `readiness.read` | 200 the published receipt next to a current evaluation of the same regression and candidate | none |
| `POST /api/v1/projects/{project}/checklists` | `dviscope.checklist/1.0` as JSON (`schemas/checklist.json`; the CLI converts YAML) | `checklist.write` | 201 imported (item revisions) / 200 duplicate; another body under an existing version → 409 | immutable version; an item's revision changes when its `requires` or evidence digest changes |
| `GET /api/v1/projects/{project}/checklists` | — | `checklist.read` | 200 checklists with their latest version | none |
| `GET /api/v1/projects/{project}/checklists/{checklist}/evaluation?branch=repo/name&version=V` | — | `checklist.read` | 200 feature evaluation: per item `state` (satisfied, failed, missing, insufficient, outdated, unreviewed, or not_applicable), every reason, per test/configuration the candidate regression (`started_at` in Unix microseconds) and seeds, seeds per simulator, `next_action`; `ready`, `valid_until`, `dig/2` digest | none |
| `POST /api/v1/projects/{project}/checklists/{checklist}/attestations` | `{version, item_id, item_revision, evidence_digest}` exactly as shown | `checklist.write` | 201 `{id}`; 412 when the item changed | attestation |
| `DELETE /api/v1/projects/{project}/checklists/{checklist}/attestations/{id}` | — | `checklist.write` | 204 | revoked |
| `PUT /api/v1/projects/{project}/hierarchy` | `dviscope.hierarchy/1` as JSON (the CLI converts YAML): `nodes` (paths), `streams` (one home node each, optional `cadence`), `links` (a stream also shown under another node) | `hierarchy.write` | 201 a new revision / 200 duplicate (same as the current revision); every file problem located (`streams[3].node`); unknown producer → 400 | new revision when it differs from the current one (A→B→A is three revisions); audited |
| `GET /api/v1/projects/{project}/hierarchy` | — | `hierarchy.read` | 200 current revision and its body (`null` without one) | none |
| `GET /api/v1/projects/{project}/health?area=PATH` | — | `health.read` | 200 node (project level without `area`; `~unassigned` for streams outside the tree), breadcrumb, KPIs (roll-up of the subtree's distinct streams), own stream rows (latest regression vs its predecessor: readiness verdict, trend, counts of required slots and deltas, pass rate in percentage points, signature sets, runtime and CPU with comparability), one roll-up per child, `watermark`, `evaluated_at`, `valid_until`; 413 `E_TOO_LARGE` above the work budget (200 streams, 32,000 slots, 40,000 attempts, 80,000 report revisions, 60,000 diagnostic buckets, 10,000 build attempts, 200,000 slot-build pairs, 80,000 build references, 64,000 declared build requirements, 1,000,000 combined signature entries; the history counts the predecessor outside its window too); 503 after the 20 s deadline | none |
| `GET /api/v1/projects/{project}/health/growth?area=PATH&days=N` | — | `health.read` | 200 the node's test inventory per UTC day over the last N days (1 to 366, default 90; today included): `required_runs` and distinct required `tests` of every stream's latest sealed regression started by that day's end (a stream keeps its last value until its next regression; tests counted once across streams), and how many `streams` had one; `watermark`, `evaluated_at`; 413 `E_TOO_LARGE` above 20,000 regressions or 2,000,000 scanned slots (choose a shorter period or a lower node); 503 after the 20 s deadline | none |
| `GET /api/v1/projects/{project}/health/history?producer=&suite=&branch=repo/name&limit=N` | — | `health.read` | 200 the stream's last N (≤ 30) retained regressions, newest first, each against its predecessor (also one outside the window), with verdicts, trend and undecided signatures as of the read; `cadence_hours` and `home` of the stream; the latest row's `overdue`; `watermark`, `evaluated_at` and `valid_until` (the next exception expiry or overdue deadline): refetch when the watermark moves or `valid_until` passes | none |
| `POST /api/v1/session` | `{username, password}` | `session.login` | 204 + cookie + CSRF token | session row; throttled |
| `DELETE /api/v1/session` | — | `session.logout` | 204 | session deleted |

**Per-record ingest result** (one NDJSON line per non-empty input line, same order):
`{"line": n, "result": "committed" | "duplicate" | "rejected", "receipt"?: {...},
"status"?: 4xx, "error"?: {...}}`. A malformed line is rejected alone; a batch that is
not UTF-8, has more than 1,000 records, or exceeds the size limits is refused whole
(400 / 413, `committed: false`).

**Reads** name the project; when two producers of a project use the same regression
reference, `?producer=NAME` selects one (otherwise 400 naming `producer`). Slot rows are
`{slot_ref, test, required, state, detail?, note, deciding, attempts}`; `state` is
settled at query time from the retained facts (never stored), with eligibility and
barriers evaluated against the current pipeline and quarantine state.

**Feature mode**: for each test and configuration an item selects, the candidate is the
most recent regression of the branch containing such a slot by its reported start (ties by
regression ID), taken from a permanent candidate index: it stays the candidate when its
facts expire or are quarantined (never an older pass). A regression whose reported start
is more than 5 minutes after its receipt has uncertain time: it is ordered by receipt time
and cannot be fresh. Configuration selectors are simulator labels (vendor) or config
digests; every test glob, on every configuration selector, must match something, else the item
is missing. A regression with unknown receipt time (legacy, receipt expired) also has
uncertain time. Seeds count distinct passing seeds within the candidate. External evidence is
declared, not verified; it needs an attestation bound to the item revision and evidence
digest.

**Quarantined removals**: a slot removed by an amendment whose credential is quarantined
since before the removal is restored at read time (the expected set does not shrink) and
readiness is insufficient until the removal is re-made with a valid credential (before
`finish`) or the quarantine is released.

**Request bounds**: a body needs a `Content-Length` (it is reserved against the
in-flight budget before a byte is read, and held until the response); encoded body ≤ 8 MiB; `Content-Encoding: gzip` decoded ≤ 32 MiB and
≤ 20 × the encoded size; one record ≤ 1 MiB and nested ≤ 32 levels; at most 64 MiB of
request bodies in flight (beyond: 503 with `Retry-After`).

**Reports** must carry exactly their slot's declared execution inputs (else 409
`E_RETRY_INPUTS_DIFFER`); a report ID and an attempt reference belong to one attempt in one
slot for good (else 409); these bindings are permanent (they outlive receipts and
facts). A simulator pack the server cannot resolve exactly keeps the exit-code check on. A build report's `pass` counts only when its runner exited 0 and
its evidence is complete without a failing diagnostic and no failure count, failing verdict or excess counted failure
(otherwise it is stored as `error`);
a build proves only its own producer's requirements, under an accepted pipeline. Identical
records in flight are serialized: the second answers the first one's receipt. Reads use
one snapshot (both regressions of a comparison included).

**Sessions**: `POST /api/v1/session` needs the canonical `Origin`; it answers 204 with
`Set-Cookie: __Host-dviscope=…; HttpOnly; Secure; SameSite=Lax; Path=/` and the CSRF token
in `X-DVIScope-CSRF`. Sessions end after 8 h idle or 7 days. Logins are throttled
(5 attempts per account, 20 per client address, per 15 minutes; 429): every attempt is
counted atomically before its password is hashed (a success refunds it), so a concurrent
burst cannot pass together.

**Receipts** (`docs/journal.md`): `{identity, revision, digest, result, server_ids}`.
Record identities: `attempt_started:<attempt_ref>`, `simulation_attempt:<report_id>`
(+ `report_revision`), `build_started:<build_ref>`, `build_attempt:<build_ref>`
(+ `report_revision`), `regression:<ref>`, `manifest_chunk:<ref>/<n>`,
`manifest_seal:<ref>`, `manifest_amend:<ref>/<revision>`, `slot_mark:<ref>/<digest>`,
`finish:<ref>`.

**Revisions** (B.3, checked in this order): identical identity + revision + payload digest
→ the original receipt (`duplicate`), also after a newer revision; same revision, other
payload → 409 `E_REVISION_CONFLICT`; a revision below the head that was never seen → 409
`E_STALE_REVISION`; a replay older than the deduplication horizon → 410
`E_REPLAY_EXPIRED`.

## Manifest state table

States of a regression: **unsealed** (chunks accepted), **sealed** (slot count and digest
fixed; amendments and marks only), **finished** (no structural change; late reports
accepted). All operations are serialized on the regression head.

| Operation | unsealed | sealed | finished |
|---|---|---|---|
| chunk `n`, new | accepted | 409 `E_REVISION_CONFLICT` (sealed) | 409 |
| chunk `n`, identical replay | duplicate receipt | duplicate receipt | duplicate receipt |
| chunk `n`, different content | replaces chunk `n` (its slots), receipt | 409 | 409 |
| a slot ref declared in two chunks | 400 `E_INVALID` naming the slot | — | — |
| seal, count and digest match the chunks (contiguous 1..N) | sealed, receipt | duplicate (same digest) / 409 (other) | duplicate / 409 |
| seal, mismatch or a gap in chunk numbers | 400 `E_INVALID` (`slot_count` / `manifest_digest`) | — | — |
| amend revision N+1 (add / remove) | 409 (not sealed) | accepted; removing a slot that is running or has reports → 409 naming it | 409 |
| amend, identical replay | — | duplicate | duplicate |
| mark cancelled/skipped | 409 (not sealed) | accepted (a mark never overrides a terminal attempt) | accepted (late marks allowed) |
| finish | accepted (*observed results only*) | accepted | duplicate |
| attempt start / report for an undeclared slot | 400 `E_INVALID` (slot) | 400 | 400 |

The manifest digest is the SHA-256 (`sha256:<hex>`) of the canonical JSON array of the
live slots (each a `SlotDecl` as the server reads it, defaults included), sorted by
`slot_ref` (byte order). The first seal is manifest revision 1; an amendment carries the
next revision (a lower one is 409 `E_STALE_REVISION`, a gap 400). A slot's configuration
digest (comparison, B.1 `config_digest`) covers its test, its plusargs without seed-like
arguments (`+ntb_random_seed`, `-sv_seed`, `+seed`, `+UVM_VERBOSITY`), modes and the
digests of its build configurations — never the seed or the source identity, so the same
configuration on another revision compares with its baseline.
