-- DVIScope schema, Stage 3 (plan B.14). Forward-only; applied under an advisory lock with
-- checksums. Every table carries project_id; composite keys and foreign keys keep children
-- in their project.

CREATE TABLE projects (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    policy      TEXT NOT NULL DEFAULT 'strict' CHECK (policy IN ('strict', 'retry-pass-accepted')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE producers (
    project_id  BIGINT NOT NULL REFERENCES projects (id),
    id          BIGSERIAL,
    name        TEXT NOT NULL,
    PRIMARY KEY (project_id, id),
    UNIQUE (id),
    UNIQUE (project_id, name)
);

CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 64),
    disabled    BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE local_credentials (
    user_id     BIGINT PRIMARY KEY REFERENCES users (id),
    phc         TEXT NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    project_id  BIGINT NOT NULL REFERENCES projects (id),
    user_id     BIGINT NOT NULL REFERENCES users (id),
    role        TEXT NOT NULL CHECK (role IN ('viewer', 'triager', 'admin')),
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE sessions (
    id_hash       BYTEA PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users (id),
    csrf          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE api_tokens (
    id                 BIGSERIAL PRIMARY KEY,
    hash               BYTEA NOT NULL UNIQUE,
    kind               TEXT NOT NULL CHECK (kind IN ('collector', 'personal')),
    project_id         BIGINT REFERENCES projects (id),
    producer_id        BIGINT REFERENCES producers (id),
    user_id            BIGINT REFERENCES users (id),
    scopes             TEXT[] NOT NULL DEFAULT '{}',
    label              TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    quarantined_since  TIMESTAMPTZ,
    CHECK ((kind = 'collector' AND project_id IS NOT NULL AND producer_id IS NOT NULL AND user_id IS NULL)
        OR (kind = 'personal' AND user_id IS NOT NULL AND producer_id IS NULL))
);

CREATE TABLE bootstrap_tokens (
    hash         BYTEA PRIMARY KEY,
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ
);

CREATE TABLE login_throttle (
    key           TEXT PRIMARY KEY,
    failures      INTEGER NOT NULL CHECK (failures >= 0),
    window_start  TIMESTAMPTZ NOT NULL
);

CREATE TABLE pipelines (
    project_id  BIGINT NOT NULL REFERENCES projects (id),
    digest      TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('accepted', 'withdrawn')),
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, digest)
);

CREATE TABLE source_manifests (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    id           BIGSERIAL,
    producer_id  BIGINT NOT NULL,
    ref          TEXT NOT NULL,
    digest       TEXT NOT NULL,
    body         JSONB NOT NULL,
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, producer_id, ref),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);

CREATE TABLE regressions (
    project_id           BIGINT NOT NULL REFERENCES projects (id),
    id                   BIGSERIAL,
    producer_id          BIGINT NOT NULL,
    ref                  TEXT NOT NULL,
    digest               TEXT NOT NULL,
    body                 JSONB NOT NULL,
    suite                TEXT NOT NULL,
    branch_repository    TEXT NOT NULL,
    branch_name          TEXT NOT NULL,
    source_manifest_ref  TEXT NOT NULL,
    started_at           TIMESTAMPTZ NOT NULL,
    state                TEXT NOT NULL DEFAULT 'unsealed' CHECK (state IN ('unsealed', 'sealed', 'finished')),
    sealed               BOOLEAN NOT NULL DEFAULT false,
    manifest_revision    INTEGER NOT NULL DEFAULT 0 CHECK (manifest_revision >= 0),
    manifest_digest      TEXT,
    finished_at          TIMESTAMPTZ,
    change_seq           BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, producer_id, ref),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);
CREATE INDEX regressions_list ON regressions (project_id, branch_repository, branch_name, suite, started_at DESC, id DESC);

CREATE TABLE manifest_chunks (
    project_id     BIGINT NOT NULL,
    regression_id  BIGINT NOT NULL,
    n              INTEGER NOT NULL CHECK (n > 0),
    digest         TEXT NOT NULL,
    credential_id  BIGINT NOT NULL,
    PRIMARY KEY (project_id, regression_id, n),
    FOREIGN KEY (project_id, regression_id) REFERENCES regressions (project_id, id)
);

CREATE TABLE slots (
    project_id         BIGINT NOT NULL,
    id                 BIGSERIAL,
    regression_id      BIGINT NOT NULL,
    slot_ref           TEXT NOT NULL,
    chunk_n            INTEGER,
    added_revision     INTEGER NOT NULL DEFAULT 0,
    removed_revision   INTEGER,
    required           BOOLEAN NOT NULL,
    test               TEXT NOT NULL,
    exec_digest        TEXT NOT NULL,
    config_digest      TEXT NOT NULL,
    build_reqs         JSONB NOT NULL DEFAULT '[]',
    expected           JSONB,
    decl               JSONB NOT NULL,
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, regression_id, slot_ref),
    FOREIGN KEY (project_id, regression_id) REFERENCES regressions (project_id, id)
);

CREATE TABLE slot_marks (
    project_id     BIGINT NOT NULL,
    slot_id        BIGINT NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('cancelled', 'skipped')),
    reason         TEXT NOT NULL,
    credential_id  BIGINT NOT NULL,
    marked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, slot_id),
    FOREIGN KEY (project_id, slot_id) REFERENCES slots (project_id, id)
);

CREATE TABLE build_attempts (
    project_id     BIGINT NOT NULL REFERENCES projects (id),
    id             BIGSERIAL,
    producer_id    BIGINT NOT NULL,
    build_ref      TEXT NOT NULL,
    build_req      TEXT NOT NULL,
    build_order    BIGINT NOT NULL CHECK (build_order > 0),
    started_at     TIMESTAMPTZ NOT NULL,
    head_revision  INTEGER,
    credential_id  BIGINT,
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, producer_id, build_ref),
    UNIQUE (project_id, build_req, build_order),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);

CREATE TABLE build_facts (
    project_id       BIGINT NOT NULL,
    build_attempt_id BIGINT NOT NULL,
    report_revision  INTEGER NOT NULL CHECK (report_revision > 0),
    report_digest    TEXT NOT NULL,
    outcome          TEXT NOT NULL CHECK (outcome IN ('pass', 'fail', 'error')),
    phase_reached    TEXT NOT NULL,
    purpose          TEXT NOT NULL CHECK (purpose IN ('production', 'experiment')),
    credential_id    BIGINT NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, build_attempt_id, report_revision),
    FOREIGN KEY (project_id, build_attempt_id) REFERENCES build_attempts (project_id, id)
);

CREATE TABLE attempts (
    project_id     BIGINT NOT NULL,
    id             BIGSERIAL,
    slot_id        BIGINT NOT NULL,
    attempt_ref    TEXT NOT NULL,
    attempt_seq    INTEGER NOT NULL CHECK (attempt_seq > 0),
    build_refs     JSONB NOT NULL DEFAULT '[]',
    started_at     TIMESTAMPTZ NOT NULL,
    start_credential_id BIGINT,
    head_revision  INTEGER,
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, slot_id, attempt_seq),
    UNIQUE (project_id, slot_id, attempt_ref),
    FOREIGN KEY (project_id, slot_id) REFERENCES slots (project_id, id)
);

CREATE TABLE attempt_facts (
    project_id       BIGINT NOT NULL,
    attempt_id       BIGINT NOT NULL,
    report_revision  INTEGER NOT NULL CHECK (report_revision > 0),
    report_digest    TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    blocking_phase   TEXT,
    effective        TEXT NOT NULL,
    assessment       TEXT NOT NULL,
    completion       TEXT NOT NULL,
    termination      TEXT NOT NULL,
    design_loaded    TEXT NOT NULL,
    pipeline_digest  TEXT NOT NULL,
    pipeline_status  TEXT NOT NULL CHECK (pipeline_status IN ('accepted', 'withdrawn', 'unknown')),
    purpose          TEXT NOT NULL CHECK (purpose IN ('production', 'experiment')),
    source_matches   BOOLEAN NOT NULL,
    build_refs       JSONB NOT NULL DEFAULT '[]',
    simulator        TEXT NOT NULL DEFAULT '',
    contradiction    BOOLEAN NOT NULL,
    primary_diag     TEXT,
    credential_id    BIGINT NOT NULL,
    producer_id      BIGINT NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, attempt_id, report_revision),
    FOREIGN KEY (project_id, attempt_id) REFERENCES attempts (project_id, id)
);

-- Payloads (expire earlier than the facts).
CREATE TABLE attempt_reports (
    project_id       BIGINT NOT NULL,
    attempt_id       BIGINT NOT NULL,
    report_revision  INTEGER NOT NULL,
    payload          JSONB NOT NULL,
    PRIMARY KEY (project_id, attempt_id, report_revision),
    FOREIGN KEY (project_id, attempt_id, report_revision) REFERENCES attempt_facts (project_id, attempt_id, report_revision)
);

CREATE SEQUENCE signature_numbers;

CREATE TABLE signatures (
    project_id        BIGINT NOT NULL REFERENCES projects (id),
    id                BIGSERIAL,
    number            BIGINT NOT NULL DEFAULT nextval('signature_numbers') CHECK (number > 0),
    fingerprint       TEXT NOT NULL,
    family_kind       TEXT NOT NULL,
    diag_id           TEXT NOT NULL,
    identity_template TEXT NOT NULL,
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, fingerprint),
    UNIQUE (project_id, number)
);

CREATE TABLE buckets (
    project_id         BIGINT NOT NULL,
    attempt_id         BIGINT NOT NULL,
    report_revision    INTEGER NOT NULL,
    idx                INTEGER NOT NULL CHECK (idx >= 0),
    diag_id            TEXT NOT NULL,
    site               TEXT,
    observed_severity  TEXT NOT NULL,
    effective_severity TEXT NOT NULL,
    framework          TEXT NOT NULL,
    provenance         TEXT NOT NULL CHECK (provenance IN ('observed', 'synthetic')),
    fails_run          BOOLEAN NOT NULL,
    count              NUMERIC(39, 0) NOT NULL CHECK (count >= 0),
    signature_id       BIGINT NOT NULL,
    PRIMARY KEY (project_id, attempt_id, report_revision, idx),
    FOREIGN KEY (project_id, attempt_id, report_revision) REFERENCES attempt_facts (project_id, attempt_id, report_revision),
    FOREIGN KEY (project_id, signature_id) REFERENCES signatures (project_id, id)
);
CREATE INDEX buckets_signature ON buckets (project_id, signature_id);

-- Idempotency: one receipt per record identity and revision.
CREATE TABLE receipts (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    producer_id  BIGINT NOT NULL,
    identity     TEXT NOT NULL,
    revision     INTEGER NOT NULL CHECK (revision > 0),
    digest       TEXT NOT NULL,
    receipt      JSONB NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, producer_id, identity, revision),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);

CREATE TABLE audit (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    object      TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}'
);
