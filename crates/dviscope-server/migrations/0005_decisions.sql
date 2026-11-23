-- Decisions (plan B.10): triage cases and exceptions are heads with immutable revisions;
-- history is append-only; every decision-affecting write advances the project's change
-- sequence in the same transaction (readiness watermark, B.11).

CREATE TABLE project_heads (
    project_id  BIGINT PRIMARY KEY REFERENCES projects (id),
    change_seq  BIGINT NOT NULL DEFAULT 0 CHECK (change_seq >= 0)
);
INSERT INTO project_heads (project_id) SELECT id FROM projects;

CREATE TABLE changes (
    project_id  BIGINT NOT NULL REFERENCES projects (id),
    seq         BIGINT NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind        TEXT NOT NULL,
    object      TEXT NOT NULL,
    PRIMARY KEY (project_id, seq)
);

CREATE TABLE triage_cases (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    id           BIGSERIAL,
    signature_id BIGINT NOT NULL,
    branch       TEXT NOT NULL,            -- repository-qualified: "repo/name"
    revision     INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, signature_id, branch),
    FOREIGN KEY (project_id, signature_id) REFERENCES signatures (project_id, id)
);

CREATE TABLE triage_revisions (
    project_id  BIGINT NOT NULL,
    case_id     BIGINT NOT NULL,
    revision    INTEGER NOT NULL CHECK (revision > 0),
    state       TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    owner       TEXT,
    notes       TEXT NOT NULL DEFAULT '' CHECK (octet_length(notes) <= 65536),
    bug_urls    TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(bug_urls) <= 20),
    author      BIGINT NOT NULL REFERENCES users (id),
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, case_id, revision),
    FOREIGN KEY (project_id, case_id) REFERENCES triage_cases (project_id, id)
);

CREATE TABLE exceptions (
    project_id    BIGINT NOT NULL REFERENCES projects (id),
    id            BIGSERIAL,
    signature_id  BIGINT NOT NULL,
    branch        TEXT NOT NULL,
    suite         TEXT NOT NULL,
    revision      INTEGER NOT NULL CHECK (revision > 0),
    reason        TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 4096),
    author        BIGINT NOT NULL REFERENCES users (id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    superseded_by BIGINT,
    PRIMARY KEY (project_id, id),
    CHECK (expires_at <= created_at + interval '180 days'),
    FOREIGN KEY (project_id, signature_id) REFERENCES signatures (project_id, id)
);
-- One unrevoked, unsuperseded exception per scope.
CREATE UNIQUE INDEX exceptions_one_live ON exceptions (project_id, signature_id, branch, suite)
    WHERE revoked_at IS NULL AND superseded_by IS NULL;

CREATE TABLE history (
    id          BIGSERIAL PRIMARY KEY,
    project_id  BIGINT NOT NULL REFERENCES projects (id),
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       BIGINT NOT NULL,
    object      TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE publication_receipts (
    project_id     BIGINT NOT NULL REFERENCES projects (id),
    digest         TEXT NOT NULL,
    summary        JSONB NOT NULL,
    published_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    monitor_until  TIMESTAMPTZ,
    retired_at     TIMESTAMPTZ,
    PRIMARY KEY (project_id, digest)
);
