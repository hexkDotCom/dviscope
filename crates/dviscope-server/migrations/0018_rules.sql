-- Project rules and activation (plan B.9.4): pipeline definitions, the project's active
-- pipeline and activation sample, sample files (uploaded in chunks, resumable by digest),
-- and the activation history. Private site data: never exported, never in logs.

CREATE TABLE pipeline_definitions (
    project_id  BIGINT NOT NULL REFERENCES projects (id),
    digest      TEXT NOT NULL,
    -- {"format": "dviscope.pipeline/1", "default_packs": bool, "packs": [{"name", "text"}]}
    definition  JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, digest)
);

CREATE TABLE project_rules (
    project_id       BIGINT PRIMARY KEY REFERENCES projects (id),
    -- The pipeline a new activation is checked against (none: the shipped default).
    active_pipeline  TEXT,
    -- The current activation sample (none: activation is blocked).
    sample_digest    TEXT,
    changed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sample_files (
    project_id  BIGINT NOT NULL REFERENCES projects (id),
    sha256      TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size        BIGINT NOT NULL CHECK (size >= 0 AND size <= 67108864),
    content     BYTEA NOT NULL DEFAULT ''::bytea,
    complete    BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, sha256)
);

CREATE TABLE activation_samples (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    digest       TEXT NOT NULL,
    manifest     JSONB NOT NULL,
    uploaded_by  BIGINT NOT NULL,
    uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, digest)
);

CREATE TABLE activations (
    project_id     BIGINT NOT NULL REFERENCES projects (id),
    id             BIGSERIAL,
    old_pipeline   TEXT NOT NULL,
    new_pipeline   TEXT NOT NULL,
    sample_digest  TEXT NOT NULL,
    result         JSONB NOT NULL,
    actor_user     BIGINT NOT NULL,
    activated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, id)
);
