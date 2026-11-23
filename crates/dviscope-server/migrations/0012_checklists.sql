-- Feature mode (plan B.11, B.12, B.16): regression receipt times (for time trust), the
-- permanent candidate index, and checklists with immutable versions, item revisions and
-- attestations.

-- When the server first received each regression; older rows take their reported start
-- (they are never flagged as skewed).
ALTER TABLE regressions ADD COLUMN received_at TIMESTAMPTZ;
UPDATE regressions SET received_at = started_at;
ALTER TABLE regressions ALTER COLUMN received_at SET DEFAULT now();
ALTER TABLE regressions ALTER COLUMN received_at SET NOT NULL;

-- One row per regression × test × configuration, kept when the regression's facts expire
-- or are deleted, so feature selection never falls back to an older regression.
CREATE TABLE candidate_index (
    project_id     BIGINT NOT NULL REFERENCES projects (id),
    branch         TEXT NOT NULL,               -- repository-qualified: "repo/name"
    test           TEXT NOT NULL,
    config_digest  TEXT NOT NULL,
    simulator      TEXT NOT NULL DEFAULT '',
    regression_id  BIGINT NOT NULL,             -- no foreign key: outlives the regression
    regression_ref TEXT NOT NULL,
    producer_id    BIGINT NOT NULL,
    started_at     TIMESTAMPTZ NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL,
    state          TEXT NOT NULL DEFAULT 'live' CHECK (state IN ('live', 'expired', 'deleted')),
    PRIMARY KEY (project_id, regression_id, test, config_digest)
);
CREATE INDEX candidate_index_branch ON candidate_index (project_id, branch, test);

INSERT INTO candidate_index (project_id, branch, test, config_digest, simulator, regression_id,
                             regression_ref, producer_id, started_at, received_at)
SELECT DISTINCT ON (s.project_id, s.regression_id, s.test, s.config_digest)
       s.project_id, r.branch_repository || '/' || r.branch_name, s.test, s.config_digest,
       coalesce(s.decl #>> '{build_reqs,0,build_config,simulator,vendor}', ''), r.id, r.ref,
       r.producer_id, r.started_at, r.received_at
  FROM slots s JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
 ORDER BY s.project_id, s.regression_id, s.test, s.config_digest, s.id
ON CONFLICT DO NOTHING;

CREATE TABLE checklists (
    project_id    BIGINT NOT NULL REFERENCES projects (id),
    id            BIGSERIAL,
    checklist_id  TEXT NOT NULL CHECK (length(checklist_id) BETWEEN 1 AND 128),
    PRIMARY KEY (project_id, id),
    UNIQUE (project_id, checklist_id)
);

-- Immutable versions.
CREATE TABLE checklist_versions (
    project_id    BIGINT NOT NULL,
    checklist     BIGINT NOT NULL,
    version       TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    digest        TEXT NOT NULL,
    body          JSONB NOT NULL,
    imported_by   BIGINT NOT NULL REFERENCES users (id),
    imported_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, checklist, version),
    FOREIGN KEY (project_id, checklist) REFERENCES checklists (project_id, id)
);

-- Item revisions: a new revision when `requires` or the evidence digests change.
CREATE TABLE checklist_items (
    project_id      BIGINT NOT NULL,
    checklist       BIGINT NOT NULL,
    item_id         TEXT NOT NULL CHECK (length(item_id) BETWEEN 1 AND 128),
    revision        INTEGER NOT NULL CHECK (revision > 0),
    content_digest  TEXT NOT NULL,
    evidence_digest TEXT,
    PRIMARY KEY (project_id, checklist, item_id, revision),
    FOREIGN KEY (project_id, checklist) REFERENCES checklists (project_id, id)
);

-- Which item revisions a version holds (with the item as written in that version).
CREATE TABLE checklist_version_items (
    project_id   BIGINT NOT NULL,
    checklist    BIGINT NOT NULL,
    version      TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    revision     INTEGER NOT NULL,
    position     INTEGER NOT NULL,
    item         JSONB NOT NULL,
    PRIMARY KEY (project_id, checklist, version, item_id),
    FOREIGN KEY (project_id, checklist, version)
        REFERENCES checklist_versions (project_id, checklist, version),
    FOREIGN KEY (project_id, checklist, item_id, revision)
        REFERENCES checklist_items (project_id, checklist, item_id, revision)
);

-- Attestations (project admin), bound to (version, item revision, evidence digest).
CREATE TABLE attestations (
    project_id      BIGINT NOT NULL,
    id              BIGSERIAL,
    checklist       BIGINT NOT NULL,
    version         TEXT NOT NULL,
    item_id         TEXT NOT NULL,
    item_revision   INTEGER NOT NULL,
    evidence_digest TEXT NOT NULL,
    author          BIGINT NOT NULL REFERENCES users (id),
    at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    PRIMARY KEY (project_id, id),
    FOREIGN KEY (project_id, checklist, item_id, item_revision)
        REFERENCES checklist_items (project_id, checklist, item_id, revision)
);
