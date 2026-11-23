-- Regression health (dashboard): runner metrics retained beside the attempt facts (own
-- table, so a server writes them only once this migration ran), so runtime and CPU survive
-- payload expiry. A missing row or NULL = not measured or reported before this migration
-- (unknown, never zero). Removed with its fact revision.

CREATE TABLE attempt_metrics (
    project_id       BIGINT NOT NULL,
    attempt_id       BIGINT NOT NULL,
    report_revision  INTEGER NOT NULL,
    wall_s           NUMERIC CHECK (wall_s >= 0),
    cpu_s            NUMERIC CHECK (cpu_s >= 0),
    cpu_scope        TEXT CHECK (cpu_scope IN ('process', 'process_and_waited_children', 'job')),
    run_finished_at  TIMESTAMPTZ,
    PRIMARY KEY (project_id, attempt_id, report_revision),
    FOREIGN KEY (project_id, attempt_id, report_revision)
        REFERENCES attempt_facts (project_id, attempt_id, report_revision) ON DELETE CASCADE
);

-- Hierarchy of the project (SoC → subsystems → blocks, any depth), versioned: each import
-- that changes the tree is a new revision; the current tree is the highest revision.
CREATE TABLE area_trees (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    revision     INTEGER NOT NULL CHECK (revision > 0),
    digest       TEXT NOT NULL,
    body         JSONB NOT NULL,
    imported_by  TEXT NOT NULL,
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, revision)
);

CREATE TABLE areas (
    project_id   BIGINT NOT NULL,
    revision     INTEGER NOT NULL,
    path         TEXT NOT NULL,
    parent_path  TEXT,
    title        TEXT NOT NULL,
    ord          INTEGER NOT NULL,
    PRIMARY KEY (project_id, revision, path),
    FOREIGN KEY (project_id, revision) REFERENCES area_trees (project_id, revision),
    FOREIGN KEY (project_id, revision, parent_path) REFERENCES areas (project_id, revision, path)
);

-- A stream (producer × suite × repository-qualified branch) attached to a node: exactly one
-- home per revision (import validation; at most one by the index), any number of links.
CREATE TABLE area_streams (
    project_id         BIGINT NOT NULL,
    revision           INTEGER NOT NULL,
    path               TEXT NOT NULL,
    producer_id        BIGINT NOT NULL,
    suite              TEXT NOT NULL,
    branch_repository  TEXT NOT NULL,
    branch_name        TEXT NOT NULL,
    home               BOOLEAN NOT NULL,
    cadence_hours      INTEGER CHECK (cadence_hours > 0),
    CHECK (home OR cadence_hours IS NULL),
    PRIMARY KEY (project_id, revision, path, producer_id, suite, branch_repository, branch_name),
    FOREIGN KEY (project_id, revision, path) REFERENCES areas (project_id, revision, path),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);
CREATE UNIQUE INDEX area_streams_one_home ON area_streams
    (project_id, revision, producer_id, suite, branch_repository, branch_name) WHERE home;
