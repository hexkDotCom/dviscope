-- Build reports keep the pipeline of their evidence: a build classified under a pipeline
-- the project does not accept (or withdrew) proves nothing (Stage 3 review, finding 5).
ALTER TABLE build_facts ADD COLUMN pipeline_digest TEXT NOT NULL DEFAULT '';

-- Expired build identities (retention): a later record of one is 410, never a new build.
CREATE TABLE expired_builds (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    producer_id  BIGINT NOT NULL,
    build_ref    TEXT NOT NULL,
    expired_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, producer_id, build_ref),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);
