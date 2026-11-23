-- Permanent identity bindings (Stage 3 review r2): an attempt reference names one slot of
-- one regression, and a report ID one attempt, for good. Claimed atomically by the unique
-- keys; never removed by retention (they outlive receipts and facts).
CREATE TABLE attempt_bindings (
    project_id      BIGINT NOT NULL REFERENCES projects (id),
    producer_id     BIGINT NOT NULL,
    attempt_ref     TEXT NOT NULL,
    regression_ref  TEXT NOT NULL,
    slot_ref        TEXT NOT NULL,
    PRIMARY KEY (project_id, producer_id, attempt_ref),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);

CREATE TABLE report_bindings (
    project_id   BIGINT NOT NULL REFERENCES projects (id),
    producer_id  BIGINT NOT NULL,
    report_id    TEXT NOT NULL,
    attempt_ref  TEXT NOT NULL,
    PRIMARY KEY (project_id, producer_id, report_id),
    FOREIGN KEY (project_id, producer_id) REFERENCES producers (project_id, id)
);
