CREATE TABLE IF NOT EXISTS integrity_schema.audit_anchors (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    epoch_id BIGINT NOT NULL UNIQUE,
    start_log_id BIGINT NOT NULL,
    end_log_id BIGINT NOT NULL,
    event_count INT NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    chain_tip VARCHAR(64) NOT NULL,
    s3_key VARCHAR(255) NOT NULL,
    rekor_log_index BIGINT,
    rekor_entry_uuid VARCHAR(128) NOT NULL,
    rekor_integrated_time TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_anchors_epoch ON integrity_schema.audit_anchors(epoch_id);
CREATE INDEX IF NOT EXISTS idx_audit_anchors_created_at ON integrity_schema.audit_anchors(created_at);
