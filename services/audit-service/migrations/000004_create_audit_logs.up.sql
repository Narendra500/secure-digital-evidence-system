CREATE TABLE IF NOT EXISTS integrity_schema.audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID DEFAULT gen_random_uuid(),

    user_id BIGINT NOT NULL,
    case_id BIGINT NOT NULL,
    evidence_id BIGINT NOT NULL,
    request_id uuid unique NOT NULL,

    previous_hash varchar(128),
    current_hash varchar(128) NOT NULL,

    action_type int REFERENCES integrity_schema.actions(id) NOT NULL,
    service_name VARCHAR(60) NOT NULL,
    ip_address INET NOT NULL,
    status integrity_schema.integrity_status NOT NULL,

    details JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_evidence_id ON integrity_schema.audit_logs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_type ON integrity_schema.audit_logs(action_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON integrity_schema.audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_evidence_time ON integrity_schema.audit_logs(evidence_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON integrity_schema.audit_logs(user_id);
