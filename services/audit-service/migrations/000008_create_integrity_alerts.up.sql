ALTER TYPE integrity_schema.integrity_status ADD VALUE IF NOT EXISTS 'restored';

INSERT INTO integrity_schema.actions (name, description) 
VALUES ('RESTORE', 'Restored audit log from immutable S3 batch manifest')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS integrity_schema.integrity_alerts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID UNIQUE DEFAULT gen_random_uuid(),
    scope VARCHAR(30) NOT NULL,
    target_id VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    tampered_count INT NOT NULL DEFAULT 0,
    restored_count INT NOT NULL DEFAULT 0,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_integrity_alerts_scope ON integrity_schema.integrity_alerts(scope, target_id);
CREATE INDEX IF NOT EXISTS idx_integrity_alerts_created_at ON integrity_schema.integrity_alerts(created_at DESC);
