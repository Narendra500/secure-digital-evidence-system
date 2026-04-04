CREATE TABLE IF NOT EXISTS integrity_schema.custody_logs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  public_id UUID UNIQUE DEFAULT GEN_RANDOM_UUID(),
  evidence_id BIGINT NOT NULL,
  case_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  action_type INT REFERENCES integrity_schema.actions(id) NOT NULL,
  action_metadata JSONB NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  remarks TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custody_logs_evidence_id ON integrity_schema.custody_logs (evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_logs_timestamp ON integrity_schema.custody_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_custody_logs_evidence_time ON integrity_schema.custody_logs (timestamp DESC, evidence_id);
