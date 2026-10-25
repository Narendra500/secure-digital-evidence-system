package models

import "time"

type AuditEventMessage struct {
	UserID      int64     `json:"user_id"`
	CaseID      int64     `json:"case_id"`
	EvidenceID  int64     `json:"evidence_id"`
	ActionType  int32     `json:"action_type"`
	ActionName  string    `json:"action_name"`
	ServiceName string    `json:"service_name"`
	IPAddress   string    `json:"ip_address"`
	RequestID   string    `json:"request_id"`
	Status      string    `json:"status"`
	Details     string    `json:"details"`
	Timestamp   time.Time `json:"timestamp"`
}

type AuditLogRecord struct {
	UserID       int64     `json:"user_id"`
	CaseID       int64     `json:"case_id"`
	EvidenceID   int64     `json:"evidence_id"`
	ActionType   int32     `json:"action_type"`
	ActionName   string    `json:"action_name"`
	ServiceName  string    `json:"service_name"`
	IPAddress    string    `json:"ip_address"`
	RequestID    string    `json:"request_id"`
	PreviousHash string    `json:"previous_hash"`
	CurrentHash  string    `json:"current_hash"`
	Status       string    `json:"status"`
	Details      string    `json:"details"`
	CreatedAt    time.Time `json:"created_at"`
}

type AuditAnchor struct {
	EpochID             int64     `json:"epoch_id"`
	StartLogID          int64     `json:"start_log_id"`
	EndLogID            int64     `json:"end_log_id"`
	EventCount          int       `json:"event_count"`
	MerkleRoot          string    `json:"merkle_root"`
	ChainTip            string    `json:"chain_tip"`
	S3Key               string    `json:"s3_key"`
	RekorLogIndex       int64     `json:"rekor_log_index"`
	RekorEntryUUID      string    `json:"rekor_entry_uuid"`
	RekorIntegratedTime time.Time `json:"rekor_integrated_time"`
	CreatedAt           time.Time `json:"created_at"`
}

type BatchManifest struct {
	EpochID       int64            `json:"epoch_id"`
	EventCount    int              `json:"event_count"`
	MerkleRoot    string           `json:"merkle_root"`
	ChainTip      string           `json:"chain_tip"`
	RekorUUID     string           `json:"rekor_uuid,omitempty"`
	RekorLogIndex int64            `json:"rekor_log_index,omitempty"`
	Timestamp     time.Time        `json:"timestamp"`
	Events        []AuditLogRecord `json:"events"`
}
