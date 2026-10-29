package store

import (
	"crypto/rand"
	"fmt"
	"time"
)

type EvidenceDetails struct {
	EvidenceID       int64
	EvidencePublicID string
	Algorithm        string
	FileHash         string
}

type EvidenceHash struct {
	EvidenceID       int64
	EvidencePublicID string
	FileHash         string
	Algorithm        string
}

type EvidenceStatus struct {
	EvidenceID  int64  `json:"evidence_id" db:"evidence_id"`
	Status      string `json:"status" db:"status"`
	CurrentHash string `json:"current_hash" db:"current_hash"`
}

type EvidenceRegistrationDetails struct {
	EvidenceID       int64  `json:"evidence_id" binding:"required"`
	EvidencePublicID string `json:"evidence_public_id" binding:"required"`
	Algorithm        string `json:"algorithm" binding:"required"`
	FileHash         string `json:"file_hash" binding:"required"`
	CaseID           int64  `json:"case_id" binding:"required"`
	UserID           int64  `json:"user_id" binding:"required"`
	Action           string `json:"action" binding:"required"`
	Remarks          string `json:"remarks" binding:"required"`
	// jsonb data
	ActionMetadata string `json:"action_metadata" binding:"required"`
	ServiceName    string `json:"service_name" binding:"required"`
	IPAddress      string `json:"ip_address" binding:"required"`
}

type CustodyLog struct {
	EvidenceID int64
	CaseID     int64
	UserID     int64
	ActionType int32
	Remarks    string
	// jsonb data
	ActionMetadata string
}

type CustodyLogDTO struct {
	PublicID         string         `json:"public_id"`
	EvidencePublicID string         `json:"evidence_public_id"`
	EvidenceName     string         `json:"evidence_name,omitempty"`
	CasePublicID     string         `json:"case_public_id,omitempty"`
	CaseTitle        string         `json:"case_title,omitempty"`
	UserPublicID     string         `json:"user_public_id,omitempty"`
	UserName         string         `json:"user_name,omitempty"`
	EvidenceID       int64          `json:"-"`
	CaseID           int64          `json:"-"`
	UserID           int64          `json:"-"`
	Action           string         `json:"action"`
	ActionMetadata   map[string]any `json:"action_metadata"`
	Remarks          string         `json:"remarks"`
	Timestamp        time.Time      `json:"timestamp"`
}

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

type AuditLog struct {
	UserID      int64
	CaseID      int64
	EvidenceId  int64
	ActionType  int32
	ServiceName string
	IPAddress   string
	RequestID   string
	Status      string
	Details     string
}

type VerifiableAuditLog struct {
	ID               int64     `json:"id"`
	PublicID         string    `json:"public_id"`
	EvidenceID       int64     `json:"evidence_id"`
	EvidencePublicID string    `json:"evidence_public_id"`
	CaseID           int64     `json:"case_id"`
	UserID           int64     `json:"user_id"`
	ActionType       int32     `json:"action_type"`
	ActionName       string    `json:"action_name"`
	ServiceName      string    `json:"service_name"`
	IPAddress        string    `json:"ip_address"`
	RequestID        string    `json:"request_id"`
	PreviousHash     string    `json:"previous_hash"`
	CurrentHash      string    `json:"current_hash"`
	Status           string    `json:"status"`
	Details          string    `json:"details"`
	CreatedAt        time.Time `json:"created_at"`
}

type AuditLogDTO struct {
	PublicID         string         `json:"public_id"`
	EvidencePublicID string         `json:"evidence_public_id"`
	EvidenceName     string         `json:"evidence_name,omitempty"`
	CasePublicID     string         `json:"case_public_id,omitempty"`
	CaseTitle        string         `json:"case_title,omitempty"`
	UserPublicID     string         `json:"user_public_id,omitempty"`
	UserName         string         `json:"user_name,omitempty"`
	EvidenceID       int64          `json:"-"`
	CaseID           int64          `json:"-"`
	UserID           int64          `json:"-"`
	RequestID        string         `json:"request_id"`
	PreviousHash     string         `json:"previous_hash"`
	CurrentHash      string         `json:"current_hash"`
	Action           string         `json:"action"`
	ServiceName      string         `json:"service_name"`
	IPAddress        string         `json:"ip_address"`
	Status           string         `json:"status"`
	Details          map[string]any `json:"details,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
}

// GenerateRequestID generates a UUIDv4 identifier for request tracking.
func GenerateRequestID(args ...any) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // RFC 4122 version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%012x",
		b[0:4], b[4:6], b[6:8], b[8], b[9], b[10:16])
}

func (d *EvidenceRegistrationDetails) ToCustodyLog(actionID int32) CustodyLog {
	return CustodyLog{
		EvidenceID: d.EvidenceID,
		CaseID:     d.CaseID,
		UserID:     d.UserID,
		ActionType: actionID,
		Remarks:    d.Remarks,
		// jsonb data
		ActionMetadata: d.ActionMetadata,
	}
}

func (d *EvidenceRegistrationDetails) ToAuditLog(actionID int32) AuditLog {
	requestID := GenerateRequestID(d.EvidenceID, d.FileHash, actionID, d.UserID, d.CaseID)
	return AuditLog{
		UserID:      d.UserID,
		CaseID:      d.CaseID,
		EvidenceId:  d.EvidenceID,
		ActionType:  actionID,
		ServiceName: d.ServiceName,
		IPAddress:   d.IPAddress,
		RequestID:   requestID,
	}
}

func (d *EvidenceRegistrationDetails) ToAuditEventMessage(actionID int32) AuditEventMessage {
	requestID := GenerateRequestID(d.EvidenceID, d.FileHash, actionID, d.UserID, d.CaseID)
	return AuditEventMessage{
		UserID:      d.UserID,
		CaseID:      d.CaseID,
		EvidenceID:  d.EvidenceID,
		ActionType:  actionID,
		ActionName:  d.Action,
		ServiceName: d.ServiceName,
		IPAddress:   d.IPAddress,
		RequestID:   requestID,
		Status:      "unchanged",
		Details:     d.ActionMetadata,
		Timestamp:   time.Now().UTC(),
	}
}

func (d *EvidenceRegistrationDetails) ToEvidenceDetails() EvidenceDetails {
	return EvidenceDetails{
		EvidenceID:       d.EvidenceID,
		EvidencePublicID: d.EvidencePublicID,
		Algorithm:        d.Algorithm,
		FileHash:         d.FileHash,
	}
}

type BatchAuditLogRecord struct {
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

type BatchManifest struct {
	EpochID       int64                 `json:"epoch_id"`
	EventCount    int                   `json:"event_count"`
	MerkleRoot    string                `json:"merkle_root"`
	ChainTip      string                `json:"chain_tip"`
	RekorUUID     string                `json:"rekor_uuid,omitempty"`
	RekorLogIndex int64                 `json:"rekor_log_index,omitempty"`
	Timestamp     time.Time             `json:"timestamp"`
	Events        []BatchAuditLogRecord `json:"events"`
}

type IntegrityAlert struct {
	ID            int64          `json:"-" db:"id"`
	PublicID      string         `json:"public_id" db:"public_id"`
	Scope         string         `json:"scope" db:"scope"`
	TargetID      string         `json:"target_id" db:"target_id"`
	Status        string         `json:"status" db:"status"`
	TamperedCount int            `json:"tampered_count" db:"tampered_count"`
	RestoredCount int            `json:"restored_count" db:"restored_count"`
	Details       map[string]any `json:"details" db:"details"`
	CreatedAt     time.Time      `json:"created_at" db:"created_at"`
}

type LogVerificationIssue struct {
	EvidenceID       int64  `json:"evidence_id"`
	EvidencePublicID string `json:"evidence_public_id"`
	LogID            int64  `json:"log_id,omitempty"`
	RequestID        string `json:"request_id"`
	IssueType        string `json:"issue_type"` // HASH_MISMATCH, CHAIN_BROKEN, S3_MANIFEST_DISCREPANCY, MISSING_ROW
	ExpectedHash     string `json:"expected_hash,omitempty"`
	ActualHash       string `json:"actual_hash,omitempty"`
	Message          string `json:"message"`
	Restored         bool   `json:"restored"`
}

type LogVerificationResult struct {
	VerifiedAt       time.Time              `json:"verified_at"`
	Scope            string                 `json:"scope"`
	TargetID         string                 `json:"target_id"`
	Status           string                 `json:"status"` // VALID, TAMPER_DETECTED, TAMPERED_AND_RESTORED
	Modified         bool                   `json:"modified"`
	Restored         bool                   `json:"restored"`
	EvidencesChecked int                    `json:"evidences_checked"`
	LogsChecked      int                    `json:"logs_checked"`
	TamperedCount    int                    `json:"tampered_count"`
	RestoredCount    int                    `json:"restored_count"`
	Issues           []LogVerificationIssue `json:"issues"`
	Alert            *IntegrityAlert        `json:"alert,omitempty"`
	Message          string                 `json:"message"`
}
