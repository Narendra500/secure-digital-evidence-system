package store

import (
	"crypto/sha256"
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

// GenerateRequestID generates a deterministic UUIDv5-style identifier for idempotent request tracking.
func GenerateRequestID(evidenceID int64, fileHash string, actionID int32, userID int64, caseID int64) string {
	data := fmt.Sprintf("%d:%s:%d:%d:%d", evidenceID, fileHash, actionID, userID, caseID)
	hash := sha256.Sum256([]byte(data))
	// Set RFC 4122 version 5 (bits 4-7 = 0101) and variant (bits 6-7 = 10)
	hash[6] = (hash[6] & 0x0f) | 0x50
	hash[8] = (hash[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%012x",
		hash[0:4], hash[4:6], hash[6:8], hash[8], hash[9], hash[10:16])
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
