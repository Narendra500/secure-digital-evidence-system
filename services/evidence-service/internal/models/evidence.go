package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Evidence struct {
	ID          int64     `db:"id"           json:"id"`
	PublicID    string    `db:"public_id"    json:"public_id"`
	CaseID      string    `db:"case_id"      json:"case_id"`
	FileName    string    `db:"file_name"    json:"file_name"`
	FileSize    int64     `db:"file_size"    json:"file_size"`
	StoragePath string    `db:"storage_path" json:"storage_path"`
	CurrentHash string    `db:"current_hash" json:"current_hash"`
	MimeType    string    `db:"mime_type"    json:"mime_type"`
	UploadedBy  string    `db:"uploaded_by"  json:"uploaded_by"`
	UploadedAt  time.Time `db:"uploaded_at"  json:"uploaded_at"`
	Status      string    `json:"status"`
}

type EvidenceManifestFile struct {
	EvidencePublicID string    `json:"evidence_public_id"`
	FileName         string    `json:"file_name"`
	Path             string    `json:"path"`
	FileSize         int64     `json:"file_size"`
	SHA256           string    `json:"sha256"`
	RecordedHash     string    `json:"recorded_hash"`
	Tampered         bool      `json:"tampered"`
	MimeType         string    `json:"mime_type,omitempty"`
	UploadedAt       time.Time `json:"uploaded_at"`
}

type EvidenceManifestCase struct {
	PublicID string `json:"public_id"`
	Title    string `json:"title,omitempty"`
}

type EvidenceManifestExportedBy struct {
	UserPublicID string `json:"user_public_id"`
}

type EvidenceManifest struct {
	System        string                     `json:"system"`
	Version       string                     `json:"version"`
	Case          EvidenceManifestCase       `json:"case"`
	ExportedAt    string                     `json:"exported_at"`
	ExportedBy    EvidenceManifestExportedBy `json:"exported_by"`
	HashAlgorithm string                     `json:"hash_algorithm"`
	LogsFile      string                     `json:"logs_file,omitempty"`
	FileCount     int                        `json:"file_count"`
	Files         []EvidenceManifestFile     `json:"files"`
}

type ExportAuditLog struct {
	PublicID         string         `json:"public_id"`
	EvidencePublicID string         `json:"evidence_public_id"`
	EvidenceName     string         `json:"evidence_name,omitempty"`
	CasePublicID     string         `json:"case_public_id,omitempty"`
	CaseTitle        string         `json:"case_title,omitempty"`
	UserPublicID     string         `json:"user_public_id,omitempty"`
	UserName         string         `json:"user_name,omitempty"`
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

type ExportCustodyLog struct {
	PublicID         string         `json:"public_id"`
	EvidencePublicID string         `json:"evidence_public_id"`
	EvidenceName     string         `json:"evidence_name,omitempty"`
	CasePublicID     string         `json:"case_public_id,omitempty"`
	CaseTitle        string         `json:"case_title,omitempty"`
	UserPublicID     string         `json:"user_public_id,omitempty"`
	UserName         string         `json:"user_name,omitempty"`
	Action           string         `json:"action"`
	ActionMetadata   map[string]any `json:"action_metadata,omitempty"`
	Remarks          string         `json:"remarks"`
	Timestamp        time.Time      `json:"timestamp"`
}

type EvidenceLogsItem struct {
	EvidencePublicID string             `json:"evidence_public_id"`
	FileName         string             `json:"file_name"`
	CurrentHash      string             `json:"current_hash"`
	AuditLogs        []ExportAuditLog   `json:"audit_logs"`
	CustodyLogs      []ExportCustodyLog `json:"custody_logs"`
}

type CaseLogsExport struct {
	System           string             `json:"system"`
	CasePublicID     string             `json:"case_public_id"`
	CaseTitle        string             `json:"case_title,omitempty"`
	ExportedAt       string             `json:"exported_at"`
	EvidenceCount    int                `json:"evidence_count"`
	TotalAuditLogs   int                `json:"total_audit_logs"`
	TotalCustodyLogs int                `json:"total_custody_logs"`
	Evidences        []EvidenceLogsItem `json:"evidences"`
	AllAuditLogs     []ExportAuditLog   `json:"all_audit_logs"`
	AllCustodyLogs   []ExportCustodyLog `json:"all_custody_logs"`
}

type EvidenceStatus struct {
	EvidenceID  int64  `json:"evidence_id"`
	Status      string `json:"status"`
	CurrentHash string `json:"current_hash"`
}

type EvidenceVersion struct {
	ID          int64     `db:"id"            json:"id"`
	EvidenceID  int64     `db:"evidence_id"   json:"evidence_id"`
	S3VersionID string    `db:"s3_version_id" json:"s3_version_id"`
	FileHash    string    `db:"file_hash"     json:"file_hash"`
	FileSize    int64     `db:"file_size"     json:"file_size"`
	IsCurrent   bool      `db:"is_current"    json:"is_current"`
	CreatedBy   int64     `db:"created_by"    json:"created_by"`
	CreatedAt   time.Time `db:"created_at"    json:"created_at"`
}

type Claims struct {
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}
