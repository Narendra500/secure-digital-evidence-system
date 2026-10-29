package repository

import (
	"audit-service/internal/store"
	"context"
)

type EvidenceRepo interface {
	InsertEvidenceHash(ctx context.Context, e store.EvidenceDetails) error
	GetEvidenceHash(ctx context.Context, evidenceID string) (*store.EvidenceHash, error)
	GetEvidenceStatus(ctx context.Context, evidenceIDs []int64) ([]store.EvidenceStatus, error)
	UpdateEvidenceHash(ctx context.Context, evidenceID int64, newHash string) error
}

type CustodyRepo interface {
	InsertCustodyLog(ctx context.Context, c store.CustodyLog) error
	ListCustodyLogs(ctx context.Context, evidenceID string, caseID string, limit int, offset int) ([]store.CustodyLogDTO, error)
	GetCustodyLogByID(ctx context.Context, id string) (*store.CustodyLogDTO, error)
}

type AuditRepo interface {
	InsertAuditLog(ctx context.Context, a store.AuditLog) error
	ListAuditLogs(ctx context.Context, evidenceID string, caseID string, limit int, offset int) ([]store.AuditLogDTO, error)
	GetAuditLogByID(ctx context.Context, id string) (*store.AuditLogDTO, error)
	GetLatestAuditLogByEvidenceID(ctx context.Context, evidenceID int64) (*store.AuditLogDTO, error)
	GetOriginalEvidenceHash(ctx context.Context, evidenceID int64) (string, error)
	GetAuditLogsForVerification(ctx context.Context, scope string, targetID string) ([]store.VerifiableAuditLog, error)
	GetLatestEpochID(ctx context.Context) (int64, error)
	RestoreAuditLog(ctx context.Context, record store.BatchAuditLogRecord) error
	InsertIntegrityAlert(ctx context.Context, alert store.IntegrityAlert) (*store.IntegrityAlert, error)
	ListIntegrityAlerts(ctx context.Context, limit int, offset int) ([]store.IntegrityAlert, error)
}

type ActionRepo interface {
	GetActionIDByName(ctx context.Context, name string) (int32, error)
}
