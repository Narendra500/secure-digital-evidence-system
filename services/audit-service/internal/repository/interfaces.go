package repository

import (
	"audit-service/internal/store"
	"context"
)

type EvidenceRepo interface {
	InsertEvidenceHash(ctx context.Context, e store.EvidenceDetails) error
	GetEvidenceHash(ctx context.Context, evidenceId string) (*store.EvidenceHash, error)
}

type CustodyRepo interface {
	InsertCustodyLog(ctx context.Context, c store.CustodyLog) error
}

type AuditRepo interface {
	InsertAuditLog(ctx context.Context, a store.AuditLog) error
}
