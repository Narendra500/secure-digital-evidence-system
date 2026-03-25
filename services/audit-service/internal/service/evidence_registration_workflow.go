package service

import (
	"audit-service/internal/repository"
	"audit-service/internal/store"
	"context"
)

type EvidenceRegistrationWorkflow struct {
	store        *store.Storage
	evidenceRepo repository.EvidenceRepo
	custodyRepo  repository.CustodyRepo
	auditRepo    repository.AuditRepo
}

func NewEvidenceRegistrationWorkflow(store *store.Storage, evidenceRepo repository.EvidenceRepo, custodyRepo repository.CustodyRepo, auditRepo repository.AuditRepo) *EvidenceRegistrationWorkflow {
	return &EvidenceRegistrationWorkflow{store, evidenceRepo, custodyRepo, auditRepo}
}

func (ev *EvidenceRegistrationWorkflow) RegisterEvidence(ctx context.Context, evidence store.EvidenceRegistrationDetails) error {
	return ev.store.WithinTransactionReadCommitted(ctx, func(txCtx context.Context) error {
		// Pass txCtx instead of ctx to ensure that query is executed within the transaction.
		if err := ev.evidenceRepo.InsertEvidenceHash(txCtx, evidence.ToEvidenceDetails()); err != nil {
			return err
		}

		if err := ev.custodyRepo.InsertCustodyLog(txCtx, evidence.ToCustodyLog()); err != nil {
			return err
		}

		if err := ev.auditRepo.InsertAuditLog(txCtx, evidence.ToAuditLog()); err != nil {
			return err
		}

		return nil // Everything commits successfully.
	})
}
