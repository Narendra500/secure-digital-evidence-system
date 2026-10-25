package service

import (
	"audit-service/internal/queue"
	"audit-service/internal/repository"
	"audit-service/internal/store"
	"context"
	"log"
)

type EvidenceRegistrationWorkflow struct {
	store        *store.Storage
	evidenceRepo repository.EvidenceRepo
	custodyRepo  repository.CustodyRepo
	auditRepo    repository.AuditRepo
	actionRepo   repository.ActionRepo
	publisher    queue.Publisher
}

func NewEvidenceRegistrationWorkflow(
	store *store.Storage,
	evidenceRepo repository.EvidenceRepo,
	custodyRepo repository.CustodyRepo,
	auditRepo repository.AuditRepo,
	actionRepo repository.ActionRepo,
	publisher queue.Publisher,
) *EvidenceRegistrationWorkflow {
	return &EvidenceRegistrationWorkflow{store, evidenceRepo, custodyRepo, auditRepo, actionRepo, publisher}
}

func (ev *EvidenceRegistrationWorkflow) RegisterEvidence(ctx context.Context, evidence store.EvidenceRegistrationDetails) error {
	return ev.store.WithinTransactionReadCommitted(ctx, func(txCtx context.Context) error {
		// Resolve the action name to action ID
		actionID, err := ev.actionRepo.GetActionIDByName(txCtx, evidence.Action)
		if err != nil {
			return err
		}

		if evidence.Action == "REVERT" {
			if err := ev.evidenceRepo.UpdateEvidenceHash(txCtx, evidence.EvidenceID, evidence.FileHash); err != nil {
				return err
			}
		} else {
			// Pass txCtx instead of ctx to ensure that query is executed within the transaction.
			if err := ev.evidenceRepo.InsertEvidenceHash(txCtx, evidence.ToEvidenceDetails()); err != nil {
				return err
			}
		}

		if err := ev.custodyRepo.InsertCustodyLog(txCtx, evidence.ToCustodyLog(actionID)); err != nil {
			return err
		}

		if ev.publisher != nil {
			if err := ev.publisher.PublishAuditEvent(txCtx, evidence.ToAuditEventMessage(actionID)); err != nil {
				log.Printf("warning: failed to publish audit event: %v", err)
			}
		} else if ev.auditRepo != nil {
			if err := ev.auditRepo.InsertAuditLog(txCtx, evidence.ToAuditLog(actionID)); err != nil {
				return err
			}
		}

		return nil // Everything commits successfully.
	})
}
