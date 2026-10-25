package service

import (
	"audit-service/internal/cerrors"
	"audit-service/internal/queue"
	"audit-service/internal/repository"
	"audit-service/internal/store"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"time"
)

type EvidenceService interface {
	VerifyEvidence(ctx context.Context, evidenceID string, authToken string, clientIP string) (*VerifyEvidenceResult, error)
	GetEvidenceStatus(ctx context.Context, evidenceIDs []int64) ([]store.EvidenceStatus, error)
}

type evidenceService struct {
	evidenceRepo repository.EvidenceRepo
	auditRepo    repository.AuditRepo
	actionRepo   repository.ActionRepo
	fileFetcher  FileFetcher
	publisher    queue.Publisher
}

func NewEvidenceService(
	evidenceRepo repository.EvidenceRepo,
	auditRepo repository.AuditRepo,
	actionRepo repository.ActionRepo,
	fileFetcher FileFetcher,
	publisher queue.Publisher,
) EvidenceService {
	if fileFetcher == nil {
		fileFetcher = NewFileFetcher("", nil)
	}
	return &evidenceService{
		evidenceRepo: evidenceRepo,
		auditRepo:    auditRepo,
		actionRepo:   actionRepo,
		fileFetcher:  fileFetcher,
		publisher:    publisher,
	}
}

type VerifyEvidenceResult struct {
	Status       string `json:"status"` // "VALID", "TAMPERED", "NOT_FOUND", "FILE_NOT_FOUND", "HASHING_ERROR", "FILE_FETCHING_ERROR"
	StoredHash   string `json:"stored_hash,omitempty"`
	ComputedHash string `json:"computed_hash,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	Message      string `json:"message,omitempty"`
}

func computeSHA256Hash(file io.ReadCloser) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (e *evidenceService) VerifyEvidence(ctx context.Context, evidenceID string, authToken string, clientIP string) (*VerifyEvidenceResult, error) {
	// Get stored evidence hash from integrity database
	evidenceHash, err := e.evidenceRepo.GetEvidenceHash(ctx, evidenceID)
	if err != nil {
		if errors.Is(err, cerrors.ErrEvidenceNotFound.Error) {
			return &VerifyEvidenceResult{
				Status:  "NOT_FOUND",
				Message: "Evidence hash not found in integrity database",
			}, cerrors.ErrEvidenceNotFound.Error
		}
		return nil, err
	}

	// Fetch evidence file from evidence service
	file, err := e.fileFetcher.GetFile(ctx, evidenceID, authToken)
	if err != nil {
		if errors.Is(err, cerrors.ErrFileNotFound.Error) {
			return &VerifyEvidenceResult{
				Status:     "FILE_NOT_FOUND",
				StoredHash: evidenceHash.FileHash,
				Algorithm:  evidenceHash.Algorithm,
				Message:    "Evidence file not found in storage",
			}, cerrors.ErrFileNotFound.Error
		}
		return &VerifyEvidenceResult{
			Status:     "FILE_FETCHING_ERROR",
			StoredHash: evidenceHash.FileHash,
			Algorithm:  evidenceHash.Algorithm,
			Message:    err.Error(),
		}, err
	}
	defer file.Close()

	// Compute current cryptographic hash of the file stream
	computedHash, err := computeSHA256Hash(file)
	if err != nil {
		return &VerifyEvidenceResult{
			Status:     "HASHING_ERROR",
			StoredHash: evidenceHash.FileHash,
			Algorithm:  evidenceHash.Algorithm,
			Message:    err.Error(),
		}, err
	}

	// Get original known-good hash from earliest audit log (or fallback to evidence_hashes)
	originalHash := evidenceHash.FileHash
	if e.auditRepo != nil {
		if orig, err := e.auditRepo.GetOriginalEvidenceHash(ctx, evidenceHash.EvidenceID); err == nil && orig != "" {
			originalHash = orig
		}
	}

	// Compare current computed hash with original registered hash
	isTampered := !strings.EqualFold(computedHash, originalHash)

	resultStatus := "VALID"
	logStatus := "unchanged"
	message := "Evidence integrity verified: file hash matches original registered hash"

	if isTampered {
		resultStatus = "TAMPERED"
		logStatus = "tampered"
		message = "Evidence integrity check failed: file hash does not match original registered hash"

		// Update evidence_hashes to reflect the current (tampered) file hash
		if err := e.evidenceRepo.UpdateEvidenceHash(ctx, evidenceHash.EvidenceID, computedHash); err != nil {
			log.Printf("warning: failed to update tampered evidence hash: %v", err)
		}
	}

	// Retrieve previous audit log metadata to preserve case, user, and file names
	var userID int64 = 1
	var caseID int64 = 1
	detailsMap := make(map[string]any)

	if e.auditRepo != nil {
		latestAudit, err := e.auditRepo.GetLatestAuditLogByEvidenceID(ctx, evidenceHash.EvidenceID)
		if err == nil && latestAudit != nil {
			userID = latestAudit.UserID
			caseID = latestAudit.CaseID
			for k, v := range latestAudit.Details {
				detailsMap[k] = v
			}
		}
	}

	detailsMap["verified_status"] = resultStatus
	detailsMap["original_hash"] = originalHash
	detailsMap["stored_hash"] = originalHash
	detailsMap["computed_hash"] = computedHash
	detailsMap["verified_at"] = time.Now().UTC().Format(time.RFC3339)

	detailsBytes, _ := json.Marshal(detailsMap)

	// Log the VERIFY action into audit_logs
	if e.auditRepo != nil && e.actionRepo != nil {
		actionID, err := e.actionRepo.GetActionIDByName(ctx, "VERIFY")
		if err != nil {
			log.Printf("warning: failed to get action id for VERIFY: %v", err)
			actionID = 3 // fallback if action id lookup fails
		}

		requestID := store.GenerateRequestID(evidenceHash.EvidenceID, computedHash, actionID, userID, caseID)

		auditEvent := store.AuditEventMessage{
			UserID:      userID,
			CaseID:      caseID,
			EvidenceID:  evidenceHash.EvidenceID,
			ActionType:  actionID,
			ActionName:  "VERIFY",
			ServiceName: "audit-service",
			IPAddress:   clientIP,
			RequestID:   requestID,
			Status:      logStatus,
			Details:     string(detailsBytes),
			Timestamp:   time.Now().UTC(),
		}

		if e.publisher != nil {
			if err := e.publisher.PublishAuditEvent(ctx, auditEvent); err != nil {
				log.Printf("warning: failed to publish verify audit event: %v", err)
			}
		} else if e.auditRepo != nil {
			auditLog := store.AuditLog{
				UserID:      userID,
				CaseID:      caseID,
				EvidenceId:  evidenceHash.EvidenceID,
				ActionType:  actionID,
				ServiceName: "audit-service",
				IPAddress:   clientIP,
				RequestID:   requestID,
				Status:      logStatus,
				Details:     string(detailsBytes),
			}
			if err := e.auditRepo.InsertAuditLog(ctx, auditLog); err != nil {
				log.Printf("warning: failed to insert verify audit log: %v", err)
			}
		}
	}

	return &VerifyEvidenceResult{
		Status:       resultStatus,
		StoredHash:   evidenceHash.FileHash,
		ComputedHash: computedHash,
		Algorithm:    evidenceHash.Algorithm,
		Message:      message,
	}, nil
}

func (e *evidenceService) GetEvidenceStatus(ctx context.Context, evidenceIDs []int64) ([]store.EvidenceStatus, error) {
	statuses, err := e.evidenceRepo.GetEvidenceStatus(ctx, evidenceIDs)
	if err != nil {
		return nil, err
	}

	return statuses, nil
}
