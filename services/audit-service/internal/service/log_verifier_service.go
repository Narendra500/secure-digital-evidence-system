package service

import (
	"audit-service/internal/repository"
	"audit-service/internal/s3"
	"audit-service/internal/store"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

type LogVerifierService interface {
	VerifyLogs(ctx context.Context, scope string, targetID string, autoRestore bool) (*store.LogVerificationResult, error)
	ListAlerts(ctx context.Context, limit int, offset int) ([]store.IntegrityAlert, error)
}

type logVerifierService struct {
	auditRepo repository.AuditRepo
	s3Client  s3.Client
}

func NewLogVerifierService(auditRepo repository.AuditRepo, s3Cli s3.Client) LogVerifierService {
	return &logVerifierService{
		auditRepo: auditRepo,
		s3Client:  s3Cli,
	}
}

func cleanIP(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if idx := strings.Index(ipStr, "/"); idx != -1 {
		ipStr = ipStr[:idx]
	}
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		return host
	}
	if ipStr == "" {
		return "127.0.0.1"
	}
	return ipStr
}

func computeHashFromVerifiableLog(l store.VerifiableAuditLog, prevRowHash string) string {
	ip := cleanIP(l.IPAddress)
	concatenated := strconv.Itoa(int(l.UserID)) +
		strconv.Itoa(int(l.CaseID)) +
		strconv.Itoa(int(l.EvidenceID)) +
		strconv.Itoa(int(l.ActionType)) +
		l.ServiceName +
		ip +
		prevRowHash

	hash := sha256.Sum256([]byte(concatenated))
	return hex.EncodeToString(hash[:])
}

func (s *logVerifierService) VerifyLogs(ctx context.Context, scope string, targetID string, autoRestore bool) (*store.LogVerificationResult, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	targetID = strings.TrimSpace(targetID)

	if targetID == "" {
		return nil, fmt.Errorf("target_id is required")
	}
	if scope != "evidence" && scope != "case" && scope != "org" {
		return nil, fmt.Errorf("invalid scope: %s (must be 'evidence', 'case', or 'org')", scope)
	}

	logs, err := s.auditRepo.GetAuditLogsForVerification(ctx, scope, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit logs for verification: %w", err)
	}

	if len(logs) == 0 {
		return &store.LogVerificationResult{
			VerifiedAt:       time.Now().UTC(),
			Scope:            scope,
			TargetID:         targetID,
			Status:           "VALID",
			Modified:         false,
			Restored:         false,
			EvidencesChecked: 0,
			LogsChecked:      0,
			TamperedCount:    0,
			RestoredCount:    0,
			Issues:           []store.LogVerificationIssue{},
			Message:          fmt.Sprintf("No audit logs found for %s '%s'", scope, targetID),
		}, nil
	}

	// Group logs by evidence_id
	logsByEvidence := make(map[int64][]store.VerifiableAuditLog)
	evidenceMap := make(map[int64]string)
	dbRequestIDs := make(map[string]bool)

	for _, l := range logs {
		logsByEvidence[l.EvidenceID] = append(logsByEvidence[l.EvidenceID], l)
		if l.EvidencePublicID != "" {
			evidenceMap[l.EvidenceID] = l.EvidencePublicID
		}
		if l.RequestID != "" {
			dbRequestIDs[l.RequestID] = true
		}
	}

	var issues []store.LogVerificationIssue
	modified := false

	// =========================================================================
	// Phase 1: Local Postgres Hash Chain Verification
	// =========================================================================
	for evID, evLogs := range logsByEvidence {
		evPubID := evidenceMap[evID]
		expectedPrevHash := ""

		for i, logRow := range evLogs {
			// Check previous_hash chain continuity
			if logRow.PreviousHash != expectedPrevHash {
				modified = true
				issues = append(issues, store.LogVerificationIssue{
					EvidenceID:       evID,
					EvidencePublicID: evPubID,
					LogID:            logRow.ID,
					RequestID:        logRow.RequestID,
					IssueType:        "CHAIN_BROKEN",
					ExpectedHash:     expectedPrevHash,
					ActualHash:       logRow.PreviousHash,
					Message: fmt.Sprintf("Hash chain continuity broken at row %d (log ID %d): previous_hash is '%s', expected '%s'",
						i+1, logRow.ID, logRow.PreviousHash, expectedPrevHash),
				})
			}

			// Recompute row digest and compare with current_hash
			recomputed := computeHashFromVerifiableLog(logRow, expectedPrevHash)
			if recomputed != logRow.CurrentHash {
				modified = true
				issues = append(issues, store.LogVerificationIssue{
					EvidenceID:       evID,
					EvidencePublicID: evPubID,
					LogID:            logRow.ID,
					RequestID:        logRow.RequestID,
					IssueType:        "HASH_MISMATCH",
					ExpectedHash:     recomputed,
					ActualHash:       logRow.CurrentHash,
					Message: fmt.Sprintf("Row digest mismatch at log ID %d: recorded current_hash is '%s', recomputed '%s'",
						logRow.ID, logRow.CurrentHash, recomputed),
				})
			}

			expectedPrevHash = logRow.CurrentHash
		}
	}

	// =========================================================================
	// Phase 2: Authoritative S3 Batch Manifest Cross-Verification
	// =========================================================================
	latestEpoch, err := s.auditRepo.GetLatestEpochID(ctx)
	if err != nil {
		log.Printf("Warning: could not get latest epoch ID: %v", err)
	}

	s3EventsByRequestID := make(map[string]store.BatchAuditLogRecord)

	if latestEpoch > 0 && s.s3Client != nil {
		manifests, err := s.s3Client.GetAllBatches(ctx, latestEpoch)
		if err != nil {
			log.Printf("Warning: failed to load S3 batch manifests: %v", err)
		} else {
			for _, m := range manifests {
				if m == nil {
					continue
				}
				for _, evRecord := range m.Events {
					if _, inScope := logsByEvidence[evRecord.EvidenceID]; inScope {
						if evRecord.RequestID != "" {
							s3EventsByRequestID[evRecord.RequestID] = evRecord
						}
					}
				}
			}

			// Compare DB logs against S3 batch manifest authoritative records
			for _, logRow := range logs {
				if s3Ev, ok := s3EventsByRequestID[logRow.RequestID]; ok {
					if logRow.CurrentHash != s3Ev.CurrentHash || logRow.PreviousHash != s3Ev.PreviousHash {
						modified = true
						issues = append(issues, store.LogVerificationIssue{
							EvidenceID:       logRow.EvidenceID,
							EvidencePublicID: evidenceMap[logRow.EvidenceID],
							LogID:            logRow.ID,
							RequestID:        logRow.RequestID,
							IssueType:        "S3_MANIFEST_DISCREPANCY",
							ExpectedHash:     s3Ev.CurrentHash,
							ActualHash:       logRow.CurrentHash,
							Message: fmt.Sprintf("Discrepancy with immutable S3 batch manifest for request %s: DB hash '%s' != S3 manifest hash '%s'",
								logRow.RequestID, logRow.CurrentHash, s3Ev.CurrentHash),
						})
					}
				}
			}

			// Check for missing rows in DB that exist in S3 manifests
			for reqID, s3Ev := range s3EventsByRequestID {
				if !dbRequestIDs[reqID] {
					modified = true
					issues = append(issues, store.LogVerificationIssue{
						EvidenceID:       s3Ev.EvidenceID,
						EvidencePublicID: evidenceMap[s3Ev.EvidenceID],
						RequestID:        reqID,
						IssueType:        "MISSING_ROW",
						ExpectedHash:     s3Ev.CurrentHash,
						Message: fmt.Sprintf("Audit log record '%s' exists in S3 batch manifest but was deleted from PostgreSQL",
							reqID),
					})
				}
			}
		}
	}

	// =========================================================================
	// Phase 3: Automated Restoration & Alert Notification
	// =========================================================================
	restoredCount := 0
	var savedAlert *store.IntegrityAlert

	if modified {
		if autoRestore && len(s3EventsByRequestID) > 0 {
			log.Printf("Tampering detected in %d entries for %s '%s'. Initiating automated restoration from S3 manifests...",
				len(issues), scope, targetID)

			for i := range issues {
				reqID := issues[i].RequestID
				if s3Record, exists := s3EventsByRequestID[reqID]; exists {
					if restoreErr := s.auditRepo.RestoreAuditLog(ctx, s3Record); restoreErr != nil {
						log.Printf("Failed to restore audit log %s from S3 manifest: %v", reqID, restoreErr)
					} else {
						issues[i].Restored = true
						restoredCount++
					}
				}
			}
		}

		status := "TAMPER_DETECTED"
		if autoRestore && restoredCount > 0 {
			status = "TAMPERED_AND_RESTORED"
		}

		alertRecord := store.IntegrityAlert{
			Scope:         scope,
			TargetID:      targetID,
			Status:        status,
			TamperedCount: len(issues),
			RestoredCount: restoredCount,
			Details: map[string]any{
				"evidences_checked": len(logsByEvidence),
				"logs_checked":      len(logs),
				"auto_restore":      autoRestore,
				"issues":            issues,
				"timestamp":         time.Now().UTC().Format(time.RFC3339),
			},
		}

		alert, err := s.auditRepo.InsertIntegrityAlert(ctx, alertRecord)
		if err != nil {
			log.Printf("Warning: failed to persist integrity alert: %v", err)
		} else {
			savedAlert = alert
		}

		message := fmt.Sprintf("Tampering detected in %d log entries for %s '%s'.", len(issues), scope, targetID)
		if restoredCount > 0 {
			message += fmt.Sprintf(" Successfully restored %d entries from authoritative S3 batch manifests.", restoredCount)
		}

		return &store.LogVerificationResult{
			VerifiedAt:       time.Now().UTC(),
			Scope:            scope,
			TargetID:         targetID,
			Status:           status,
			Modified:         true,
			Restored:         restoredCount > 0,
			EvidencesChecked: len(logsByEvidence),
			LogsChecked:      len(logs),
			TamperedCount:    len(issues),
			RestoredCount:    restoredCount,
			Issues:           issues,
			Alert:            savedAlert,
			Message:          message,
		}, nil
	}

	return &store.LogVerificationResult{
		VerifiedAt:       time.Now().UTC(),
		Scope:            scope,
		TargetID:         targetID,
		Status:           "VALID",
		Modified:         false,
		Restored:         false,
		EvidencesChecked: len(logsByEvidence),
		LogsChecked:      len(logs),
		TamperedCount:    0,
		RestoredCount:    0,
		Issues:           []store.LogVerificationIssue{},
		Message:          fmt.Sprintf("All audit log chains and S3 batch manifests verified successfully for %s '%s'. No tampering detected.", scope, targetID),
	}, nil
}

func (s *logVerifierService) ListAlerts(ctx context.Context, limit int, offset int) ([]store.IntegrityAlert, error) {
	return s.auditRepo.ListIntegrityAlerts(ctx, limit, offset)
}
