package service

import (
	"audit-service/internal/store"
	"context"
	"testing"
	"time"
)

type mockAuditRepo struct {
	logs        []store.VerifiableAuditLog
	latestEpoch int64
	restored    map[string]store.BatchAuditLogRecord
	alerts      []store.IntegrityAlert
}

func (m *mockAuditRepo) InsertAuditLog(ctx context.Context, a store.AuditLog) error {
	return nil
}

func (m *mockAuditRepo) ListAuditLogs(ctx context.Context, evidenceID string, caseID string, limit int, offset int) ([]store.AuditLogDTO, error) {
	return nil, nil
}

func (m *mockAuditRepo) GetAuditLogByID(ctx context.Context, id string) (*store.AuditLogDTO, error) {
	return nil, nil
}

func (m *mockAuditRepo) GetLatestAuditLogByEvidenceID(ctx context.Context, evidenceID int64) (*store.AuditLogDTO, error) {
	return nil, nil
}

func (m *mockAuditRepo) GetOriginalEvidenceHash(ctx context.Context, evidenceID int64) (string, error) {
	return "", nil
}

func (m *mockAuditRepo) GetAuditLogsForVerification(ctx context.Context, scope string, targetID string) ([]store.VerifiableAuditLog, error) {
	return m.logs, nil
}

func (m *mockAuditRepo) GetLatestEpochID(ctx context.Context) (int64, error) {
	return m.latestEpoch, nil
}

func (m *mockAuditRepo) RestoreAuditLog(ctx context.Context, record store.BatchAuditLogRecord) error {
	if m.restored == nil {
		m.restored = make(map[string]store.BatchAuditLogRecord)
	}
	m.restored[record.RequestID] = record
	return nil
}

func (m *mockAuditRepo) InsertIntegrityAlert(ctx context.Context, alert store.IntegrityAlert) (*store.IntegrityAlert, error) {
	alert.ID = int64(len(m.alerts) + 1)
	alert.PublicID = "alert-test-uuid"
	alert.CreatedAt = time.Now().UTC()
	m.alerts = append(m.alerts, alert)
	return &alert, nil
}

func (m *mockAuditRepo) ListIntegrityAlerts(ctx context.Context, limit int, offset int) ([]store.IntegrityAlert, error) {
	return m.alerts, nil
}

type mockS3Client struct {
	manifests []*store.BatchManifest
}

func (m *mockS3Client) GetBatch(ctx context.Context, epochID int64) (*store.BatchManifest, error) {
	for _, man := range m.manifests {
		if man.EpochID == epochID {
			return man, nil
		}
	}
	return nil, nil
}

func (m *mockS3Client) GetAllBatches(ctx context.Context, maxEpoch int64) ([]*store.BatchManifest, error) {
	return m.manifests, nil
}

func TestVerifyLogs_ValidChain(t *testing.T) {
	log1 := store.VerifiableAuditLog{
		ID:          1,
		EvidenceID:  10,
		UserID:      1,
		CaseID:      100,
		ActionType:  1,
		ServiceName: "evidence-service",
		IPAddress:   "127.0.0.1",
		RequestID:   "req-1",
	}
	log1.CurrentHash = computeHashFromVerifiableLog(log1, "")

	log2 := store.VerifiableAuditLog{
		ID:           2,
		EvidenceID:   10,
		UserID:       2,
		CaseID:       100,
		ActionType:   3,
		ServiceName:  "audit-service",
		IPAddress:    "127.0.0.1",
		RequestID:    "req-2",
		PreviousHash: log1.CurrentHash,
	}
	log2.CurrentHash = computeHashFromVerifiableLog(log2, log1.CurrentHash)

	repo := &mockAuditRepo{
		logs: []store.VerifiableAuditLog{log1, log2},
	}
	s3Cli := &mockS3Client{}
	svc := NewLogVerifierService(repo, s3Cli)

	res, err := svc.VerifyLogs(context.Background(), "evidence", "10", true)
	if err != nil {
		t.Fatalf("VerifyLogs failed: %v", err)
	}
	if res.Modified {
		t.Fatalf("Expected modified to be false, got true with issues: %+v", res.Issues)
	}
	if res.Status != "VALID" {
		t.Fatalf("Expected status VALID, got: %s", res.Status)
	}
}

func TestVerifyLogs_TamperedContent(t *testing.T) {
	log1 := store.VerifiableAuditLog{
		ID:          1,
		EvidenceID:  10,
		UserID:      1,
		CaseID:      100,
		ActionType:  1,
		ServiceName: "evidence-service",
		IPAddress:   "127.0.0.1",
		RequestID:   "req-1",
	}
	log1.CurrentHash = computeHashFromVerifiableLog(log1, "")

	// Tampered log: hash has been poisoned
	log2 := store.VerifiableAuditLog{
		ID:           2,
		EvidenceID:   10,
		UserID:       2,
		CaseID:       100,
		ActionType:   3,
		ServiceName:  "audit-service",
		IPAddress:    "127.0.0.1",
		RequestID:    "req-2",
		PreviousHash: log1.CurrentHash,
		CurrentHash:  "poisoned-hash-value-12345",
	}

	repo := &mockAuditRepo{
		logs: []store.VerifiableAuditLog{log1, log2},
	}
	s3Cli := &mockS3Client{}
	svc := NewLogVerifierService(repo, s3Cli)

	res, err := svc.VerifyLogs(context.Background(), "case", "100", false)
	if err != nil {
		t.Fatalf("VerifyLogs failed: %v", err)
	}
	if !res.Modified {
		t.Fatalf("Expected modified to be true, got false")
	}
	if res.Status != "TAMPER_DETECTED" {
		t.Fatalf("Expected status TAMPER_DETECTED, got: %s", res.Status)
	}
	if len(res.Issues) == 0 {
		t.Fatalf("Expected issues to be reported")
	}
}

func TestVerifyLogs_S3DiscrepancyAndRestoration(t *testing.T) {
	log1 := store.VerifiableAuditLog{
		ID:          1,
		EvidenceID:  10,
		UserID:      1,
		CaseID:      100,
		ActionType:  1,
		ServiceName: "evidence-service",
		IPAddress:   "127.0.0.1",
		RequestID:   "req-1",
	}
	validHash1 := computeHashFromVerifiableLog(log1, "")
	log1.CurrentHash = validHash1

	// In database, an attacker altered row 1's action or current_hash
	tamperedDBLog := log1
	tamperedDBLog.CurrentHash = "tampered-db-hash"

	// But S3 batch manifest contains the authentic record
	s3Record := store.BatchAuditLogRecord{
		UserID:       1,
		CaseID:       100,
		EvidenceID:   10,
		ActionType:   1,
		ServiceName:  "evidence-service",
		IPAddress:    "127.0.0.1",
		RequestID:    "req-1",
		PreviousHash: "",
		CurrentHash:  validHash1,
	}

	repo := &mockAuditRepo{
		logs:        []store.VerifiableAuditLog{tamperedDBLog},
		latestEpoch: 1,
	}
	s3Cli := &mockS3Client{
		manifests: []*store.BatchManifest{
			{
				EpochID:    1,
				EventCount: 1,
				Events:     []store.BatchAuditLogRecord{s3Record},
			},
		},
	}

	svc := NewLogVerifierService(repo, s3Cli)

	res, err := svc.VerifyLogs(context.Background(), "evidence", "10", true)
	if err != nil {
		t.Fatalf("VerifyLogs failed: %v", err)
	}
	if !res.Modified {
		t.Fatalf("Expected modified to be true")
	}
	if !res.Restored {
		t.Fatalf("Expected restored to be true")
	}
	if res.Status != "TAMPERED_AND_RESTORED" {
		t.Fatalf("Expected status TAMPERED_AND_RESTORED, got %s", res.Status)
	}
	if repo.restored["req-1"].CurrentHash != validHash1 {
		t.Fatalf("Expected restored record to have hash %s, got: %s", validHash1, repo.restored["req-1"].CurrentHash)
	}
	if len(repo.alerts) == 0 {
		t.Fatalf("Expected integrity alert to be persisted")
	}
}
