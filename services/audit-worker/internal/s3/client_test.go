package s3

import (
	"audit-worker/internal/models"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestLocalBatchStorage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "batch-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	client := &localBatchStorage{}
	ctx := context.Background()

	// 1. Upload Batch 1 with evidence 10 and 20
	manifest1 := models.BatchManifest{
		EpochID:    1,
		EventCount: 2,
		ChainTip:   "hash-tip-1",
		Timestamp:  time.Now().UTC(),
		Events: []models.AuditLogRecord{
			{
				EvidenceID:  10,
				CurrentHash: "hash-ev10-v1",
			},
			{
				EvidenceID:  20,
				CurrentHash: "hash-ev20-v1",
			},
		},
	}
	data1, _ := json.Marshal(manifest1)
	_, err = client.UploadBatch(ctx, 1, data1)
	if err != nil {
		t.Fatalf("UploadBatch failed: %v", err)
	}

	// 2. Upload Batch 2 with evidence 10 (updated) and 30
	manifest2 := models.BatchManifest{
		EpochID:    2,
		EventCount: 2,
		ChainTip:   "hash-tip-2",
		Timestamp:  time.Now().UTC(),
		Events: []models.AuditLogRecord{
			{
				EvidenceID:  10,
				CurrentHash: "hash-ev10-v2",
			},
			{
				EvidenceID:  30,
				CurrentHash: "hash-ev30-v1",
			},
		},
	}
	data2, _ := json.Marshal(manifest2)
	_, err = client.UploadBatch(ctx, 2, data2)
	if err != nil {
		t.Fatalf("UploadBatch failed: %v", err)
	}

	// Test FindLatestHashForEvidence
	h10, found, err := client.FindLatestHashForEvidence(ctx, 10, 2)
	if err != nil || !found || h10 != "hash-ev10-v2" {
		t.Fatalf("Expected hash-ev10-v2, got hash=%s found=%v err=%v", h10, found, err)
	}

	h20, found, err := client.FindLatestHashForEvidence(ctx, 20, 2)
	if err != nil || !found || h20 != "hash-ev20-v1" {
		t.Fatalf("Expected hash-ev20-v1, got hash=%s found=%v err=%v", h20, found, err)
	}

	h99, found, err := client.FindLatestHashForEvidence(ctx, 99, 2)
	if err != nil || found || h99 != "" {
		t.Fatalf("Expected not found for evidence 99, got hash=%s found=%v err=%v", h99, found, err)
	}

	// Test RecoverStateFromS3
	state, tip, err := client.RecoverStateFromS3(ctx, 2)
	if err != nil {
		t.Fatalf("RecoverStateFromS3 failed: %v", err)
	}
	if tip != "hash-tip-2" {
		t.Fatalf("Expected chain tip hash-tip-2, got %s", tip)
	}
	if state[10] != "hash-ev10-v2" || state[20] != "hash-ev20-v1" || state[30] != "hash-ev30-v1" {
		t.Fatalf("Recovered state mismatch: %+v", state)
	}
}
