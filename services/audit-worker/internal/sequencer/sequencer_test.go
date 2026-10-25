package sequencer

import (
	"audit-worker/internal/models"
	"testing"
	"time"
)

func TestSequencerChaining(t *testing.T) {
	seq := NewSequencer()

	// Initial event
	ev1 := models.AuditEventMessage{
		UserID:      1,
		CaseID:      10,
		EvidenceID:  100,
		ActionType:  1,
		ActionName:  "UPLOAD",
		ServiceName: "evidence-service",
		IPAddress:   "192.168.1.10",
		RequestID:   "req-1",
		Timestamp:   time.Now().UTC(),
	}

	rec1 := seq.ProcessEvent(ev1)
	if rec1.PreviousHash != "" {
		t.Fatalf("Expected first event previous hash to be empty, got: %s", rec1.PreviousHash)
	}
	if rec1.CurrentHash == "" {
		t.Fatalf("Expected first event current hash to be non-empty")
	}

	// Second event for the same evidence
	ev2 := models.AuditEventMessage{
		UserID:      2,
		CaseID:      10,
		EvidenceID:  100,
		ActionType:  3,
		ActionName:  "VERIFY",
		ServiceName: "audit-service",
		IPAddress:   "192.168.1.20",
		RequestID:   "req-2",
		Timestamp:   time.Now().UTC(),
	}

	rec2 := seq.ProcessEvent(ev2)
	if rec2.PreviousHash != rec1.CurrentHash {
		t.Fatalf("Expected rec2 previous hash (%s) to match rec1 current hash (%s)", rec2.PreviousHash, rec1.CurrentHash)
	}
	if rec2.CurrentHash == rec1.CurrentHash {
		t.Fatalf("Expected rec2 current hash to be different from rec1")
	}

	// Third event for a DIFFERENT evidence
	ev3 := models.AuditEventMessage{
		UserID:      1,
		CaseID:      10,
		EvidenceID:  200,
		ActionType:  1,
		ActionName:  "UPLOAD",
		ServiceName: "evidence-service",
		IPAddress:   "192.168.1.10",
		RequestID:   "req-3",
		Timestamp:   time.Now().UTC(),
	}

	rec3 := seq.ProcessEvent(ev3)
	if rec3.PreviousHash != "" {
		t.Fatalf("Expected new evidence 200 previous hash to be empty, got: %s", rec3.PreviousHash)
	}
}

func TestSequencerStateInitialization(t *testing.T) {
	seq := NewSequencer()
	knownHashes := map[int64]string{
		50: "known-hash-for-50",
	}
	seq.InitializeState(knownHashes, "known-tip")

	ev := models.AuditEventMessage{
		UserID:      1,
		CaseID:      10,
		EvidenceID:  50,
		ActionType:  2,
		ServiceName: "evidence-service",
		IPAddress:   "127.0.0.1",
	}

	rec := seq.ProcessEvent(ev)
	if rec.PreviousHash != "known-hash-for-50" {
		t.Fatalf("Expected initialized previous hash 'known-hash-for-50', got: %s", rec.PreviousHash)
	}
}
