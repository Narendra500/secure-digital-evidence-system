package sequencer

import (
	"audit-worker/internal/models"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Sequencer interface {
	ProcessEvent(event models.AuditEventMessage) models.AuditLogRecord
	GetChainTip() string
	GetLatestHash(evidenceID int64) string
	HasEvidence(evidenceID int64) bool
	SetLatestHash(evidenceID int64, hash string)
	InitializeState(initialEvidenceHashes map[int64]string, initialChainTip string)
}

type inMemorySequencer struct {
	mu                  sync.RWMutex
	lastHashByEvidence  map[int64]string
	globalChainTip      string
}

func NewSequencer() Sequencer {
	return &inMemorySequencer{
		lastHashByEvidence: make(map[int64]string),
	}
}

func (s *inMemorySequencer) InitializeState(initialEvidenceHashes map[int64]string, initialChainTip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range initialEvidenceHashes {
		s.lastHashByEvidence[k] = v
	}
	s.globalChainTip = initialChainTip
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

func hashRowContents(event models.AuditEventMessage, prevRowHash string) string {
	ip := cleanIP(event.IPAddress)
	concatenatedRow := strconv.Itoa(int(event.UserID)) +
		strconv.Itoa(int(event.CaseID)) +
		strconv.Itoa(int(event.EvidenceID)) +
		strconv.Itoa(int(event.ActionType)) +
		event.ServiceName +
		ip +
		prevRowHash

	hash := sha256.Sum256([]byte(concatenatedRow))
	return hex.EncodeToString(hash[:])
}

func (s *inMemorySequencer) ProcessEvent(event models.AuditEventMessage) models.AuditLogRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevHash := s.lastHashByEvidence[event.EvidenceID]
	currHash := hashRowContents(event, prevHash)

	s.lastHashByEvidence[event.EvidenceID] = currHash
	s.globalChainTip = currHash

	timestamp := event.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	status := event.Status
	if status == "" {
		status = "unchanged"
	}

	return models.AuditLogRecord{
		UserID:       event.UserID,
		CaseID:       event.CaseID,
		EvidenceID:   event.EvidenceID,
		ActionType:   event.ActionType,
		ActionName:   event.ActionName,
		ServiceName:  event.ServiceName,
		IPAddress:    cleanIP(event.IPAddress),
		RequestID:    event.RequestID,
		PreviousHash: prevHash,
		CurrentHash:  currHash,
		Status:       status,
		Details:      event.Details,
		CreatedAt:    timestamp,
	}
}

func (s *inMemorySequencer) GetChainTip() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.globalChainTip
}

func (s *inMemorySequencer) GetLatestHash(evidenceID int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastHashByEvidence[evidenceID]
}

func (s *inMemorySequencer) HasEvidence(evidenceID int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.lastHashByEvidence[evidenceID]
	return exists
}

func (s *inMemorySequencer) SetLatestHash(evidenceID int64, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHashByEvidence[evidenceID] = hash
}
