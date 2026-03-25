package service

import (
	"audit-service/internal/repository"
)

type evidenceService struct {
	evidenceRepo repository.EvidenceRepo
}

func NewEvidenceService(evidenceRepo repository.EvidenceRepo) *evidenceService {
	return &evidenceService{evidenceRepo}
}
