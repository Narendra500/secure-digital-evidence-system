package service

import (
	"audit-service/internal/repository"
)

type auditService struct {
	auditRepo repository.AuditRepo
}

func NewAuditService(auditRepo repository.AuditRepo) *auditService {
	return &auditService{auditRepo}
}
