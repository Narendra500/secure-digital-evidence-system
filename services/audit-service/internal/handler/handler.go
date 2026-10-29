package handler

import (
	"audit-service/internal/cerrors"
	"audit-service/internal/service"
	"audit-service/internal/store"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// Handler defines the HTTP handlers for the services.
type Handler struct {
	registrationService *service.EvidenceRegistrationWorkflow
	evidenceService     service.EvidenceService
	custodyService      service.CustodyService
	auditService        service.AuditService
	verifierService     service.LogVerifierService
}

func NewHandler(
	regisService *service.EvidenceRegistrationWorkflow,
	evidenceService service.EvidenceService,
	custodyService service.CustodyService,
	auditService service.AuditService,
	verifierService service.LogVerifierService,
) *Handler {
	return &Handler{
		registrationService: regisService,
		evidenceService:     evidenceService,
		custodyService:      custodyService,
		auditService:        auditService,
		verifierService:     verifierService,
	}
}

func parsePagination(c *gin.Context) (int, int) {
	limitStr := c.Query("limit")
	offsetStr := c.Query("offset")
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}
	return limit, offset
}

// Insert the evidence into the database.
// The corresponding custody log and audit log will also be inserted.
// All three tasks are performed in a single transaction. Guaranteed to be atomic.
func (h *Handler) RegisterEvidence(c *gin.Context) {
	var evidenceDetails store.EvidenceRegistrationDetails

	// Parse the request body.
	if err := c.ShouldBindJSON(&evidenceDetails); err != nil {
		log.Printf("failed to parse request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Register the evidence via the evidence registration workflow service.
	if err := h.registrationService.RegisterEvidence(c.Request.Context(), evidenceDetails); err != nil {
		// Special case for evidence already exists error.
		if errors.Is(err, cerrors.ErrEvidenceAlreadyExists.Error) {
			c.JSON(cerrors.ErrEvidenceAlreadyExists.HTTPCode, gin.H{"error": cerrors.ErrEvidenceAlreadyExists.Error.Error()})
			return
		}

		if errors.Is(err, cerrors.ErrActionNotFound.Error) {
			c.JSON(cerrors.ErrActionNotFound.HTTPCode, gin.H{"error": cerrors.ErrActionNotFound.Error.Error()})
			return
		}

		// Other errors are considered as internal server errors.
		log.Printf("error: failed to register evidence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "evidence registered successfully"})
}

// VerifyEvidence compares the current evidence file hash with the previously registered known-good hash.
func (h *Handler) VerifyEvidence(c *gin.Context) {
	evidenceID := c.Param("id")
	if evidenceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing evidence id"})
		return
	}

	authHeader := c.GetHeader("Authorization")
	clientIP := c.ClientIP()

	result, err := h.evidenceService.VerifyEvidence(c.Request.Context(), evidenceID, authHeader, clientIP)
	if err != nil {
		if errors.Is(err, cerrors.ErrEvidenceNotFound.Error) {
			c.JSON(http.StatusNotFound, gin.H{
				"status":  "NOT_FOUND",
				"error":   "evidence hash not found in integrity database",
				"message": result.Message,
			})
			return
		}
		if errors.Is(err, cerrors.ErrFileNotFound.Error) {
			c.JSON(http.StatusNotFound, gin.H{
				"status":  "FILE_NOT_FOUND",
				"error":   "evidence file not found in storage",
				"message": result.Message,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  result.Status,
			"error":   err.Error(),
			"message": result.Message,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":        result.Status,
		"verified":      result.Status == "VALID",
		"stored_hash":   result.StoredHash,
		"computed_hash": result.ComputedHash,
		"algorithm":     result.Algorithm,
		"message":       result.Message,
	})
}

func (h *Handler) GetEvidenceStatus(c *gin.Context) {
	strEvidenceIDs := strings.Split(c.Query("evidence_ids"), ",")
	if len(strEvidenceIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing evidence ids"})
		return
	}

	evidenceIDs := make([]int64, len(strEvidenceIDs))
	for i := range len(strEvidenceIDs) {
		val, err := strconv.Atoi(strEvidenceIDs[i])
		if err != nil {
			log.Printf("Failed to convert string to int: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error:": "Given id is not integer"})
		}
		evidenceIDs[i] = int64(val)
	}

	statuses, err := h.evidenceService.GetEvidenceStatus(c.Request.Context(), evidenceIDs)
	if err != nil {
		log.Printf("failed to get evidence status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve evidence status"})
		return
	}

	c.JSON(http.StatusOK, statuses)
}

// GetCustodyLogs returns chain-of-custody logs with optional filtering.
func (h *Handler) GetCustodyLogs(c *gin.Context) {
	evidenceID := c.Query("evidence_id")
	if evidenceID == "" {
		evidenceID = c.Param("id")
	}
	caseID := c.Query("case_id")
	limit, offset := parsePagination(c)

	logs, err := h.custodyService.GetCustodyLogs(c.Request.Context(), evidenceID, caseID, limit, offset)
	if err != nil {
		log.Printf("failed to get custody logs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve custody logs"})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// GetAuditLogs returns immutable audit logs with optional filtering.
func (h *Handler) GetAuditLogs(c *gin.Context) {
	evidenceID := c.Query("evidence_id")
	if evidenceID == "" {
		evidenceID = c.Param("id")
	}
	caseID := c.Query("case_id")
	limit, offset := parsePagination(c)

	logs, err := h.auditService.GetAuditLogs(c.Request.Context(), evidenceID, caseID, limit, offset)
	if err != nil {
		log.Printf("failed to get audit logs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve audit logs"})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// GetCustodyLogByID returns a single custody log record by its ID or UUID.
func (h *Handler) GetCustodyLogByID(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing log id"})
		return
	}

	logEntry, err := h.custodyService.GetCustodyLogByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "custody log not found"})
		return
	}

	c.JSON(http.StatusOK, logEntry)
}

// GetAuditLogByID returns a single immutable audit log record by its ID or UUID.
func (h *Handler) GetAuditLogByID(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing log id"})
		return
	}

	logEntry, err := h.auditService.GetAuditLogByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "audit log not found"})
		return
	}

	c.JSON(http.StatusOK, logEntry)
}

type VerifyLogsRequest struct {
	Scope       string `json:"scope"`
	ID          string `json:"id"`
	AutoRestore *bool  `json:"auto_restore"`
}

// VerifyLogs verifies whether audit logs were modified at evidence, case, or org level.
// Performs local hash-chain verification and authoritative S3 batch manifest cross-verification.
// If modifications/tampering are detected and auto_restore is enabled, it automatically restores logs from S3.
func (h *Handler) VerifyLogs(c *gin.Context) {
	var req VerifyLogsRequest
	_ = c.ShouldBindJSON(&req)

	if req.Scope == "" {
		req.Scope = c.Query("scope")
	}
	if req.ID == "" {
		req.ID = c.Query("id")
	}
	autoRestore := true
	if req.AutoRestore != nil {
		autoRestore = *req.AutoRestore
	} else if arStr := c.Query("auto_restore"); arStr != "" {
		if ar, err := strconv.ParseBool(arStr); err == nil {
			autoRestore = ar
		}
	}

	if req.Scope == "" || req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "scope ('evidence', 'case', or 'org') and id are required",
		})
		return
	}

	result, err := h.verifierService.VerifyLogs(c.Request.Context(), req.Scope, req.ID, autoRestore)
	if err != nil {
		log.Printf("Error verifying logs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetAlerts returns persisted integrity alerts and restoration history.
func (h *Handler) GetAlerts(c *gin.Context) {
	limit, offset := parsePagination(c)
	alerts, err := h.verifierService.ListAlerts(c.Request.Context(), limit, offset)
	if err != nil {
		log.Printf("Error listing integrity alerts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list integrity alerts"})
		return
	}
	c.JSON(http.StatusOK, alerts)
}
