package handler

import (
	"audit-service/internal/cerrors"
	"audit-service/internal/service"
	"audit-service/internal/store"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler defines the HTTP handlers for the services.
type Handler struct {
	registrationService *service.EvidenceRegistrationWorkflow
}

func NewHandler(regisService *service.EvidenceRegistrationWorkflow) *Handler {
	return &Handler{registrationService: regisService}
}

// Insert the evidence into the database.
// The corresponsing custody log and audit log will also be inserted.
// All three tasks are performed in a single transaction. Guaranteed to be atomic.
func (h *Handler) RegisterEvidence(c *gin.Context) {
	var evidenceDetails store.EvidenceRegistrationDetails

	// Parse the request body.
	if err := c.ShouldBindJSON(&evidenceDetails); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Register the evidence via the evidence registration workflow service.
	if err := h.registrationService.RegisterEvidence(c.Request.Context(), evidenceDetails); err != nil {
		// Special case for evidence already exists error.
		if errors.Is(err, cerrors.ErrEvidenceAlreadyExists.Error) {
			c.JSON(cerrors.ErrEvidenceAlreadyExists.HTTPCode, gin.H{"error": cerrors.ErrEvidenceAlreadyExists.Error})
			return
		}

		// Other errors are considered as internal server errors.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "evidence registered successfully"})
}
