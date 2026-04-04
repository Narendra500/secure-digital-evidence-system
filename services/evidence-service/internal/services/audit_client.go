package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// AuditRegistrationRequest 
type AuditRegistrationRequest struct {
	EvidenceID       int64                  `json:"evidence_id"`
	EvidencePublicID string                 `json:"evidence_public_id"`
	Algorithm        string                 `json:"algorithm"`
	FileHash         string                 `json:"file_hash"`
	CaseID           string                 `json:"case_id"`
	UserID           string                 `json:"user_id"`
	ActionType       int                    `json:"action_type"`
	Remarks          string                 `json:"remarks"`
	ActionMetadata   map[string]interface{} `json:"action_metadata"`
	ServiceName      string                 `json:"service_name"`
	IPAddress        string                 `json:"ip_address"`
}

type AuditClient struct {
	BaseURL string
	Client  *http.Client
}

func NewAuditClient() *AuditClient {
	return &AuditClient{
		BaseURL: os.Getenv("AUDIT_SERVICE_URL"),
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RegisterAudit sends metadata to the Audit Service
func (c *AuditClient) RegisterAudit(ctx context.Context, req AuditRegistrationRequest) error {
	if c.BaseURL == "" {
		return fmt.Errorf("AUDIT_SERVICE_URL not configured")
	}

	url := fmt.Sprintf("%s/api/v1/evidence/register", c.BaseURL)
	jsonData, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("audit service returned status %d", resp.StatusCode)
	}

	return nil
}
