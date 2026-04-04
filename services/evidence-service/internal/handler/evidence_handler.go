package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"evidence-service/internal/middleware"
	"evidence-service/internal/models"
	"evidence-service/internal/services"
	"evidence-service/internal/store"

	"github.com/gorilla/mux"
)

type EvidenceHandler struct {
	Store       *store.Storage
	S3Client    *services.S3Client
	AuditClient *services.AuditClient
}

// CreateEvidence handles multipart file uploads to S3
func (h *EvidenceHandler) CreateEvidence(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (10MB max)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, `{"error":"file too large"}`, http.StatusBadRequest)
		return
	}

	casePublicID := r.FormValue("case_id")
	if casePublicID == "" {
		http.Error(w, `{"error":"case_id is required"}`, http.StatusBadRequest)
		return
	}

	// Get file from multipart
	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"file is required"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Extract token for inter-service calls
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	// Validate case exists via case service
	_, err = services.ValidateCase(casePublicID, token)
	if err != nil {
		log.Printf("Case validation failed: %v", err)
		http.Error(w, `{"error":"case not found or invalid"}`, http.StatusNotFound)
		return
	}

	// Get user public_id from JWT context (UUID)
	userPublicID := r.Context().Value(middleware.UserIDKey).(string)

	// Check user has access to this case
	hasAccess, err := services.CheckUserCaseAccess(casePublicID, userPublicID, token)
	if err != nil || !hasAccess {
		http.Error(w, `{"error":"access denied: user not assigned to this case"}`, http.StatusForbidden)
		return
	}

	// Generate SHA256 hash of file content
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		http.Error(w, `{"error":"error hashing file"}`, http.StatusInternalServerError)
		return
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Reset file pointer after hashing
	if _, err := file.Seek(0, 0); err != nil {
		http.Error(w, `{"error":"failed to seek file"}`, http.StatusInternalServerError)
		return
	}

	// Upload to S3
	s3Key := fmt.Sprintf("%s_%s", hash, fileHeader.Filename)
	err = h.S3Client.UploadFile(context.TODO(), s3Key, file)
	if err != nil {
		log.Printf("S3 upload error: %v", err)
		http.Error(w, `{"error":"failed to upload file to S3"}`, http.StatusInternalServerError)
		return
	}

	// Insert into DB — capture the internal BIGINT ID for the audit service
	var insertedID int64
	err = h.Store.DB.QueryRow(
		`INSERT INTO evidence_schema.evidence
		(case_id, file_name, file_size, storage_path, current_hash, uploaded_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		casePublicID,
		fileHeader.Filename,
		fileHeader.Size,
		s3Key,
		hash,
		userPublicID,
	).Scan(&insertedID)

	if err != nil {
		log.Printf("DB insert error: %v", err)
		http.Error(w, `{"error":"failed to store evidence metadata"}`, http.StatusInternalServerError)
		return
	}

	// 5. Register with Audit Service (Audit flow)
	// We do this in a separate goroutine or handle errors non-fatally to avoid blocking the user
	go func() {
		auditReq := services.AuditRegistrationRequest{
			EvidenceID:       insertedID,
			EvidencePublicID: "", 
			Algorithm:        "SHA256",
			FileHash:         hash,
			CaseID:           casePublicID,
			UserID:           userPublicID,
			ActionType:       1, // 1 = UPLOAD
			Remarks:          "Initial upload registered for AuditTrail",
			ServiceName:      "evidence-service",
			IPAddress:        r.RemoteAddr,
		}
		
		h.Store.DB.Get(&auditReq.EvidencePublicID, "SELECT public_id FROM evidence_schema.evidence WHERE id = $1", insertedID)

		err := h.AuditClient.RegisterAudit(context.Background(), auditReq)
		if err != nil {
			log.Printf("CRITICAL: Failed to register evidence with Audit Service: %v", err)
		} else {
			log.Printf("Successfully registered audit for evidence ID %d", insertedID)
		}
	}()

	// Log upload access locally
	_, _ = h.Store.DB.Exec(
		`INSERT INTO evidence_access_log (evidence_id, user_id, action, via_service)
		 VALUES ($1, (SELECT id FROM users WHERE public_id = $2), 'UPLOAD', 'evidence-service')`,
		insertedID, userPublicID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "uploaded",
		"hash":   hash,
		"file":   fileHeader.Filename,
		"size":   fileHeader.Size,
		"s3_key": s3Key,
	})
}

// GetEvidence handles downloading evidence from S3 with metadata headers
func (h *EvidenceHandler) GetEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	evidencePublicID := vars["id"]

	// Look up evidence record
	var evidence models.Evidence
	err := h.Store.DB.Get(&evidence,
		`SELECT id, public_id, case_id, file_name, file_size, storage_path,
		        current_hash, uploaded_by, uploaded_at
		 FROM evidence_schema.evidence WHERE public_id = $1`,
		evidencePublicID,
	)
	if err != nil {
		http.Error(w, `{"error":"evidence not found"}`, http.StatusNotFound)
		return
	}

	// Get user from JWT
	userPublicID := r.Context().Value(middleware.UserIDKey).(string)
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	// Check access
	hasAccess, err := services.CheckUserCaseAccess(evidence.CaseID, userPublicID, token)
	if err != nil || !hasAccess {
		http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
		return
	}

	// Download from S3
	body, err := h.S3Client.DownloadFile(context.TODO(), evidence.StoragePath)
	if err != nil {
		log.Printf("S3 download error: %v", err)
		http.Error(w, `{"error":"failed to fetch from S3"}`, http.StatusInternalServerError)
		return
	}
	defer body.Close()

	// Audit log
	_, _ = h.Store.DB.Exec(
		`INSERT INTO evidence_access_log (evidence_id, user_id, action, via_service)
		 VALUES ($1, (SELECT id FROM users WHERE public_id = $2), 'DOWNLOAD', 'evidence-service')`,
		evidence.ID, userPublicID,
	)

	// Serve with metadata headers
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, evidence.FileName))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", evidence.FileSize))
	io.Copy(w, body)
}

// StreamEvidenceFile implements GET /evidence/{id}/file
// Returns raw binary stream with no additional headers or buffering
func (h *EvidenceHandler) StreamEvidenceFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	evidencePublicID := vars["id"]

	// 1. Look up storage path
	var evidence models.Evidence
	err := h.Store.DB.Get(&evidence,
		`SELECT id, case_id, storage_path FROM evidence_schema.evidence WHERE public_id = $1`,
		evidencePublicID,
	)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 2. Security Check (Mandatory!)
	userPublicID := r.Context().Value(middleware.UserIDKey).(string)
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	hasAccess, err := services.CheckUserCaseAccess(evidence.CaseID, userPublicID, token)
	if err != nil || !hasAccess {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 3. Connect to S3 stream
	body, err := h.S3Client.DownloadFile(context.TODO(), evidence.StoragePath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer body.Close()

	// 4. Log the streaming access
	_, _ = h.Store.DB.Exec(
		`INSERT INTO evidence_access_log (evidence_id, user_id, action, via_service)
		 VALUES ($1, (SELECT id FROM users WHERE public_id = $2), 'STREAM', 'evidence-service')`,
		evidence.ID, userPublicID,
	)

	// 5. Pipe the binary stream directly to the response (No buffering)
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, body)
}

// ListEvidence returns all evidence for a given case
func (h *EvidenceHandler) ListEvidence(w http.ResponseWriter, r *http.Request) {

	casePublicID := r.URL.Query().Get("case_id")
	if casePublicID == "" {
		http.Error(w, `{"error":"case_id query parameter is required"}`, http.StatusBadRequest)
		return
	}

	// Get user from JWT
	userPublicID := r.Context().Value(middleware.UserIDKey).(string)

	// Extract token for inter-service calls
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	// Validate case and check access control
	hasAccess, err := services.CheckUserCaseAccess(casePublicID, userPublicID, token)
	if err != nil || !hasAccess {
		http.Error(w, `{"error":"access denied: user not assigned to this case"}`, http.StatusForbidden)
		return
	}

	// Fetch evidence records
	var evidenceList []models.Evidence
	err = h.Store.DB.Select(&evidenceList,
		`SELECT id, public_id, case_id, file_name, file_size,
		        storage_path, current_hash, uploaded_by, uploaded_at
		 FROM evidence_schema.evidence
		 WHERE case_id = $1
		 ORDER BY uploaded_at DESC`,
		casePublicID,
	)
	if err != nil {
		log.Printf("DB select error: %v", err)
		http.Error(w, `{"error":"failed to fetch evidence"}`, http.StatusInternalServerError)
		return
	}

	if evidenceList == nil {
		evidenceList = []models.Evidence{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(evidenceList)
}