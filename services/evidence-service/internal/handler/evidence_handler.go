package handler

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"evidence-service/internal/models"
	"evidence-service/internal/services"
	"evidence-service/internal/store"

	"github.com/gorilla/mux"
)

type EvidenceHandler struct {
	Store       *store.Storage
	S3Client    *services.S3Client
	AuditClient *services.AuditClient
	Signer      services.Signer
}

// CreateEvidence handles multipart file uploads to S3
func (h *EvidenceHandler) CreateEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ctx.Value("claims").(*models.Claims)
	if !ok {
		http.Error(w, "Failed to get claims from the token", http.StatusInternalServerError)
		return
	}
	userPublicID := claims.Subject

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
	caseResp, err := services.ValidateCase(casePublicID, token)
	if err != nil {
		log.Printf("Case validation failed: %v", err)
		http.Error(w, `{"error":"case not found or invalid"}`, http.StatusNotFound)
		return
	}

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
	s3VersionID, err := h.S3Client.UploadFile(context.TODO(), s3Key, file)
	if err != nil {
		log.Printf("S3 upload error: %v", err)
		http.Error(w, `{"error":"failed to upload file to S3"}`, http.StatusInternalServerError)
		return
	}

	// Resolve user public_id (UUID) to internal bigint ID
	var userInternalID int64
	err = h.Store.DB.Get(&userInternalID,
		`SELECT id FROM auth_schema.users WHERE public_id = $1`, userPublicID)
	if err != nil {
		log.Printf("Failed to resolve user internal ID: %v", err)
		http.Error(w, `{"error":"user not found"}`, http.StatusBadRequest)
		return
	}

	// Detect MIME type from file header
	mimeType := fileHeader.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Insert into DB — capture the internal BIGINT ID for the audit service
	var insertedID int64
	var insertedPublicID string
	err = h.Store.DB.QueryRow(
		`INSERT INTO evidence
		(case_id, file_name, mime_type, file_size, storage_path, current_hash, uploaded_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, public_id`,
		caseResp.ID,
		fileHeader.Filename,
		mimeType,
		fileHeader.Size,
		s3Key,
		hash,
		userInternalID,
	).Scan(&insertedID, &insertedPublicID)

	if err != nil {
		log.Printf("DB insert error: %v", err)
		http.Error(w, `{"error":"failed to store evidence metadata"}`, http.StatusInternalServerError)
		return
	}

	// Record initial version in evidence_versions table
	_, err = h.Store.DB.Exec(
		`INSERT INTO evidence_schema.evidence_versions
		(evidence_id, s3_version_id, file_hash, file_size, is_current, created_by)
		VALUES ($1, $2, $3, $4, true, $5)`,
		insertedID, s3VersionID, hash, fileHeader.Size, userInternalID,
	)
	if err != nil {
		log.Printf("Warning: failed to record evidence version: %v", err)
	}

	// 5. Register with Audit Service (Audit flow)
	var userName string
	_ = h.Store.DB.Get(&userName, `SELECT name FROM auth_schema.users WHERE id = $1`, userInternalID)
	if userName == "" {
		userName = "User"
	}

	metadata := map[string]any{
		"file_name":      fileHeader.Filename,
		"file_size":      fileHeader.Size,
		"file_hash":      hash,
		"case_title":     caseResp.Title,
		"case_public_id": caseResp.PublicID,
		"user_name":      userName,
		"user_public_id": userPublicID,
	}
	metadataJSON, _ := json.Marshal(metadata)
	metadataStr := string(metadataJSON)
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
	}
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	go func() {
		auditReq := services.AuditRegistrationRequest{
			EvidenceID:       insertedID,
			EvidencePublicID: insertedPublicID,
			Algorithm:        "SHA256",
			FileHash:         hash,
			CaseID:           caseResp.ID,
			UserID:           userInternalID,
			Action:           "UPLOAD",
			ActionMetadata:   metadataStr,
			Remarks:          fmt.Sprintf("Uploaded '%s' to case '%s' by %s", fileHeader.Filename, caseResp.Title, userName),
			ServiceName:      "evidence-service",
			IPAddress:        clientIP,
		}

		h.Store.DB.Get(&auditReq.EvidencePublicID, "SELECT public_id FROM evidence WHERE id = $1", insertedID)

		err := h.AuditClient.RegisterAudit(context.Background(), auditReq)
		if err != nil {
			log.Printf("CRITICAL: Failed to register evidence with Audit Service: %v", err)
		} else {
			log.Printf("Successfully registered audit for evidence ID %d", insertedID)
		}
	}()

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
	ctx := r.Context()
	claims, ok := ctx.Value("claims").(*models.Claims)
	if !ok {
		http.Error(w, "Failed to get claims from the token", http.StatusInternalServerError)
		return
	}
	userPublicID := claims.Subject

	vars := mux.Vars(r)
	evidencePublicID := vars["id"]

	// Look up evidence record
	var evidence models.Evidence
	err := h.Store.DB.Get(&evidence,
		`SELECT e.id, e.public_id, c.public_id AS case_id, e.file_name, e.file_size, e.storage_path,
		        e.current_hash, e.uploaded_by, e.uploaded_at
		 FROM evidence e
		 JOIN case_schema.cases c ON c.id = e.case_id
		 WHERE e.public_id = $1`,
		evidencePublicID,
	)
	if err != nil {
		http.Error(w, `{"error":"evidence not found"}`, http.StatusNotFound)
		return
	}

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

	// Serve with metadata headers
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, evidence.FileName))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", evidence.FileSize))
	io.Copy(w, body)
}

// StreamEvidenceFile implements GET /evidence/{id}/file
// Returns raw binary stream with no additional headers or buffering
func (h *EvidenceHandler) StreamEvidenceFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ctx.Value("claims").(*models.Claims)
	if !ok {
		http.Error(w, "Failed to get claims from the token", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	evidencePublicID := vars["id"]

	// 1. Look up storage path
	var evidence models.Evidence
	err := h.Store.DB.Get(&evidence,
		`SELECT e.id, c.public_id AS case_id, e.storage_path
		 FROM evidence e
		 JOIN case_schema.cases c ON c.id = e.case_id
		 WHERE e.public_id = $1`,
		evidencePublicID,
	)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 2. Security Check only for user requests.
	if claims.TokenType == "user" {
		userPublicID, err := claims.GetSubject()
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		hasAccess, err := services.CheckUserCaseAccess(evidence.CaseID, userPublicID, token)
		if err != nil || !hasAccess {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
	}

	// 3. Connect to S3 stream
	body, err := h.S3Client.DownloadFile(context.TODO(), evidence.StoragePath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer body.Close()

	// 5. Pipe the binary stream directly to the response (No buffering)
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, body)
}

// ListEvidence returns all evidence for a given case
func (h *EvidenceHandler) ListEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ctx.Value("claims").(*models.Claims)
	if !ok {
		http.Error(w, "Failed to get claims from the token", http.StatusInternalServerError)
		return
	}
	userPublicID := claims.Subject

	casePublicID := r.URL.Query().Get("case_id")
	if casePublicID == "" {
		http.Error(w, `{"error":"case_id query parameter is required"}`, http.StatusBadRequest)
		return
	}

	// Extract token for inter-service calls
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	// Validate case exists via case service
	caseResp, err := services.ValidateCase(casePublicID, token)
	if err != nil {
		log.Printf("Case validation failed: %v", err)
		http.Error(w, `{"error":"case not found or invalid"}`, http.StatusNotFound)
		return
	}

	// Check access control
	hasAccess, err := services.CheckUserCaseAccess(casePublicID, userPublicID, token)
	if err != nil || !hasAccess {
		http.Error(w, `{"error":"access denied: user not assigned to this case"}`, http.StatusForbidden)
		return
	}

	// Fetch evidence records
	var evidenceList []models.Evidence
	err = h.Store.DB.Select(&evidenceList,
		`SELECT e.id, e.public_id, c.public_id AS case_id, e.file_name, e.file_size,
		        e.storage_path, e.current_hash, e.uploaded_by, e.uploaded_at
		 FROM evidence e
		 JOIN case_schema.cases c ON c.id = e.case_id
		 WHERE e.case_id = $1
		 ORDER BY e.uploaded_at DESC`,
		caseResp.ID,
	)
	if err != nil {
		log.Printf("DB select error: %v", err)
		http.Error(w, `{"error":"failed to fetch evidence"}`, http.StatusInternalServerError)
		return
	}

	if evidenceList == nil {
		evidenceList = []models.Evidence{}
	} else {
		var evidenceIDs = make([]int64, len(evidenceList))
		for i, evidence := range evidenceList {
			evidenceIDs[i] = evidence.ID
		}

		auditClient := services.NewAuditClient()

		evidenceStatuses, err := auditClient.GetEvidenceStatus(ctx, evidenceIDs)
		if err != nil {
			log.Printf("Audit service call for evidence status failed, %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		evidenceStatusesMap := make(map[int64]models.EvidenceStatus)
		for _, evidence := range evidenceStatuses {
			evidenceStatusesMap[evidence.EvidenceID] = evidence
		}

		for i, evidence := range evidenceList {
			evidenceList[i].CurrentHash = evidenceStatusesMap[evidence.ID].CurrentHash
			evidenceList[i].Status = evidenceStatusesMap[evidence.ID].Status
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(evidenceList)
}

// RevertEvidence handles reverting a tampered evidence file to its previous known-good version.
// POST /api/v1/evidence/{id}/revert
func (h *EvidenceHandler) RevertEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ctx.Value("claims").(*models.Claims)
	if !ok {
		http.Error(w, `{"error":"failed to get claims from token"}`, http.StatusUnauthorized)
		return
	}
	userPublicID := claims.Subject

	vars := mux.Vars(r)
	evidencePublicID := vars["id"]
	if evidencePublicID == "" {
		http.Error(w, `{"error":"evidence ID is required"}`, http.StatusBadRequest)
		return
	}

	// 1. Look up evidence record
	var evidence models.Evidence
	err := h.Store.DB.Get(&evidence,
		`SELECT e.id, e.public_id, c.public_id AS case_id, e.file_name, e.file_size, e.storage_path,
		        e.current_hash, e.uploaded_by, e.uploaded_at
		 FROM evidence_schema.evidence e
		 JOIN case_schema.cases c ON c.id = e.case_id
		 WHERE e.public_id = $1`,
		evidencePublicID,
	)
	if err != nil {
		http.Error(w, `{"error":"evidence not found"}`, http.StatusNotFound)
		return
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	// 2. Check access to case
	hasAccess, err := services.CheckUserCaseAccess(evidence.CaseID, userPublicID, token)
	if err != nil || !hasAccess {
		http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
		return
	}

	// 3. Resolve user internal ID and name
	var userInternalID int64
	var userName string
	err = h.Store.DB.QueryRow(
		`SELECT id, name FROM auth_schema.users WHERE public_id = $1`, userPublicID,
	).Scan(&userInternalID, &userName)
	if err != nil {
		http.Error(w, `{"error":"user not found"}`, http.StatusBadRequest)
		return
	}
	if userName == "" {
		userName = "User"
	}

	// 4. Find the original known-good version
	// First check evidence_versions table
	var versions []models.EvidenceVersion
	_ = h.Store.DB.Select(&versions,
		`SELECT id, evidence_id, s3_version_id, file_hash, file_size, is_current, created_by, created_at
		 FROM evidence_schema.evidence_versions
		 WHERE evidence_id = $1
		 ORDER BY created_at ASC`,
		evidence.ID,
	)

	var targetVersionID string
	var targetHash string
	var targetSize int64

	// If versions exist in DB, look for the first (original upload) version
	if len(versions) > 0 {
		targetVersionID = versions[0].S3VersionID
		targetHash = versions[0].FileHash
		targetSize = versions[0].FileSize
	}

	// If no version found in DB or version ID empty, check S3 version history
	if targetVersionID == "" {
		s3Versions, err := h.S3Client.ListObjectVersions(ctx, evidence.StoragePath)
		if err != nil || len(s3Versions) == 0 {
			log.Printf("Failed to list S3 versions: %v", err)
			http.Error(w, `{"error":"no S3 version history found for this evidence file"}`, http.StatusNotFound)
			return
		}

		// S3 versions are ordered newest to oldest. Look for the oldest version.
		for i := len(s3Versions) - 1; i >= 0; i-- {
			v := s3Versions[i]
			if v.VersionId != nil && *v.VersionId != "" {
				body, err := h.S3Client.DownloadFileVersion(ctx, evidence.StoragePath, *v.VersionId)
				if err == nil {
					hasher := sha256.New()
					if size, copyErr := io.Copy(hasher, body); copyErr == nil {
						body.Close()
						computed := hex.EncodeToString(hasher.Sum(nil))
						targetVersionID = *v.VersionId
						targetHash = computed
						targetSize = size
						break
					}
					body.Close()
				}
			}
		}
	}

	if targetVersionID == "" {
		http.Error(w, `{"error":"unable to find a previous valid version to revert to"}`, http.StatusBadRequest)
		return
	}

	// 5. Restore the version in S3 by copying it over the current object (creates a new current S3 version)
	newVersionID, err := h.S3Client.CopyVersion(ctx, evidence.StoragePath, targetVersionID)
	if err != nil {
		// Fallback: download the historical version stream and upload it
		body, dlErr := h.S3Client.DownloadFileVersion(ctx, evidence.StoragePath, targetVersionID)
		if dlErr != nil {
			log.Printf("Failed to copy/download version: %v", err)
			http.Error(w, `{"error":"failed to restore file in S3"}`, http.StatusInternalServerError)
			return
		}
		defer body.Close()
		newVersionID, err = h.S3Client.UploadFile(ctx, evidence.StoragePath, body)
		if err != nil {
			log.Printf("Failed to re-upload restored version: %v", err)
			http.Error(w, `{"error":"failed to restore file in S3"}`, http.StatusInternalServerError)
			return
		}
	}

	// 6. Update database records
	// Update evidence table
	_, err = h.Store.DB.Exec(
		`UPDATE evidence_schema.evidence
		 SET current_hash = $1, file_size = $2
		 WHERE id = $3`,
		targetHash, targetSize, evidence.ID,
	)
	if err != nil {
		log.Printf("DB update error on revert: %v", err)
		http.Error(w, `{"error":"failed to update evidence metadata"}`, http.StatusInternalServerError)
		return
	}

	// Update evidence_versions table
	_, _ = h.Store.DB.Exec(
		`UPDATE evidence_schema.evidence_versions SET is_current = false WHERE evidence_id = $1`,
		evidence.ID,
	)
	_, _ = h.Store.DB.Exec(
		`INSERT INTO evidence_schema.evidence_versions
		 (evidence_id, s3_version_id, file_hash, file_size, is_current, created_by)
		 VALUES ($1, $2, $3, $4, true, $5)`,
		evidence.ID, newVersionID, targetHash, targetSize, userInternalID,
	)

	// 7. Register REVERT with Audit Service (audit log + custody log + update evidence hash)
	var caseTitle string
	var caseInternalID int64
	_ = h.Store.DB.QueryRow(`SELECT id, title FROM case_schema.cases WHERE public_id = $1`, evidence.CaseID).Scan(&caseInternalID, &caseTitle)

	metadata := map[string]any{
		"file_name":         evidence.FileName,
		"file_size":         targetSize,
		"file_hash":         targetHash,
		"reverted_from":     evidence.CurrentHash,
		"restored_hash":     targetHash,
		"source_version_id": targetVersionID,
		"new_version_id":    newVersionID,
		"case_title":        caseTitle,
		"case_public_id":    evidence.CaseID,
		"user_name":         userName,
		"user_public_id":    userPublicID,
	}
	metadataJSON, _ := json.Marshal(metadata)
	metadataStr := string(metadataJSON)

	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
	}
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	go func() {
		auditReq := services.AuditRegistrationRequest{
			EvidenceID:       evidence.ID,
			EvidencePublicID: evidence.PublicID,
			Algorithm:        "SHA256",
			FileHash:         targetHash,
			CaseID:           caseInternalID,
			UserID:           userInternalID,
			Action:           "REVERT",
			ActionMetadata:   metadataStr,
			Remarks:          fmt.Sprintf("Reverted '%s' to original version (SHA-256: %s) by %s", evidence.FileName, targetHash, userName),
			ServiceName:      "evidence-service",
			IPAddress:        clientIP,
		}

		err := h.AuditClient.RegisterAudit(context.Background(), auditReq)
		if err != nil {
			log.Printf("CRITICAL: Failed to register revert with Audit Service: %v", err)
		} else {
			log.Printf("Successfully registered REVERT audit for evidence ID %d", evidence.ID)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "reverted",
		"message":       "Evidence successfully reverted to previous known-good version",
		"file":          evidence.FileName,
		"restored_hash": targetHash,
		"reverted_from": evidence.CurrentHash,
		"size":          targetSize,
	})
}

// ExportCaseEvidence packages all evidence for a case into a cryptographically signed ZIP archive
func (h *EvidenceHandler) ExportCaseEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ctx.Value("claims").(*models.Claims)
	if !ok {
		http.Error(w, `{"error":"failed to get claims from the token"}`, http.StatusInternalServerError)
		return
	}
	userPublicID := claims.Subject

	vars := mux.Vars(r)
	casePublicID := vars["case_id"]
	if casePublicID == "" {
		casePublicID = r.URL.Query().Get("case_id")
	}
	if casePublicID == "" {
		http.Error(w, `{"error":"case_id is required"}`, http.StatusBadRequest)
		return
	}

	// Extract token for inter-service calls
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	// Validate case exists via case service
	caseResp, err := services.ValidateCase(casePublicID, token)
	if err != nil {
		log.Printf("Case validation failed: %v", err)
		http.Error(w, `{"error":"case not found or invalid"}`, http.StatusNotFound)
		return
	}

	// Check access control
	hasAccess, err := services.CheckUserCaseAccess(casePublicID, userPublicID, token)
	if err != nil || !hasAccess {
		http.Error(w, `{"error":"access denied: user not assigned to this case"}`, http.StatusForbidden)
		return
	}

	// Fetch all evidence records for this case
	var evidenceList []models.Evidence
	err = h.Store.DB.Select(&evidenceList,
		`SELECT e.id, e.public_id, c.public_id AS case_id, e.file_name, e.file_size,
		        e.storage_path, e.current_hash, e.mime_type, e.uploaded_by, e.uploaded_at
		 FROM evidence e
		 JOIN case_schema.cases c ON c.id = e.case_id
		 WHERE e.case_id = $1
		 ORDER BY e.uploaded_at ASC`,
		caseResp.ID,
	)
	if err != nil {
		log.Printf("DB select error for export: %v", err)
		http.Error(w, `{"error":"failed to fetch evidence for export"}`, http.StatusInternalServerError)
		return
	}

	// Prepare HTTP response headers for zip streaming
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"case_%s_evidence.zip\"", casePublicID))

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	// Track filename counts for collision avoidance
	nameCount := make(map[string]int)
	for _, ev := range evidenceList {
		nameCount[ev.FileName]++
	}

	usedPaths := make(map[string]bool)
	var manifestFiles []models.EvidenceManifestFile

	// 1. Stream each evidence file into evidence/ in the ZIP
	for _, ev := range evidenceList {
		filename := ev.FileName
		// Disambiguate if duplicate filename exists in case
		if nameCount[ev.FileName] > 1 || usedPaths[filename] {
			filename = fmt.Sprintf("%s_%s", ev.PublicID[:8], ev.FileName)
		}
		usedPaths[filename] = true
		relPath := fmt.Sprintf("evidence/%s", filename)

		body, err := h.S3Client.DownloadFile(ctx, ev.StoragePath)
		if err != nil {
			log.Printf("Failed to download evidence %s from S3: %v", ev.PublicID, err)
			continue
		}

		entryWriter, err := zipWriter.Create(relPath)
		if err != nil {
			body.Close()
			log.Printf("Failed to create zip entry for %s: %v", relPath, err)
			continue
		}

		// Compute SHA-256 while streaming into the zip entry
		hasher := sha256.New()
		multiWriter := io.MultiWriter(entryWriter, hasher)
		bytesCopied, err := io.Copy(multiWriter, body)
		body.Close()
		if err != nil {
			log.Printf("Error streaming evidence %s into zip: %v", ev.PublicID, err)
			continue
		}

		computedHash := hex.EncodeToString(hasher.Sum(nil))
		isTampered := (computedHash != ev.CurrentHash)

		manifestFiles = append(manifestFiles, models.EvidenceManifestFile{
			EvidencePublicID: ev.PublicID,
			FileName:         ev.FileName,
			Path:             relPath,
			FileSize:         bytesCopied,
			SHA256:           computedHash,
			RecordedHash:     ev.CurrentHash,
			Tampered:         isTampered,
			MimeType:         ev.MimeType,
			UploadedAt:       ev.UploadedAt,
		})
	}

	// 2. Fetch all logs for the evidences in this case and write logs.json
	caseLogs := h.fetchCaseLogs(ctx, casePublicID, caseResp.ID, evidenceList, caseResp.Title)
	logsJSON, err := json.MarshalIndent(caseLogs, "", "  ")
	if err != nil {
		log.Printf("Warning: failed to marshal case logs to JSON: %v", err)
	} else {
		logsEntry, err := zipWriter.Create("logs.json")
		if err != nil {
			log.Printf("Warning: failed to create logs.json entry in zip: %v", err)
		} else {
			logsHasher := sha256.New()
			logsMultiWriter := io.MultiWriter(logsEntry, logsHasher)
			bytesWritten, err := logsMultiWriter.Write(logsJSON)
			if err != nil {
				log.Printf("Warning: failed to write logs.json to zip: %v", err)
			} else {
				logsHash := hex.EncodeToString(logsHasher.Sum(nil))
				manifestFiles = append(manifestFiles, models.EvidenceManifestFile{
					FileName:     "logs.json",
					Path:         "logs.json",
					FileSize:     int64(bytesWritten),
					SHA256:       logsHash,
					RecordedHash: logsHash,
					Tampered:     false,
					MimeType:     "application/json",
					UploadedAt:   time.Now().UTC(),
				})
			}
		}
	}

	// 3. Build manifest.json
	manifest := models.EvidenceManifest{
		System:  "Secure Digital Evidence System (SDES)",
		Version: "1.0",
		Case: models.EvidenceManifestCase{
			PublicID: casePublicID,
			Title:    caseResp.Title,
		},
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		ExportedBy: models.EvidenceManifestExportedBy{
			UserPublicID: userPublicID,
		},
		HashAlgorithm: "sha256",
		LogsFile:      "logs.json",
		FileCount:     len(manifestFiles),
		Files:         manifestFiles,
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal manifest JSON: %v", err)
		return
	}

	// 4. Cryptographically sign manifest.json
	var signature []byte
	if h.Signer != nil {
		sig, err := h.Signer.Sign(manifestJSON)
		if err != nil {
			log.Printf("Warning: failed to sign manifest: %v", err)
		} else {
			signature = sig
		}
	}

	// 5. Write manifest.json to zip root
	manifestEntry, err := zipWriter.Create("manifest.json")
	if err == nil {
		_, _ = manifestEntry.Write(manifestJSON)
	}

	// 6. Write manifest.sig to zip root
	if len(signature) > 0 {
		sigEntry, err := zipWriter.Create("manifest.sig")
		if err == nil {
			_, _ = sigEntry.Write(signature)
		}
	}

	log.Printf("Exported case %s with %d evidence files and logs.json into ZIP", casePublicID, len(manifestFiles))
}

func (h *EvidenceHandler) fetchCaseLogs(ctx context.Context, casePublicID string, caseInternalID int64, evidenceList []models.Evidence, caseTitle string) models.CaseLogsExport {
	logsExport := models.CaseLogsExport{
		System:           "Secure Digital Evidence System (SDES)",
		CasePublicID:     casePublicID,
		CaseTitle:        caseTitle,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		EvidenceCount:    len(evidenceList),
		Evidences:        make([]models.EvidenceLogsItem, 0),
		AllAuditLogs:     make([]models.ExportAuditLog, 0),
		AllCustodyLogs:   make([]models.ExportCustodyLog, 0),
	}

	// 1. Fetch audit logs (via AuditClient or fallback to DB)
	var auditLogs []models.ExportAuditLog
	if h.AuditClient != nil {
		logs, err := h.AuditClient.GetAuditLogs(ctx, casePublicID, "")
		if err == nil {
			auditLogs = logs
		} else {
			log.Printf("Warning: failed to fetch audit logs via AuditClient: %v. Falling back to DB.", err)
		}
	}

	if len(auditLogs) == 0 && h.Store != nil && h.Store.DB != nil {
		rows, err := h.Store.DB.QueryContext(ctx, `
			SELECT 
				al.public_id::text,
				COALESCE(eh.evidence_public_id::text, ''),
				COALESCE(al.request_id::text, ''),
				COALESCE(al.previous_hash, ''),
				al.current_hash,
				COALESCE(a.name, 'UNKNOWN'),
				al.service_name,
				al.ip_address::text,
				al.status::text,
				COALESCE(al.details, '{}'::jsonb),
				al.created_at
			FROM integrity_schema.audit_logs al
			LEFT JOIN integrity_schema.actions a ON al.action_type = a.id
			LEFT JOIN integrity_schema.evidence_hashes eh ON al.evidence_id = eh.evidence_id
			WHERE al.case_id = $1
			ORDER BY al.created_at ASC
		`, caseInternalID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l models.ExportAuditLog
				var detailsJSON []byte
				if err := rows.Scan(
					&l.PublicID,
					&l.EvidencePublicID,
					&l.RequestID,
					&l.PreviousHash,
					&l.CurrentHash,
					&l.Action,
					&l.ServiceName,
					&l.IPAddress,
					&l.Status,
					&detailsJSON,
					&l.CreatedAt,
				); err == nil {
					if len(detailsJSON) > 0 {
						_ = json.Unmarshal(detailsJSON, &l.Details)
						if fn, ok := l.Details["file_name"].(string); ok {
							l.EvidenceName = fn
						}
					}
					l.CasePublicID = casePublicID
					l.CaseTitle = caseTitle
					auditLogs = append(auditLogs, l)
				}
			}
		}
	}

	// 2. Fetch custody logs (via AuditClient or fallback to DB)
	var custodyLogs []models.ExportCustodyLog
	if h.AuditClient != nil {
		logs, err := h.AuditClient.GetCustodyLogs(ctx, casePublicID, "")
		if err == nil {
			custodyLogs = logs
		} else {
			log.Printf("Warning: failed to fetch custody logs via AuditClient: %v. Falling back to DB.", err)
		}
	}

	if len(custodyLogs) == 0 && h.Store != nil && h.Store.DB != nil {
		rows, err := h.Store.DB.QueryContext(ctx, `
			SELECT 
				c.public_id::text,
				COALESCE(eh.evidence_public_id::text, ''),
				COALESCE(a.name, 'UNKNOWN'),
				COALESCE(c.action_metadata, '{}'::jsonb),
				c.remarks,
				c.timestamp
			FROM integrity_schema.custody_logs c
			LEFT JOIN integrity_schema.actions a ON c.action_type = a.id
			LEFT JOIN integrity_schema.evidence_hashes eh ON c.evidence_id = eh.evidence_id
			WHERE c.case_id = $1
			ORDER BY c.timestamp ASC
		`, caseInternalID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l models.ExportCustodyLog
				var metaJSON []byte
				if err := rows.Scan(
					&l.PublicID,
					&l.EvidencePublicID,
					&l.Action,
					&metaJSON,
					&l.Remarks,
					&l.Timestamp,
				); err == nil {
					if len(metaJSON) > 0 {
						_ = json.Unmarshal(metaJSON, &l.ActionMetadata)
						if fn, ok := l.ActionMetadata["file_name"].(string); ok {
							l.EvidenceName = fn
						}
					}
					l.CasePublicID = casePublicID
					l.CaseTitle = caseTitle
					custodyLogs = append(custodyLogs, l)
				}
			}
		}
	}

	logsExport.AllAuditLogs = auditLogs
	logsExport.TotalAuditLogs = len(auditLogs)
	logsExport.AllCustodyLogs = custodyLogs
	logsExport.TotalCustodyLogs = len(custodyLogs)

	// Map logs to individual evidences
	auditByEvidence := make(map[string][]models.ExportAuditLog)
	for _, l := range auditLogs {
		if l.EvidencePublicID != "" {
			auditByEvidence[l.EvidencePublicID] = append(auditByEvidence[l.EvidencePublicID], l)
		}
	}

	custodyByEvidence := make(map[string][]models.ExportCustodyLog)
	for _, l := range custodyLogs {
		if l.EvidencePublicID != "" {
			custodyByEvidence[l.EvidencePublicID] = append(custodyByEvidence[l.EvidencePublicID], l)
		}
	}

	for _, ev := range evidenceList {
		evAudits := auditByEvidence[ev.PublicID]
		if evAudits == nil {
			evAudits = []models.ExportAuditLog{}
		}
		evCustody := custodyByEvidence[ev.PublicID]
		if evCustody == nil {
			evCustody = []models.ExportCustodyLog{}
		}

		logsExport.Evidences = append(logsExport.Evidences, models.EvidenceLogsItem{
			EvidencePublicID: ev.PublicID,
			FileName:         ev.FileName,
			CurrentHash:      ev.CurrentHash,
			AuditLogs:        evAudits,
			CustodyLogs:      evCustody,
		})
	}

	return logsExport
}
