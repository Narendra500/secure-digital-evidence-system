package service

import (
	"audit-service/internal/cerrors"
	"audit-service/internal/repository"
	"audit-service/internal/store"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
)

type evidenceService struct {
	evidenceRepo repository.EvidenceRepo
}

func NewEvidenceService(evidenceRepo repository.EvidenceRepo) *evidenceService {
	return &evidenceService{evidenceRepo}
}

type VerifyEvidenceResult struct {
	Status string
}

func newTamperedEvidenceResult() *VerifyEvidenceResult {
	return &VerifyEvidenceResult{Status: "TAMPERED"}
}

func newValidEvidenceResult() *VerifyEvidenceResult {
	return &VerifyEvidenceResult{Status: "VALID"}
}

func newNotFoundEvidenceResult() *VerifyEvidenceResult {
	return &VerifyEvidenceResult{Status: "NOT_FOUND"}
}

func newHashingErrorEvidenceResult() *VerifyEvidenceResult {
	return &VerifyEvidenceResult{Status: "HASHING_ERROR"}
}

func newFileFetchingErrorEvidenceResult() *VerifyEvidenceResult {
	return &VerifyEvidenceResult{Status: "FILE_FETCHING_ERROR"}
}

func computeSHA256Hash(file io.ReadCloser) (string, error) {
	h := sha256.New()

	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// Checks if the evidence with given id has not been tampered with.
//
// #Returns
//
// nil, err if evidenceHash could not be fetched from the external evidence service.
//
// *VerifyEvidenceResult with status "TAMPERED" if evidence is tampered.
//
// *VerifyEvidenceResult with status "VALID" if evidence is valid.
//
// *VerifyEvidenceResult with status "NOT_FOUND" if evidence is not found.
//
// *VerifyEvidenceResult with status "HASHING_ERROR" if there is an error while hashing the evidence.
//
// *VerifyEvidenceResult with status "FILE_FETCHING_ERROR" if there is an error while fetching the evidence.
func (e *evidenceService) VerifyEvidence(ctx context.Context, evidenceId string) (*VerifyEvidenceResult, error) {
	httpClient := &http.Client{}
	fileFetcher := NewFileFetcher("http://localhost:8080", httpClient)

	// Get evidence hash
	var evidenceHash *store.EvidenceHash
	evidenceHash, err := e.evidenceRepo.GetEvidenceHash(ctx, evidenceId)
	if err != nil {
		return nil, err
	}

	// Fetch evidence file from external evidence service.
	file, err := fileFetcher.GetFile(ctx, evidenceId)
	if err != nil {
		if errors.Is(err, cerrors.ErrFileNotFound.Error) {
			return newNotFoundEvidenceResult(), cerrors.ErrFileNotFound.Error
		}
		return newFileFetchingErrorEvidenceResult(), err
	}
	defer file.Close()

	// Compute hash for the fetched evidence file.
	computedHash, err := computeSHA256Hash(file)
	if err != nil {
		return newHashingErrorEvidenceResult(), err
	}

	// Compare computed hash with the one stored in the database.
	if computedHash != evidenceHash.FileHash {
		return newTamperedEvidenceResult(), nil
	}

	// Evidence is valid.
	return newValidEvidenceResult(), nil
}
