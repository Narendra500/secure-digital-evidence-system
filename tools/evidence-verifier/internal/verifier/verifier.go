package verifier

import (
	"archive/zip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ManifestFile struct {
	EvidencePublicID string    `json:"evidence_public_id"`
	FileName         string    `json:"file_name"`
	Path             string    `json:"path"`
	FileSize         int64     `json:"file_size"`
	SHA256           string    `json:"sha256"`
	RecordedHash     string    `json:"recorded_hash"`
	Tampered         bool      `json:"tampered"`
	MimeType         string    `json:"mime_type,omitempty"`
	UploadedAt       time.Time `json:"uploaded_at"`
}

type ManifestCase struct {
	PublicID string `json:"public_id"`
	Title    string `json:"title,omitempty"`
}

type ManifestExportedBy struct {
	UserPublicID string `json:"user_public_id"`
}

type Manifest struct {
	System        string             `json:"system"`
	Version       string             `json:"version"`
	Case          ManifestCase       `json:"case"`
	ExportedAt    string             `json:"exported_at"`
	ExportedBy    ManifestExportedBy `json:"exported_by"`
	HashAlgorithm string             `json:"hash_algorithm"`
	LogsFile      string             `json:"logs_file,omitempty"`
	FileCount     int                `json:"file_count"`
	Files         []ManifestFile     `json:"files"`
}

type FileResult struct {
	Path         string `json:"path"`
	FileName     string `json:"file_name"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`
	Status       string `json:"status"` // "VERIFIED", "TAMPERED", "MISSING", "EXTRA_FILE", "EXPORT_TAMPERED"
	Message      string `json:"message"`
}

type Report struct {
	CasePublicID   string       `json:"case_public_id"`
	CaseTitle      string       `json:"case_title"`
	ExportedAt     string       `json:"exported_at"`
	ExportedBy     string       `json:"exported_by"`
	LogsFile       string       `json:"logs_file,omitempty"`
	SignatureValid bool         `json:"signature_valid"`
	TotalFiles     int          `json:"total_files"`
	VerifiedFiles  int          `json:"verified_files"`
	TamperedFiles  int          `json:"tampered_files"`
	MissingFiles   int          `json:"missing_files"`
	ExtraFiles     int          `json:"extra_files"`
	Passed         bool         `json:"passed"`
	Results        []FileResult `json:"results"`
	Errors         []string     `json:"errors"`
}

func ParsePublicKey(pubKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block from public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, errCert := x509.ParseCertificate(block.Bytes)
		if errCert == nil {
			if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				return rsaPub, nil
			}
		}
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an RSA public key")
	}
	return rsaPub, nil
}

func VerifySignature(manifestBytes, sigBytes, pubKeyPEM []byte) error {
	pubKey, err := ParsePublicKey(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	hashed := sha256.Sum256(manifestBytes)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// VerifyDir inspects an unzipped directory on disk
func VerifyDir(dirPath string, pubKeyPEM []byte) (*Report, error) {
	manifestPath := filepath.Join(dirPath, "manifest.json")
	sigPath := filepath.Join(dirPath, "manifest.sig")

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("manifest.json not found in %s: %w", dirPath, err)
	}

	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("manifest.sig not found in %s: %w", dirPath, err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest.json format: %w", err)
	}

	rep := &Report{
		CasePublicID: manifest.Case.PublicID,
		CaseTitle:    manifest.Case.Title,
		ExportedAt:   manifest.ExportedAt,
		ExportedBy:   manifest.ExportedBy.UserPublicID,
		LogsFile:     manifest.LogsFile,
		TotalFiles:   len(manifest.Files),
	}

	// 1. Verify digital signature
	if err := VerifySignature(manifestBytes, sigBytes, pubKeyPEM); err != nil {
		rep.SignatureValid = false
		rep.Errors = append(rep.Errors, fmt.Sprintf("CRITICAL: Server signature invalid: %v", err))
	} else {
		rep.SignatureValid = true
	}

	// 2. Track files in manifest
	declaredPaths := make(map[string]bool)

	for _, mf := range manifest.Files {
		cleanRel := filepath.Clean(filepath.FromSlash(mf.Path))
		declaredPaths[cleanRel] = true
		fullPath := filepath.Join(dirPath, cleanRel)

		f, err := os.Open(fullPath)
		if err != nil {
			rep.MissingFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				Status:       "MISSING",
				Message:      "File not found on disk",
			})
			continue
		}

		hasher := sha256.New()
		_, err = io.Copy(hasher, f)
		f.Close()
		if err != nil {
			rep.TamperedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				Status:       "READ_ERROR",
				Message:      fmt.Sprintf("Failed to read file: %v", err),
			})
			continue
		}

		actualHash := hex.EncodeToString(hasher.Sum(nil))

		if actualHash != mf.SHA256 {
			rep.TamperedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				ActualHash:   actualHash,
				Status:       "TAMPERED",
				Message:      "Hash mismatch! File content has been modified.",
			})
		} else if mf.Tampered {
			// Was marked tampered at the time of server export
			rep.TamperedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				ActualHash:   actualHash,
				Status:       "EXPORT_TAMPERED",
				Message:      fmt.Sprintf("Matches exported file, but server flagged it as tampered (recorded: %s)", mf.RecordedHash),
			})
		} else {
			rep.VerifiedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				ActualHash:   actualHash,
				Status:       "VERIFIED",
				Message:      "Integrity verified (SHA-256 match)",
			})
		}
	}

	// 3. Scan for unauthorized / extra files
	_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dirPath, path)
		if err != nil {
			return nil
		}
		rel = filepath.Clean(rel)

		// Ignore metadata files
		if rel == "manifest.json" || rel == "manifest.sig" || strings.HasPrefix(filepath.Base(rel), ".") {
			return nil
		}

		if !declaredPaths[rel] {
			rep.ExtraFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:    rel,
				Status:  "EXTRA_FILE",
				Message: "Unauthorized file detected in directory (not in signed manifest)",
			})
		}
		return nil
	})

	rep.Passed = rep.SignatureValid && rep.TamperedFiles == 0 && rep.MissingFiles == 0 && rep.ExtraFiles == 0
	return rep, nil
}

// VerifyZip inspects an unextracted .zip file directly
func VerifyZip(zipPath string, pubKeyPEM []byte) (*Report, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip file %s: %w", zipPath, err)
	}
	defer zr.Close()

	var manifestBytes, sigBytes []byte
	filesInZip := make(map[string]*zip.File)

	for _, f := range zr.File {
		cleanName := filepath.Clean(filepath.ToSlash(f.Name))
		filesInZip[cleanName] = f

		if cleanName == "manifest.json" {
			rc, err := f.Open()
			if err == nil {
				manifestBytes, _ = io.ReadAll(rc)
				rc.Close()
			}
		} else if cleanName == "manifest.sig" {
			rc, err := f.Open()
			if err == nil {
				sigBytes, _ = io.ReadAll(rc)
				rc.Close()
			}
		}
	}

	if len(manifestBytes) == 0 {
		return nil, errors.New("manifest.json not found inside zip archive")
	}
	if len(sigBytes) == 0 {
		return nil, errors.New("manifest.sig not found inside zip archive")
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest.json format in zip: %w", err)
	}

	rep := &Report{
		CasePublicID: manifest.Case.PublicID,
		CaseTitle:    manifest.Case.Title,
		ExportedAt:   manifest.ExportedAt,
		ExportedBy:   manifest.ExportedBy.UserPublicID,
		LogsFile:     manifest.LogsFile,
		TotalFiles:   len(manifest.Files),
	}

	// 1. Signature check
	if err := VerifySignature(manifestBytes, sigBytes, pubKeyPEM); err != nil {
		rep.SignatureValid = false
		rep.Errors = append(rep.Errors, fmt.Sprintf("CRITICAL: Server signature invalid: %v", err))
	} else {
		rep.SignatureValid = true
	}

	declaredPaths := make(map[string]bool)

	// 2. Check each manifest file
	for _, mf := range manifest.Files {
		cleanPath := filepath.Clean(filepath.ToSlash(mf.Path))
		declaredPaths[cleanPath] = true

		zf, ok := filesInZip[cleanPath]
		if !ok {
			rep.MissingFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				Status:       "MISSING",
				Message:      "File not found in zip archive",
			})
			continue
		}

		rc, err := zf.Open()
		if err != nil {
			rep.TamperedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				Status:       "READ_ERROR",
				Message:      fmt.Sprintf("Failed to read zip entry: %v", err),
			})
			continue
		}

		hasher := sha256.New()
		_, _ = io.Copy(hasher, rc)
		rc.Close()

		actualHash := hex.EncodeToString(hasher.Sum(nil))

		if actualHash != mf.SHA256 {
			rep.TamperedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				ActualHash:   actualHash,
				Status:       "TAMPERED",
				Message:      "Hash mismatch! File content in zip has been modified.",
			})
		} else if mf.Tampered {
			rep.TamperedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				ActualHash:   actualHash,
				Status:       "EXPORT_TAMPERED",
				Message:      fmt.Sprintf("Matches exported file, but server flagged it as tampered (recorded: %s)", mf.RecordedHash),
			})
		} else {
			rep.VerifiedFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:         mf.Path,
				FileName:     mf.FileName,
				ExpectedHash: mf.SHA256,
				ActualHash:   actualHash,
				Status:       "VERIFIED",
				Message:      "Integrity verified (SHA-256 match)",
			})
		}
	}

	// 3. Scan for extra files in zip
	for name := range filesInZip {
		if name == "manifest.json" || name == "manifest.sig" || strings.HasPrefix(filepath.Base(name), ".") {
			continue
		}
		if !declaredPaths[name] {
			rep.ExtraFiles++
			rep.Results = append(rep.Results, FileResult{
				Path:    name,
				Status:  "EXTRA_FILE",
				Message: "Unauthorized file detected in zip (not in signed manifest)",
			})
		}
	}

	rep.Passed = rep.SignatureValid && rep.TamperedFiles == 0 && rep.MissingFiles == 0 && rep.ExtraFiles == 0
	return rep, nil
}
