package verifier

import (
	"archive/zip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return priv, pubPEM
}

func signData(t *testing.T, priv *rsa.PrivateKey, data []byte) []byte {
	t.Helper()
	hashed := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}
	return sig
}

func setupTestDirectory(t *testing.T, priv *rsa.PrivateKey) (string, []byte) {
	t.Helper()
	dir := t.TempDir()

	evDir := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(evDir, 0755); err != nil {
		t.Fatalf("Failed to create evidence dir: %v", err)
	}

	content1 := []byte("Hello evidence world 12345")
	h1 := sha256.Sum256(content1)
	hash1 := hex.EncodeToString(h1[:])
	if err := os.WriteFile(filepath.Join(evDir, "file1.txt"), content1, 0644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}

	content2 := []byte("Photographic proof XYZ")
	h2 := sha256.Sum256(content2)
	hash2 := hex.EncodeToString(h2[:])
	if err := os.WriteFile(filepath.Join(evDir, "file2.jpg"), content2, 0644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	manifest := Manifest{
		System:  "Secure Digital Evidence System (SDES)",
		Version: "1.0",
		Case: ManifestCase{
			PublicID: "case-uuid-99",
			Title:    "Test Case",
		},
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		HashAlgorithm: "sha256",
		FileCount:     2,
		Files: []ManifestFile{
			{
				EvidencePublicID: "ev-1",
				FileName:         "file1.txt",
				Path:             "evidence/file1.txt",
				FileSize:         int64(len(content1)),
				SHA256:           hash1,
				RecordedHash:     hash1,
			},
			{
				EvidencePublicID: "ev-2",
				FileName:         "file2.jpg",
				Path:             "evidence/file2.jpg",
				FileSize:         int64(len(content2)),
				SHA256:           hash2,
				RecordedHash:     hash2,
			},
		},
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal manifest: %v", err)
	}

	sigBytes := signData(t, priv, manifestBytes)

	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestBytes, 0644); err != nil {
		t.Fatalf("Failed to write manifest.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), sigBytes, 0644); err != nil {
		t.Fatalf("Failed to write manifest.sig: %v", err)
	}

	return dir, manifestBytes
}

func setupTestZip(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	dir, manifestBytes := setupTestDirectory(t, priv)

	zipPath := filepath.Join(t.TempDir(), "test_case.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Failed to create zip: %v", err)
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)

	// Copy all files into zip
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		w, _ := zw.Create(filepath.ToSlash(rel))
		data, _ := os.ReadFile(path)
		_, _ = w.Write(data)
		return nil
	})
	_ = zw.Close()
	_ = manifestBytes

	return zipPath
}

func TestVerifyDir_Valid(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)
	dir, _ := setupTestDirectory(t, priv)

	rep, err := VerifyDir(dir, pubPEM)
	if err != nil {
		t.Fatalf("VerifyDir failed: %v", err)
	}

	if !rep.Passed {
		t.Fatalf("Expected report to pass, got errors: %v", rep.Errors)
	}
	if !rep.SignatureValid {
		t.Fatalf("Expected signature to be valid")
	}
	if rep.VerifiedFiles != 2 {
		t.Fatalf("Expected 2 verified files, got: %d", rep.VerifiedFiles)
	}
}

func TestVerifyDir_TamperedFile(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)
	dir, _ := setupTestDirectory(t, priv)

	// Modify file1.txt on disk
	tamperedPath := filepath.Join(dir, "evidence", "file1.txt")
	_ = os.WriteFile(tamperedPath, []byte("MALICIOUS MODIFICATION"), 0644)

	rep, err := VerifyDir(dir, pubPEM)
	if err != nil {
		t.Fatalf("VerifyDir failed: %v", err)
	}

	if rep.Passed {
		t.Fatalf("Expected report to FAIL due to tampered file")
	}
	if rep.TamperedFiles != 1 {
		t.Fatalf("Expected 1 tampered file, got %d", rep.TamperedFiles)
	}
}

func TestVerifyDir_InvalidSignature(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)
	dir, _ := setupTestDirectory(t, priv)

	// Alter manifest without resigning
	manifestPath := filepath.Join(dir, "manifest.json")
	_ = os.WriteFile(manifestPath, []byte(`{"tampered":true}`), 0644)

	rep, err := VerifyDir(dir, pubPEM)
	if err != nil {
		t.Fatalf("VerifyDir failed: %v", err)
	}

	if rep.Passed {
		t.Fatalf("Expected report to FAIL due to invalid signature")
	}
	if rep.SignatureValid {
		t.Fatalf("Expected signature to be invalid")
	}
}

func TestVerifyDir_ExtraFile(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)
	dir, _ := setupTestDirectory(t, priv)

	// Add an unauthorized file
	_ = os.WriteFile(filepath.Join(dir, "evidence", "spyware.exe"), []byte("payload"), 0644)

	rep, err := VerifyDir(dir, pubPEM)
	if err != nil {
		t.Fatalf("VerifyDir failed: %v", err)
	}

	if rep.Passed {
		t.Fatalf("Expected report to FAIL due to extra unauthorized file")
	}
	if rep.ExtraFiles != 1 {
		t.Fatalf("Expected 1 extra file, got: %d", rep.ExtraFiles)
	}
}

func TestVerifyZip_Valid(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)
	zipPath := setupTestZip(t, priv)

	rep, err := VerifyZip(zipPath, pubPEM)
	if err != nil {
		t.Fatalf("VerifyZip failed: %v", err)
	}

	if !rep.Passed {
		t.Fatalf("Expected zip verification to pass, errors: %v", rep.Errors)
	}
	if rep.VerifiedFiles != 2 {
		t.Fatalf("Expected 2 verified files, got: %d", rep.VerifiedFiles)
	}
}
