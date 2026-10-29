package rekor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestMockRekorClient(t *testing.T) {
	client, err := NewRekorClient("mock")
	if err != nil {
		t.Fatalf("Failed to create mock Rekor client: %v", err)
	}

	testHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	res, err := client.AnchorHash(context.Background(), testHash)
	if err != nil {
		t.Fatalf("AnchorHash returned error: %v", err)
	}

	if res.EntryUUID == "" {
		t.Fatal("Expected non-empty EntryUUID")
	}
	if !res.IsMock {
		t.Fatal("Expected IsMock to be true in mock mode")
	}
}

func TestRekorSignatureVerification(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	testHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hashBytes, err := hex.DecodeString(testHash)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}

	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hashBytes)
	if err != nil {
		t.Fatalf("failed to sign ASN.1: %v", err)
	}

	// Rekor verifies the ASN.1 signature directly against the 32-byte hash
	if !ecdsa.VerifyASN1(&privKey.PublicKey, hashBytes, sigBytes) {
		t.Fatal("Signature verification failed against hashBytes (Rekor validation would fail)")
	}
}
