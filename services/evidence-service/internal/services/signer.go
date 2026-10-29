package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type Signer interface {
	Sign(data []byte) ([]byte, error)
}

type rsaSigner struct {
	privateKey *rsa.PrivateKey
}

func NewSigner(keyPath string) (Signer, error) {
	if keyPath == "" {
		keyPath = os.Getenv("SIGNING_KEY_PATH")
	}
	if keyPath == "" {
		keyPath = "private.pem"
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key at %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", keyPath)
	}

	// Try PKCS#8 then PKCS#1
	privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		rsaPriv, err1 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err1 != nil {
			return nil, fmt.Errorf("failed to parse private key: %v / %v", err, err1)
		}
		return &rsaSigner{privateKey: rsaPriv}, nil
	}

	rsaPriv, ok := privKeyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not an RSA private key", keyPath)
	}

	return &rsaSigner{privateKey: rsaPriv}, nil
}

func (s *rsaSigner) Sign(data []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("signer private key is not initialized")
	}

	hashed := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return sig, nil
}
