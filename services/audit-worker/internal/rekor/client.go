package rekor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type RekorResult struct {
	EntryUUID      string    `json:"entry_uuid"`
	LogIndex       int64     `json:"log_index"`
	IntegratedTime time.Time `json:"integrated_time"`
	IsMock         bool      `json:"is_mock"`
}

type Client interface {
	AnchorHash(ctx context.Context, hashHex string) (*RekorResult, error)
}

type rekorClient struct {
	baseURL    string
	httpClient *http.Client
	privateKey *ecdsa.PrivateKey
	pubKeyPEM  string
	mockMode   bool
}

func NewRekorClient(baseURL string) (Client, error) {
	if baseURL == "" {
		baseURL = os.Getenv("REKOR_URL")
	}
	if baseURL == "" {
		baseURL = "https://rekor.sigstore.dev"
	}

	mockMode := os.Getenv("MOCK_REKOR") == "true" || baseURL == "mock"

	// Generate ECDSA P-256 key pair for signing the anchor payload
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key for Rekor: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return &rekorClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		privateKey: privKey,
		pubKeyPEM:  base64.StdEncoding.EncodeToString(pubPEM),
		mockMode:   mockMode,
	}, nil
}

func (c *rekorClient) AnchorHash(ctx context.Context, hashHex string) (*RekorResult, error) {
	if c.mockMode {
		return c.mockAnchor(hashHex), nil
	}

	// Sign the hash with the worker's key
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		hashBytes = []byte(hashHex)
	}
	digest := sha256.Sum256(hashBytes)

	r, s, err := ecdsa.Sign(rand.Reader, c.privateKey, digest[:])
	if err != nil {
		log.Printf("warning: signing failed, falling back to mock anchor: %v", err)
		return c.mockAnchor(hashHex), nil
	}

	// ASN.1 DER signature format required by Rekor
	sigBytes, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		sigBytes = append(r.Bytes(), s.Bytes()...)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Construct Rekor hashedrekord payload
	payload := map[string]any{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     hashHex,
				},
			},
			"signature": map[string]any{
				"content": sigB64,
				"publicKey": map[string]any{
					"content": c.pubKeyPEM,
				},
			},
		},
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Rekor payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/log/entries", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("warning: Rekor request to %s failed: %v. Falling back to local mock receipt.", endpoint, err)
		return c.mockAnchor(hashHex), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("warning: Rekor returned status %d (%s). Falling back to local mock receipt.", resp.StatusCode, string(body))
		return c.mockAnchor(hashHex), nil
	}

	// Parse Rekor response
	var rawMap map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rawMap); err != nil {
		return c.mockAnchor(hashHex), nil
	}

	for uuid, v := range rawMap {
		entryMap, ok := v.(map[string]any)
		if !ok {
			continue
		}
		logIndex := int64(0)
		if li, ok := entryMap["logIndex"].(float64); ok {
			logIndex = int64(li)
		}
		intTime := time.Now().UTC()
		if it, ok := entryMap["integratedTime"].(float64); ok {
			intTime = time.Unix(int64(it), 0).UTC()
		}

		return &RekorResult{
			EntryUUID:      uuid,
			LogIndex:       logIndex,
			IntegratedTime: intTime,
			IsMock:         false,
		}, nil
	}

	return c.mockAnchor(hashHex), nil
}

func (c *rekorClient) mockAnchor(hashHex string) *RekorResult {
	prefix := hashHex
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	return &RekorResult{
		EntryUUID:      fmt.Sprintf("mock-rekor-%s-%d", prefix, time.Now().UnixNano()),
		LogIndex:       time.Now().Unix(),
		IntegratedTime: time.Now().UTC(),
		IsMock:         true,
	}
}
