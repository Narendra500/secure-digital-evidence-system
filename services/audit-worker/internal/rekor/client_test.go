package rekor

import (
	"context"
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
