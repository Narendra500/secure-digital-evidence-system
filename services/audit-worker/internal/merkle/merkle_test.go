package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestMerkleRoot(t *testing.T) {
	if ComputeRoot(nil) != "" {
		t.Fatal("Expected empty root for nil leaves")
	}

	single := hashStr("event-1")
	if ComputeRoot([]string{single}) != single {
		t.Fatal("Expected single leaf to equal root")
	}

	leaves := []string{
		hashStr("event-1"),
		hashStr("event-2"),
		hashStr("event-3"),
		hashStr("event-4"),
	}

	root := ComputeRoot(leaves)
	if root == "" {
		t.Fatal("Expected non-empty root")
	}

	// Verify that odd number of leaves works
	leavesOdd := append(leaves, hashStr("event-5"))
	rootOdd := ComputeRoot(leavesOdd)
	if rootOdd == "" {
		t.Fatal("Expected non-empty root for odd leaves")
	}
}

func TestMerkleProofVerification(t *testing.T) {
	var leaves []string
	for i := 1; i <= 8; i++ {
		leaves = append(leaves, hashStr(fmt.Sprintf("event-%d", i)))
	}

	root := ComputeRoot(leaves)

	for i := range leaves {
		proof := GenerateProof(leaves, i)
		if !VerifyProof(leaves[i], root, proof, i) {
			t.Fatalf("Proof verification failed for leaf %d", i)
		}

		// Tampered leaf must fail
		tampered := hashStr("tampered-data")
		if VerifyProof(tampered, root, proof, i) {
			t.Fatalf("Proof verification should fail for tampered leaf %d", i)
		}
	}
}
