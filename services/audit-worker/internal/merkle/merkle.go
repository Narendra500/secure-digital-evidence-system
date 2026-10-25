package merkle

import (
	"crypto/sha256"
	"encoding/hex"
)

func hashPair(left, right string) string {
	combined := left + right
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// ComputeRoot builds a binary Merkle tree from a slice of leaf hashes and returns the root hash.
func ComputeRoot(leafHashes []string) string {
	if len(leafHashes) == 0 {
		return ""
	}
	if len(leafHashes) == 1 {
		return leafHashes[0]
	}

	currentLevel := make([]string, len(leafHashes))
	copy(currentLevel, leafHashes)

	for len(currentLevel) > 1 {
		// If odd number of nodes, duplicate the last one
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1])
		}

		nextLevel := make([]string, 0, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			nextLevel = append(nextLevel, hashPair(currentLevel[i], currentLevel[i+1]))
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// GenerateProof produces the Merkle inclusion proof (audit path) for the leaf at index.
func GenerateProof(leafHashes []string, index int) []string {
	if index < 0 || index >= len(leafHashes) {
		return nil
	}

	var proof []string
	currentLevel := make([]string, len(leafHashes))
	copy(currentLevel, leafHashes)
	currentIndex := index

	for len(currentLevel) > 1 {
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1])
		}

		// Sibling index
		var siblingIndex int
		if currentIndex%2 == 0 {
			siblingIndex = currentIndex + 1
		} else {
			siblingIndex = currentIndex - 1
		}

		proof = append(proof, currentLevel[siblingIndex])

		nextLevel := make([]string, 0, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			nextLevel = append(nextLevel, hashPair(currentLevel[i], currentLevel[i+1]))
		}
		currentLevel = nextLevel
		currentIndex = currentIndex / 2
	}

	return proof
}

// VerifyProof verifies that a leaf belongs to the tree with the given root hash.
func VerifyProof(leafHash, root string, proof []string, index int) bool {
	currentHash := leafHash
	currentIndex := index

	for _, sibling := range proof {
		if currentIndex%2 == 0 {
			currentHash = hashPair(currentHash, sibling)
		} else {
			currentHash = hashPair(sibling, currentHash)
		}
		currentIndex = currentIndex / 2
	}

	return currentHash == root
}
