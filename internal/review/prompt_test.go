package review

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestPromptUnchanged fails when prompt.txt changes, so a change to the reviewer's brief
// is always deliberate: bump PromptVersion, so cached answers to the old brief are never
// reused, then update this digest.
func TestPromptUnchanged(t *testing.T) {
	sum := sha256.Sum256([]byte(systemPrompt))
	if got := hex.EncodeToString(sum[:]); got != promptDigest {
		t.Fatalf("prompt.txt changed (sha256 %s): bump PromptVersion, then set promptDigest", got)
	}
}

// promptDigest is the SHA-256 of prompt.txt for PromptVersion 3.
const promptDigest = "0fbc350abbf47f0325117c7d053ed4b9547b06690cd67d366b53892d59009f72"
