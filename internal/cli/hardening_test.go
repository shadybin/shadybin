package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/shadybin/shadybin/internal/registry"
	"github.com/shadybin/shadybin/verify"
)

// TestCertifiedInChecksSignature: a previous release counts only with a valid signature
// by a trusted key, over a statement for that release.
func TestCertifiedInChecksSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	root := t.TempDir()
	const repo = "github.com/acme/tool"
	put := func(tag, statementTag, verdict string, signer ed25519.PrivateKey, sig string) {
		t.Helper()
		dir, err := registry.ReleaseDir(root, repo, tag)
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(dir, 0o755)
		s := &verify.Statement{Repo: repo, Tag: statementTag, Verdict: verdict,
			Files: []verify.File{{Name: "tool", Digest: verify.Digest{1}}}}
		data, err := s.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, verify.StatementName), data, 0o644)
		if signer != nil {
			sig = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, data)) + "\n"
		}
		if sig != "" {
			os.WriteFile(filepath.Join(dir, verify.SignatureName), []byte(sig), 0o644)
		}
	}
	keys := []ed25519.PublicKey{pub}
	put("v1", "v1", verify.Certified, priv, "")
	put("v2", "v2", verify.Certified, nil, "bm90IGEgc2lnbmF0dXJl\n")
	put("v3", "v3", verify.Certified, other, "")
	put("v4", "v4", verify.Certified, nil, "")
	put("v5", "v5", verify.Rejected, priv, "")
	put("v6", "v1", verify.Certified, priv, "")
	if err := certifiedIn(root, repo, "v1", keys); err != nil {
		t.Errorf("a signed, certified release: %v", err)
	}
	for tag, why := range map[string]string{"v2": "a garbage signature", "v3": "another key's signature", "v4": "no signature",
		"v5": "a rejected release", "v6": "another release's statement"} {
		if err := certifiedIn(root, repo, tag, keys); err == nil {
			t.Errorf("%s: %s counted as certified", tag, why)
		}
	}
}
