package registry

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shadybin/shadybin/verify"
)

const repo = "github.com/acme/tool"

func readBadge(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sign(t *testing.T, root, tag, verdict string) {
	t.Helper()
	s := verify.Statement{Repo: repo, Tag: tag, Verdict: verdict, Files: []verify.File{{Name: "tool", Digest: sha256.Sum256([]byte("x"))}}}
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := ReleaseDir(root, repo, tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, verify.StatementName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, verify.SignatureName), []byte("sig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Published(root, repo, tag, verdict); err != nil {
		t.Fatal(err)
	}
}

// TestBadgeFollowsLatestRelease: the project's badge names the latest release, whatever
// shadybin made of it, so an old green badge cannot outlive a release nobody certified.
func TestBadgeFollowsLatestRelease(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, "github.com", "acme", "tool")
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	sign(t, root, "v1.0.0", verify.Certified)
	if err := WriteBadges(root, repo, "v1.0.0", now.Add(-48*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if b := readBadge(t, filepath.Join(proj, BadgeName)); !strings.Contains(b, `"v1.0.0 not shady"`) || !strings.Contains(b, "brightgreen") {
		t.Fatalf("certified: %s", b)
	}

	for _, c := range []struct {
		published time.Duration
		want      string
	}{
		{-2 * time.Hour, `"v1.1.0 pending"`},
		{-25 * time.Hour, `"v1.1.0 not certified"`},
	} {
		if err := WriteBadges(root, repo, "v1.1.0", now.Add(c.published), now); err != nil {
			t.Fatal(err)
		}
		if b := readBadge(t, filepath.Join(proj, BadgeName)); !strings.Contains(b, c.want) {
			t.Errorf("project badge %s, want %s", b, c.want)
		}
		if b := readBadge(t, filepath.Join(proj, "v1.1.0", BadgeName)); !strings.Contains(b, c.want) {
			t.Errorf("release badge %s, want %s", b, c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(proj, "v1.1.0", verify.StatementName)); err == nil {
		t.Fatal("a badge made a statement")
	}

	// Signed late, rejected: the badge turns red, and latest stays at v1.0.0.
	sign(t, root, "v1.1.0", verify.Rejected)
	if err := WriteBadges(root, repo, "v1.1.0", now.Add(-25*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if b := readBadge(t, filepath.Join(proj, BadgeName)); !strings.Contains(b, `"v1.1.0 shady"`) || !strings.Contains(b, "red") {
		t.Fatalf("rejected: %s", b)
	}
	if l, _ := os.ReadFile(filepath.Join(proj, "latest")); string(l) != "v1.0.0\n" {
		t.Fatalf("latest: %q", l)
	}
	// The old release keeps its own badge.
	if b := readBadge(t, filepath.Join(proj, "v1.0.0", BadgeName)); !strings.Contains(b, `"v1.0.0 not shady"`) {
		t.Fatalf("v1.0.0's own badge: %s", b)
	}
}
