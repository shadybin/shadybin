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

// TestBadgeShowsCertifyRun: a release with no statement shows what its newest certify run
// is doing, and its page links to that run; a signed verdict always wins.
func TestBadgeShowsCertifyRun(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, "github.com", "acme", "tool")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "shadybin.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	published := now.Add(-2 * time.Hour)

	for _, c := range []struct {
		status, conclusion, want string
	}{
		{"in_progress", "", `"v2.0.0 certifying"`},
		{"queued", "", `"v2.0.0 certifying"`},
		{"completed", "failure", `"v2.0.0 certify failed"`},
		{"completed", "cancelled", `"v2.0.0 certify failed"`},
		// Succeeded but not signed yet: intake signs it next.
		{"completed", "success", `"v2.0.0 pending"`},
	} {
		run, err := NewRun(repo, 42, c.status, c.conclusion)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteRun(root, repo, "v2.0.0", run); err != nil {
			t.Fatal(err)
		}
		if err := WriteBadges(root, repo, "v2.0.0", published, now); err != nil {
			t.Fatal(err)
		}
		if b := readBadge(t, filepath.Join(proj, BadgeName)); !strings.Contains(b, c.want) {
			t.Errorf("%s/%s: project badge %s, want %s", c.status, c.conclusion, b, c.want)
		}
		if b := readBadge(t, filepath.Join(proj, "v2.0.0", BadgeName)); !strings.Contains(b, c.want) {
			t.Errorf("%s/%s: release badge %s, want %s", c.status, c.conclusion, b, c.want)
		}
	}

	// The page links the unsigned release to its run.
	run, _ := NewRun(repo, 42, "in_progress", "")
	if err := WriteRun(root, repo, "v2.0.0", run); err != nil {
		t.Fatal(err)
	}
	if err := WriteBadges(root, repo, "v2.0.0", published, now); err != nil {
		t.Fatal(err)
	}
	if err := WritePages(root); err != nil {
		t.Fatal(err)
	}
	page := readBadge(t, filepath.Join(proj, "index.html"))
	if !strings.Contains(page, `<a href="https://github.com/acme/tool/actions/runs/42"`) {
		t.Fatalf("page does not link the run:\n%s", page)
	}

	// Signed, the verdict wins, and the page no longer points at the run.
	sign(t, root, "v2.0.0", verify.Certified)
	if err := WriteBadges(root, repo, "v2.0.0", published, now); err != nil {
		t.Fatal(err)
	}
	if b := readBadge(t, filepath.Join(proj, BadgeName)); !strings.Contains(b, `"v2.0.0 not shady"`) {
		t.Fatalf("signed: %s", b)
	}
	if err := WritePages(root); err != nil {
		t.Fatal(err)
	}
	if page := readBadge(t, filepath.Join(proj, "index.html")); strings.Contains(page, "actions/runs/42") {
		t.Fatal("a signed release still links its certify run")
	}
}

// TestNewRunBuildsItsOwnLink: the run's link is made from the repository and the id, and
// what GitHub would never report is refused.
func TestNewRunBuildsItsOwnLink(t *testing.T) {
	run, err := NewRun(repo, 7, "completed", "success")
	if err != nil || run.URL != "https://github.com/acme/tool/actions/runs/7" {
		t.Fatalf("%+v %v", run, err)
	}
	for _, c := range []struct {
		repo               string
		id                 uint64
		status, conclusion string
	}{
		{"gitlab.com/acme/tool", 7, "completed", "success"},
		{"github.com/acme", 7, "completed", "success"},
		{repo, 0, "completed", "success"},
		{repo, 7, "running<script>", ""},
		{repo, 7, "completed", "won"},
	} {
		if _, err := NewRun(c.repo, c.id, c.status, c.conclusion); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	// A run file that was tampered with is ignored.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, RunName), []byte(`{"url":"javascript:alert(1)","status":"in_progress"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadRun(dir); ok {
		t.Fatal("loaded a run whose link is not GitHub's")
	}
}
