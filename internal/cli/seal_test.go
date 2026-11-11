package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shadybin/shadybin/internal/registry"
)

// sealProject is a Swift project whose analysis leaves docs/ out, and whose build copies
// a file from docs/ into what it ships: the trick a sealed rebuild exists to catch.
func sealProject(t *testing.T) (project, repo string) {
	t.Helper()
	repo = t.TempDir()
	files := map[string]string{
		"Package.swift":          "// swift-tools-version: 6.0\nimport PackageDescription\nlet package = Package(name: \"app\")\n",
		"Sources/App/main.swift": "print(\"hi\")\n",
		"docs/hidden.swift":      "print(\"hidden\")\n",
		"build.sh":               "mkdir -p dist && cat Sources/App/main.swift docs/hidden.swift > dist/app\n",
	}
	for name, text := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitT(t, repo, "init", "-q", "-b", "main")
	gitT(t, repo, "add", ".")
	gitT(t, repo, "commit", "-q", "-m", "app")
	gitT(t, repo, "tag", "v1.0.0")

	p := registry.Project{
		Repo: "github.com/acme/app", Language: "swift", Seal: true, Checksums: "*.sha256",
		Analyze: registry.Analyze{Exclude: []string{"docs/**"}},
		Builds: []registry.Build{{
			Runner: "xcode-27", Fetch: []string{"echo fetched > fetched"},
			Run: []string{"sh build.sh"}, Artifacts: []string{"dist/app"},
		}},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	project = filepath.Join(t.TempDir(), "shadybin.json")
	if err := os.WriteFile(project, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return project, repo
}

func clone(t *testing.T, repo string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "src")
	gitT(t, "", "clone", "-q", "--branch", "v1.0.0", repo, dir)
	return dir
}

func TestSealCatchesAFileOutsideTheReview(t *testing.T) {
	project, repo := sealProject(t)

	// Unsealed, the build ships the excluded file.
	plain := clone(t, repo)
	out := t.TempDir()
	mustRun(t, "rebuild", "-project", project, "-tag", "v1.0.0", "-src", plain, "-out", out)
	shipped, _ := os.ReadFile(filepath.Join(out, "app"))
	if !strings.Contains(string(shipped), "hidden") {
		t.Fatalf("the unsealed build: %q", shipped)
	}

	// Sealed, it has nothing to ship but what the review saw, so its output differs from
	// the release built with the hidden file, and would not certify.
	sealed := clone(t, repo)
	record := filepath.Join(t.TempDir(), "seal")
	mustRun(t, "seal", "-project", project, "-tag", "v1.0.0", "-src", sealed, "-o", record)
	if _, err := os.Stat(filepath.Join(sealed, ".git")); err == nil {
		t.Fatal(".git survived the seal")
	}
	if fi, err := os.Stat(filepath.Join(sealed, "docs/hidden.swift")); err != nil || fi.Size() != 0 {
		t.Fatalf("the excluded file was not emptied: %v %v", fi, err)
	}
	if data, _ := os.ReadFile(filepath.Join(sealed, "Sources/App/main.swift")); string(data) != "print(\"hi\")\n" {
		t.Fatalf("a reviewed file changed: %q", data)
	}
	for _, phase := range []string{"fetch", "run"} {
		mustRun(t, "rebuild", "-project", project, "-tag", "v1.0.0", "-src", sealed, "-sealed", record, "-phase", phase, "-out", out+"-sealed")
	}
	if _, err := os.Stat(filepath.Join(sealed, "fetched")); err != nil {
		t.Fatal("the fetch phase did not run")
	}
	rebuilt, _ := os.ReadFile(filepath.Join(out+"-sealed", "app"))
	if bytes.Equal(rebuilt, shipped) || strings.Contains(string(rebuilt), "hidden") {
		t.Fatalf("the sealed build still shipped the hidden file: %q", rebuilt)
	}

	// The certify job checks the record against its own checkout.
	check := clone(t, repo)
	line := mustRun(t, "seal", "-project", project, "-tag", "v1.0.0", "-src", check, "-check", record)
	if !strings.Contains(line, "1 other files of the repository emptied") {
		t.Fatalf("report line: %q", line)
	}
}

func TestSealCheckRefuses(t *testing.T) {
	project, repo := sealProject(t)
	record := filepath.Join(t.TempDir(), "seal")
	mustRun(t, "seal", "-project", project, "-tag", "v1.0.0", "-src", clone(t, repo), "-o", record)
	good, _ := os.ReadFile(record)
	p, err := registry.LoadProject(project)
	if err != nil {
		t.Fatal(err)
	}
	check := clone(t, repo)
	if _, err := checkSeal(context.Background(), p, "v1.0.0", check, good, io.Discard); err != nil {
		t.Fatalf("a good record: %v", err)
	}
	for name, edit := range map[string]func(string) string{
		"another scope":    func(s string) string { return strings.Replace(s, "scope sha256:", "scope sha256:0", 1)[:len(s)] },
		"another commit":   func(s string) string { return strings.Replace(s, "commit ", "commit 0", 1) },
		"another tag":      func(s string) string { return strings.Replace(s, "tag v1.0.0", "tag v1.0.1", 1) },
		"not canonical":    func(s string) string { return strings.Replace(s, "emptied 1", "emptied 01", 1) },
		"no record at all": func(string) string { return "" },
	} {
		if _, err := checkSeal(context.Background(), p, "v1.0.0", check, []byte(edit(string(good))), io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A scope the analysis would not give: the excluded file kept.
	p.Analyze.Exclude = nil
	if _, err := checkSeal(context.Background(), p, "v1.0.0", check, good, io.Discard); err == nil {
		t.Error("a record sealed to another scope was accepted")
	}
}

func TestSealedRebuildRefusesAnUnsealedCheckout(t *testing.T) {
	project, repo := sealProject(t)
	record := filepath.Join(t.TempDir(), "seal")
	mustRun(t, "seal", "-project", project, "-tag", "v1.0.0", "-src", clone(t, repo), "-o", record)
	_, stderr, code := run(t, "rebuild", "-project", project, "-tag", "v1.0.0", "-src", clone(t, repo), "-sealed", record, "-out", t.TempDir())
	if code == 0 || !strings.Contains(stderr, "not sealed") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}
