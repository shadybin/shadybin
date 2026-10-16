package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shadybin/shadybin/internal/checksums"
	"github.com/shadybin/shadybin/internal/registry"
	"github.com/shadybin/shadybin/internal/review"
)

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, code := run(t, args...)
	if code != 0 {
		t.Fatalf("shadybin %s: exit %d\n%s", strings.Join(args, " "), code, stderr)
	}
	return stdout
}

func gitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_AUTHOR_DATE=2026-10-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-10-01T00:00:00Z")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestCertifyAndVerify walks one release through: the vendor builds and publishes it,
// shadybin rebuilds it from the tag, writes and signs the statement, and a user verifies
// the published file, and a tampered one, against the registry.
func TestCertifyAndVerify(t *testing.T) {
	tmp := t.TempDir()
	vendor := filepath.Join(tmp, "vendor")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	// A build that is reproducible only because it stamps SOURCE_DATE_EPOCH, not the clock.
	build := "mkdir -p dist && printf 'tool built at %s\\n' \"$SOURCE_DATE_EPOCH\" > dist/tool_Linux_x86_64.bin"
	if err := os.WriteFile(filepath.Join(vendor, "README"), []byte("tool\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, vendor, "init", "-q", "-b", "main")
	gitT(t, vendor, "add", ".")
	gitT(t, vendor, "commit", "-q", "-m", "release")
	gitT(t, vendor, "tag", "v1.0.0")

	// The vendor's own release build, and its published checksums, plus a file shadybin
	// does not rebuild.
	vendorBuild := exec.Command("sh", "-c", "export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) && "+build)
	vendorBuild.Dir = vendor
	if out, err := vendorBuild.CombinedOutput(); err != nil {
		t.Fatalf("vendor build: %v\n%s", err, out)
	}
	published := filepath.Join(vendor, "dist", "tool_Linux_x86_64.bin")
	d, err := checksums.File(published)
	if err != nil {
		t.Fatal(err)
	}
	checksumsFile := filepath.Join(tmp, "checksums.txt")
	sums := checksums.Line("tool_Linux_x86_64.bin", d) + strings.Repeat("0", 64) + "  install.sh\n"
	if err := os.WriteFile(checksumsFile, []byte(sums), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := filepath.Join(tmp, "registry")
	projDir := filepath.Join(reg, "github.com", "acme", "tool")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	proj, _ := json.Marshal(registry.Project{
		Repo: "github.com/acme/tool", Clone: vendor, Language: "go",
		Builds:    []registry.Build{{Runner: "ubuntu-24.04", Run: []string{build}, Artifacts: []string{"dist/*.bin"}}},
		Checksums: "checksums.txt",
		Analyze:   registry.Analyze{Packages: []string{"./cmd/tool"}, Targets: []string{"linux"}},
	})
	projFile := filepath.Join(projDir, "project.json")
	if err := os.WriteFile(projFile, proj, 0o644); err != nil {
		t.Fatal(err)
	}

	rebuilt := filepath.Join(tmp, "rebuilt")
	if out := mustRun(t, "rebuild", "-project", projFile, "-tag", "v1.0.0", "-out", rebuilt); !strings.Contains(out, "tool_Linux_x86_64.bin") {
		t.Fatalf("rebuild output: %s", out)
	}
	if out := mustRun(t, "compare", "-published", checksumsFile, rebuilt); !strings.Contains(out, "| `tool_Linux_x86_64.bin` |") || !strings.Contains(out, resultMatch) {
		t.Fatalf("compare output: %s", out)
	}

	report := filepath.Join(tmp, "report.md")
	if err := os.WriteFile(report, []byte("# Review\n\nNothing shady.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(tmp, "manifest.json")
	if err := os.WriteFile(manifestFile, []byte(`{"tool": "capslock", "module": "github.com/acme/tool", "goos": ["linux"], "packages": [], "modules": {}, "capabilities": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reviewFile := filepath.Join(tmp, "review.json")
	writeReview(t, reviewFile, "pass", review.Certified)
	mustRun(t, "statement", "-registry", reg, "-repo", "github.com/Acme/Tool", "-tag", "v1.0.0",
		"-published", checksumsFile, "-report", report, "-manifest", manifestFile, "-review", reviewFile, rebuilt)
	if _, stderr, code := run(t, "statement", "-registry", reg, "-repo", "github.com/acme/tool", "-tag", "v1.0.0",
		"-published", checksumsFile, "-report", report, "-manifest", manifestFile, "-review", reviewFile, rebuilt); code == 0 {
		t.Fatalf("a second statement for the release was written: %s", stderr)
	}

	keyFile := filepath.Join(tmp, "key")
	pub := strings.TrimSpace(mustRun(t, "keygen", "-o", keyFile))
	mustRun(t, "sign", "-registry", reg, "-repo", "github.com/acme/tool", "-tag", "v1.0.0", "-key", keyFile)
	badge, err := os.ReadFile(filepath.Join(projDir, "v1.0.0", "badge.json"))
	if err != nil || !strings.Contains(string(badge), `"v1.0.0 not shady"`) {
		t.Fatalf("badge: %s %v", badge, err)
	}
	if latest, err := os.ReadFile(filepath.Join(projDir, "latest")); err != nil || string(latest) != "v1.0.0\n" {
		t.Fatalf("latest: %q %v", latest, err)
	}

	if out := mustRun(t, "verify", "-registry", reg, "-key", pub, "-repo", "github.com/acme/tool", "-tag", "v1.0.0", published); !strings.HasPrefix(out, "ok") {
		t.Fatalf("verify output: %s", out)
	}

	tampered := filepath.Join(tmp, "tampered", "tool_Linux_x86_64.bin")
	if err := os.MkdirAll(filepath.Dir(tampered), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tampered, []byte("tool with a backdoor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := run(t, "verify", "-registry", reg, "-key", pub, "-repo", "github.com/acme/tool", "-tag", "v1.0.0", tampered); code != 1 || !strings.Contains(stderr, "FAIL") {
		t.Fatalf("tampered file verified: exit %d\n%s", code, stderr)
	}
	if _, stderr, code := run(t, "verify", "-registry", reg, "-key", pub, "-repo", "github.com/acme/tool", "-tag", "v2.0.0", published); code != 1 || !strings.Contains(stderr, "yet") {
		t.Fatalf("uncertified release: exit %d\n%s", code, stderr)
	}

	// A report or manifest edited after the statement was written cannot be signed for.
	other := filepath.Join(tmp, "other-key")
	mustRun(t, "keygen", "-o", other)
	for _, name := range []string{"report.md", "manifest.json", "review.json"} {
		path := filepath.Join(projDir, "v1.0.0", name)
		orig, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(orig, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, code := run(t, "sign", "-registry", reg, "-repo", "github.com/acme/tool", "-tag", "v1.0.0", "-key", other); code == 0 {
			t.Fatalf("signed a statement whose %s was edited", name)
		}
		if err := os.WriteFile(path, orig, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// writeReview writes a review.json with one project unit of the given verdict, and the
// release verdict claimed.
func writeReview(t *testing.T, path, unitVerdict, claimed string) {
	t.Helper()
	rv := review.Review{Model: review.Model, Prompt: review.PromptVersion, Verdict: claimed, Units: []review.Unit{{
		Kind: review.KindProject, Module: "github.com/acme/tool", Part: 1, Parts: 1,
		Packages: []string{"github.com/acme/tool"},
		Result:   &review.Result{Summary: "it sends ~/.aws/credentials to a pastebin", Verdict: unitVerdict},
	}}}
	data, err := rv.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRejected: a release whose review fails gets a signed rejection, which updaters
// refuse for good; it does not become the base the next release is reviewed against.
// And a statement claiming a verdict the review's answers do not give is never signed.
func TestRejected(t *testing.T) {
	tmp := t.TempDir()
	rebuilt := filepath.Join(tmp, "rebuilt")
	bin := filepath.Join(rebuilt, "tool.bin")
	if err := os.MkdirAll(rebuilt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("built\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, _ := checksums.File(bin)
	sums := filepath.Join(tmp, "checksums.txt")
	if err := os.WriteFile(sums, []byte(checksums.Line("tool.bin", d)), 0o644); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(tmp, "report.md")
	manifestFile := filepath.Join(tmp, "manifest.json")
	if err := os.WriteFile(report, []byte("r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestFile, []byte(`{"tool": "capslock", "module": "github.com/acme/tool", "goos": ["linux"], "packages": [], "modules": {}, "capabilities": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(tmp, "registry")
	key := filepath.Join(tmp, "key")
	pub := strings.TrimSpace(mustRun(t, "keygen", "-o", key))
	statement := func(tag, unitVerdict, claimed string) {
		rv := filepath.Join(tmp, tag+".json")
		writeReview(t, rv, unitVerdict, claimed)
		mustRun(t, "statement", "-registry", reg, "-repo", "github.com/acme/tool", "-tag", tag,
			"-published", sums, "-report", report, "-manifest", manifestFile, "-review", rv, rebuilt)
	}

	statement("v2.0.0", "fail", review.Rejected)
	mustRun(t, "sign", "-registry", reg, "-repo", "github.com/acme/tool", "-tag", "v2.0.0", "-key", key)
	projDir := filepath.Join(reg, "github.com", "acme", "tool")
	if badge, _ := os.ReadFile(filepath.Join(projDir, "v2.0.0", "badge.json")); !strings.Contains(string(badge), `"v2.0.0 shady"`) || !strings.Contains(string(badge), "red") {
		t.Fatalf("badge: %s", badge)
	}
	if _, err := os.Stat(filepath.Join(projDir, "latest")); err == nil {
		t.Fatal("a rejected release became latest")
	}
	if own, _ := os.ReadFile(filepath.Join(projDir, "v2.0.0", "badge.json")); !strings.Contains(string(own), `"v2.0.0 shady"`) {
		t.Fatalf("the release's own badge: %s", own)
	}
	if _, stderr, code := run(t, "verify", "-registry", reg, "-key", pub, "-repo", "github.com/acme/tool", "-tag", "v2.0.0", bin); code != 1 || !strings.Contains(stderr, "rejected") {
		t.Fatalf("verify of a rejected release: exit %d\n%s", code, stderr)
	}

	// The unit failed, but the statement claims certified: the rule, rerun, disagrees.
	statement("v2.0.1", "fail", review.Certified)
	if _, stderr, code := run(t, "sign", "-registry", reg, "-repo", "github.com/acme/tool", "-tag", "v2.0.1", "-key", key); code == 0 || !strings.Contains(stderr, "the review's answers give rejected") {
		t.Fatalf("signed a verdict the review does not give: exit %d\n%s", code, stderr)
	}
}

// TestStatementRefusesDifferentBuild: a rebuilt file that differs from the published one
// stops the statement; that difference is the whole point.
func TestStatementRefusesDifferentBuild(t *testing.T) {
	tmp := t.TempDir()
	rebuilt := filepath.Join(tmp, "rebuilt")
	if err := os.MkdirAll(rebuilt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rebuilt, "tool.bin"), []byte("from source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(tmp, "checksums.txt")
	if err := os.WriteFile(sums, []byte(strings.Repeat("ab", 32)+"  tool.bin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(tmp, "report.md")
	if err := os.WriteFile(report, []byte("r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := run(t, "statement", "-registry", filepath.Join(tmp, "reg"), "-repo", "github.com/a/b", "-tag", "v1",
		"-published", sums, "-report", report, "-manifest", report, "-review", report, rebuilt); code == 0 || !strings.Contains(stderr, "not the published one") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if _, _, code := run(t, "compare", "-published", sums, rebuilt); code != 1 {
		t.Fatalf("compare passed a different build: exit %d", code)
	}
}
