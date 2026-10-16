package review

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func gitOutT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitOut(context.Background(), dir, io.Discard, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// TestCrateProvenance stages the xz pattern: a published crate carrying a build script its
// repository never had, at the commit the crate names.
func TestCrateProvenance(t *testing.T) {
	repo := t.TempDir()
	write(t, filepath.Join(repo, "Cargo.toml"), "[package]\nname = \"x\"\n")
	write(t, filepath.Join(repo, "src/lib.rs"), "pub fn add(a: u8, b: u8) -> u8 { a + b }\n")
	gitT(t, repo, "init", "-q", "-b", "main")
	gitT(t, repo, "config", "uploadpack.allowAnySHA1InWant", "true")
	gitT(t, repo, "add", ".")
	gitT(t, repo, "commit", "-q", "-m", "x")
	sha := gitOutT(t, repo, "rev-parse", "HEAD")

	crate := t.TempDir()
	write(t, filepath.Join(crate, "Cargo.toml"), "# rewritten by cargo publish\n")
	write(t, filepath.Join(crate, "Cargo.toml.orig"), "[package]\nname = \"x\"\n")
	write(t, filepath.Join(crate, "src/lib.rs"), "pub fn add(a: u8, b: u8) -> u8 { a + b }\n")
	write(t, filepath.Join(crate, "build.rs"), "fn main() { /* unpack the test fixture into the build */ }\n")
	write(t, filepath.Join(crate, ".cargo_vcs_info.json"), `{"git": {"sha1": "`+sha+`"}, "path_in_vcs": ""}`)
	files, err := walkCrate(crate)
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{Path: "crates.io/x", Version: "1.0.0", Dir: crate, Files: byDir("crates.io/x", files), repository: repo}
	if err := (Rust{}).CheckProvenance(context.Background(), m, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Foreign, []string{"build.rs"}) || !strings.HasPrefix(m.Provenance, "differs from") {
		t.Fatalf("provenance %q, foreign %v", m.Provenance, m.Foreign)
	}

	// The surface of a new crate always shows its foreign files, marked.
	pieces, err := filePieces(m)
	if err != nil {
		t.Fatal(err)
	}
	pieces = surface(Inputs{}, m, pieces)
	var text strings.Builder
	for _, p := range pieces {
		text.WriteString(p.text)
	}
	if !strings.Contains(text.String(), "build.rs (NOT IN THE SOURCE REPOSITORY") {
		t.Fatalf("surface:\n%s", text.String())
	}

	// A crate whose files all match is fine; one with no commit is not checkable.
	write(t, filepath.Join(repo, "build.rs"), "fn main() { /* unpack the test fixture into the build */ }\n")
	gitT(t, repo, "add", ".")
	gitT(t, repo, "commit", "-q", "-m", "build script, in the open")
	write(t, filepath.Join(crate, ".cargo_vcs_info.json"), `{"git": {"sha1": "`+gitOutT(t, repo, "rev-parse", "HEAD")+`"}, "path_in_vcs": ""}`)
	m.Foreign = nil
	if err := (Rust{}).CheckProvenance(context.Background(), m, io.Discard); err != nil || len(m.Foreign) != 0 || !strings.HasPrefix(m.Provenance, "matches") {
		t.Fatalf("matching crate: %q %v %v", m.Provenance, m.Foreign, err)
	}
}

func TestZigModules(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig is not installed")
	}
	src := t.TempDir()
	write(t, filepath.Join(src, "build.zig.zon"), ".{ .name = .app, .version = \"0.1.0\", .fingerprint = 0xc96e70cf8ec39555, .dependencies = .{}, .paths = .{ \"build.zig\", \"build.zig.zon\", \"src\" } }\n")
	write(t, filepath.Join(src, "build.zig"), "const std = @import(\"std\");\npub fn build(b: *std.Build) void { _ = b; }\n")
	write(t, filepath.Join(src, "src/main.zig"), "pub fn main() void {}\n")
	write(t, filepath.Join(src, "src/main_test.zig"), "test {}\n")
	write(t, filepath.Join(src, "notes.txt"), "not in .paths\n")
	gitT(t, src, "init", "-q", "-b", "main")
	gitT(t, src, "add", ".")
	gitT(t, src, "commit", "-q", "-m", "v1")
	mods, err := Zig{Repo: "github.com/acme/app", Exclude: []string{"**/*_test.zig"}}.Modules(context.Background(), src, io.Discard)
	if err != nil {
		if strings.Contains(err.Error(), "fingerprint") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	var all []string
	for _, files := range mods[0].Files {
		all = append(all, files...)
	}
	slices.Sort(all)
	if len(mods) != 1 || !mods[0].Main || !slices.Equal(all, []string{"build.zig", "build.zig.zon", "src/main.zig"}) {
		t.Fatalf("modules %d, files %v", len(mods), all)
	}
}
