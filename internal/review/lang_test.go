package review

import (
	"context"
	"io"
	"os"
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

// TestZigFetchRunsNoBuildZig: dependencies are fetched by URL and checked against their
// hashes, lazy ones too, and the vendor's build.zig never runs. A copy in the repository's
// zig-pkg is the vendor's code.
func TestZigFetchRunsNoBuildZig(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig is not installed")
	}
	tmp := t.TempDir()
	pkg := filepath.Join(tmp, "pkg")
	write(t, filepath.Join(pkg, "build.zig.zon"), ".{ .name = .dep, .version = \"0.1.0\", .fingerprint = 0xf81054301534d274, .paths = .{ \"build.zig.zon\", \"src\" } }\n")
	write(t, filepath.Join(pkg, "src/dep.zig"), "pub fn f() void {}\n")
	tarball := filepath.Join(tmp, "dep.tar.gz")
	if out, err := exec.Command("tar", "-czf", tarball, "-C", pkg, ".").CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	f, err := newZigFetcher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("zig", "fetch", tarball)
	cmd.Dir = f.work
	out, err := cmd.Output()
	if err != nil {
		t.Skip("zig fetch: ", err)
	}
	hash := strings.TrimSpace(string(out))

	project := func(hash string) string {
		src := t.TempDir()
		write(t, filepath.Join(src, "build.zig.zon"), ".{ .name = .app, .version = \"0.1.0\", .fingerprint = 0xc96e70cf8ec39555, .dependencies = .{ .dep = .{ .url = \""+tarball+"\", .hash = \""+hash+"\", .lazy = true } }, .paths = .{ \"build.zig\", \"build.zig.zon\", \"src\" } }\n")
		write(t, filepath.Join(src, "build.zig"), "const std = @import(\"std\");\npub fn build(b: *std.Build) void {\n    _ = b;\n    std.fs.cwd().writeFile(.{ .sub_path = \"RAN\", .data = \"build.zig ran\" }) catch {};\n}\n")
		write(t, filepath.Join(src, "src/main.zig"), "pub fn main() void {}\n")
		gitT(t, src, "init", "-q", "-b", "main")
		gitT(t, src, "add", ".")
		gitT(t, src, "commit", "-q", "-m", "v1")
		return src
	}
	src := project(hash)
	mods, err := Zig{Repo: "github.com/acme/app"}.Modules(context.Background(), src, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "RAN")); err == nil {
		t.Fatal("the vendor's build.zig ran")
	}
	if len(mods) != 2 || mods[1].Version != hash || mods[1].InRepo {
		t.Fatalf("the lazy dependency should be fetched and third-party: %+v", mods)
	}

	if _, err := (Zig{Repo: "github.com/acme/app"}).Modules(context.Background(), project("dep-0.1.0-AAAAwrongwrongwrongwrongwrongwrongwrongwrong"), io.Discard); err == nil || !strings.Contains(err.Error(), "pins") {
		t.Errorf("a dependency that hashes differently should fail: %v", err)
	}

	// The vendor's own copy in zig-pkg is what the build would use: the vendor's code.
	write(t, filepath.Join(src, "zig-pkg", hash, "build.zig.zon"), ".{ .name = .dep, .version = \"0.1.0\", .fingerprint = 0xf81054301534d274, .paths = .{ \"src\" } }\n")
	write(t, filepath.Join(src, "zig-pkg", hash, "src/dep.zig"), "pub fn f() void { evil(); }\n")
	mods, err = Zig{Repo: "github.com/acme/app"}.Modules(context.Background(), src, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || !mods[1].InRepo {
		t.Fatalf("a package in the repository's zig-pkg should be the vendor's: %+v", mods[1])
	}
}

// TestCargoRunsNoVendorProgram: the vendor's .cargo/config.toml names a rustc wrapper and a
// rustc of its own; reading the crate graph runs neither.
func TestCargoRunsNoVendorProgram(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is not installed")
	}
	src := t.TempDir()
	marker := filepath.Join(t.TempDir(), "RAN")
	write(t, filepath.Join(src, "Cargo.toml"), "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	write(t, filepath.Join(src, "src/main.rs"), "fn main() {}\n")
	evil := "#!/bin/sh\necho ran > " + marker + "\nexec \"$@\"\n"
	write(t, filepath.Join(src, "evil.sh"), evil)
	if err := os.Chmod(filepath.Join(src, "evil.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(src, ".cargo/config.toml"), "[build]\nrustc-wrapper = \"./evil.sh\"\nrustc = \"./evil.sh\"\n")
	gitT(t, src, "init", "-q", "-b", "main")
	if out, err := exec.Command("cargo", "generate-lockfile", "--manifest-path", filepath.Join(src, "Cargo.toml"), "--offline").CombinedOutput(); err != nil {
		t.Skip("cargo generate-lockfile: ", string(out))
	}
	os.Remove(marker) // generate-lockfile itself honours the config
	gitT(t, src, "add", ".")
	gitT(t, src, "commit", "-q", "-m", "v1")
	if _, err := (Rust{Repo: "github.com/acme/app", Targets: []string{"x86_64-unknown-linux-gnu"}}).Modules(context.Background(), src, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("cargo metadata ran the vendor's program")
	}
}
