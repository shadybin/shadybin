package review

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// swiftRepos makes a dependency repository at two versions, the second with a submodule
// named by a relative URL, and returns its file URL and both commits.
func swiftRepos(t *testing.T) (location, v1, v2 string) {
	t.Helper()
	t.Cleanup(func() { swiftFetchProtocols = []string{"https"} })
	swiftFetchProtocols = []string{"https", "file"}
	t.Setenv("TMPDIR", t.TempDir()) // where fetched packages go

	root := t.TempDir()
	sub := filepath.Join(root, "helper")
	write(t, filepath.Join(sub, "helper.c"), "int helper(void) { return 1; }\n")
	gitT(t, sub, "init", "-q", "-b", "main")
	gitT(t, sub, "add", ".")
	gitT(t, sub, "commit", "-q", "-m", "helper")

	dep := filepath.Join(root, "dep")
	write(t, filepath.Join(dep, "Package.swift"), "// swift-tools-version: 6.4\nimport PackageDescription\n")
	write(t, filepath.Join(dep, "Sources/Dep/Dep.swift"), "public func dep() -> Int { 1 }\n")
	write(t, filepath.Join(dep, "Sources/Dep/Dep.docc/Dep.md"), "# Dep\n")
	write(t, filepath.Join(dep, "Tests/DepTests/DepTests.swift"), "import Testing\n")
	gitT(t, dep, "init", "-q", "-b", "main")
	gitT(t, dep, "config", "uploadpack.allowAnySHA1InWant", "true")
	gitT(t, dep, "add", ".")
	gitT(t, dep, "commit", "-q", "-m", "v1")
	v1 = gitOutT(t, dep, "rev-parse", "HEAD")

	write(t, filepath.Join(dep, "Sources/Dep/Dep.swift"), "public func dep() -> Int { 2 }\n")
	gitT(t, dep, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "../helper", "Sources/CHelper")
	gitT(t, dep, "add", ".")
	gitT(t, dep, "commit", "-q", "-m", "v2")
	v2 = gitOutT(t, dep, "rev-parse", "HEAD")
	return "file://" + dep, v1, v2
}

func swiftResolvedJSON(location, revision, version string) string {
	return `{"originHash": "x", "version": 3, "pins": [{"identity": "dep", "kind": "remoteSourceControl",
		"location": "` + location + `", "state": {"revision": "` + revision + `", "version": "` + version + `"}}]}`
}

// swiftProject makes a project repository whose Package.resolved pins the dependency, and
// whose Package.swift would leave a file behind if anything ran it.
func swiftProject(t *testing.T, resolved string) (src, ran string) {
	t.Helper()
	src = t.TempDir()
	ran = filepath.Join(t.TempDir(), "manifest-ran")
	write(t, filepath.Join(src, "Package.swift"), "// swift-tools-version: 6.4\nimport PackageDescription\nimport Foundation\n"+
		"FileManager.default.createFile(atPath: \""+ran+"\", contents: nil)\n"+
		"let package = Package(name: \"app\", dependencies: [.package(url: \"https://example.com/dep\", from: \"1.0.0\")])\n")
	write(t, filepath.Join(src, "Package.resolved"), resolved)
	write(t, filepath.Join(src, "Sources/App/main.swift"), "print(\"hi\")\n")
	write(t, filepath.Join(src, "Tests/AppTests/AppTests.swift"), "import Testing\n")
	gitT(t, src, "init", "-q", "-b", "main")
	gitT(t, src, "add", ".")
	gitT(t, src, "commit", "-q", "-m", "app")
	return src, ran
}

func TestSwiftModules(t *testing.T) {
	location, _, v2 := swiftRepos(t)
	src, ran := swiftProject(t, swiftResolvedJSON(location, v2, "2.0.0"))

	mods, err := Swift{Repo: "github.com/acme/app"}.Modules(context.Background(), src, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("Package.swift ran")
	}
	if len(mods) != 2 {
		t.Fatalf("modules: %d", len(mods))
	}
	main, dep := mods[0], mods[1]
	if !main.Main || !main.InRepo || main.Path != "github.com/acme/app" {
		t.Fatalf("main: %+v", main)
	}
	var mainFiles []string
	for _, fs := range main.Files {
		mainFiles = append(mainFiles, fs...)
	}
	slices.Sort(mainFiles)
	// Tests too: a manifest can give a shipped target a path under Tests.
	if want := []string{"Package.resolved", "Package.swift", "Sources/App/main.swift", "Tests/AppTests/AppTests.swift"}; !slices.Equal(mainFiles, want) {
		t.Fatalf("main files %v, want %v", mainFiles, want)
	}

	if dep.Main || dep.InRepo || dep.Version != "2.0.0" || dep.Provenance != "from its repository" {
		t.Fatalf("dependency: %+v", dep)
	}
	var depFiles []string
	for _, fs := range dep.Files {
		depFiles = append(depFiles, fs...)
	}
	slices.Sort(depFiles)
	// The pinned commit, with its submodule (a relative URL, resolved against the package's
	// repository); everything but git's own files, tests and documentation included.
	if want := []string{".gitmodules", "Package.swift", "Sources/CHelper/helper.c", "Sources/Dep/Dep.docc/Dep.md",
		"Sources/Dep/Dep.swift", "Tests/DepTests/DepTests.swift"}; !slices.Equal(depFiles, want) {
		t.Fatalf("dependency files %v, want %v", depFiles, want)
	}
	if data, _ := os.ReadFile(filepath.Join(dep.Dir, "Sources/Dep/Dep.swift")); !strings.Contains(string(data), "{ 2 }") {
		t.Fatalf("dependency not at the pinned commit: %s", data)
	}
}

func TestSwiftFetchPreviousVersion(t *testing.T) {
	location, v1, v2 := swiftRepos(t)
	src, _ := swiftProject(t, swiftResolvedJSON(location, v1, "1.0.0"))
	gitT(t, src, "tag", "v1")
	write(t, filepath.Join(src, "Package.resolved"), swiftResolvedJSON(location, v2, "2.0.0"))
	gitT(t, src, "commit", "-q", "-am", "dep 2.0.0")

	s := Swift{Repo: "github.com/acme/app", PreviousTag: "v1"}
	mods, err := s.Modules(context.Background(), src, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.Fetch(context.Background(), src, mods[1], "1.0.0", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(old, "Sources/Dep/Dep.swift")); !strings.Contains(string(data), "{ 1 }") {
		t.Fatalf("previous version: %s", data)
	}
	if _, err := s.Fetch(context.Background(), src, mods[1], "9.9.9", io.Discard); err == nil {
		t.Fatal("fetched a version the previous release never pinned")
	}
}

func TestSwiftRefuses(t *testing.T) {
	location, v1, _ := swiftRepos(t)
	missing := strings.Repeat("0", 40)
	for name, resolved := range map[string]string{
		"a commit the repository does not have": swiftResolvedJSON(location, missing, "1.0.0"),
		"a transport that runs a program":       swiftResolvedJSON("ext::sh -c touch% /tmp/x", v1, "1.0.0"),
		"ssh, which needs credentials":          swiftResolvedJSON("git@github.com:acme/dep.git", v1, "1.0.0"),
		"a branch with no commit":               swiftResolvedJSON(location, "", ""),
		"a local package":                       strings.Replace(swiftResolvedJSON(location, v1, "1.0.0"), "remoteSourceControl", "localSourceControl", 1),
		"a registry package":                    strings.Replace(swiftResolvedJSON(location, v1, "1.0.0"), "remoteSourceControl", "registry", 1),
		"an old lockfile":                       `{"object": {"pins": []}, "version": 1}`,
	} {
		t.Run(name, func(t *testing.T) {
			src, _ := swiftProject(t, resolved)
			_, err := (Swift{Repo: "github.com/acme/app"}).Modules(context.Background(), src, io.Discard)
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}

	t.Run("packages declared but not pinned", func(t *testing.T) {
		src, _ := swiftProject(t, "")
		gitT(t, src, "rm", "-q", "Package.resolved")
		gitT(t, src, "commit", "-q", "-m", "unpinned")
		_, err := (Swift{Repo: "github.com/acme/app"}).Modules(context.Background(), src, io.Discard)
		if err == nil {
			t.Fatal("accepted")
		}
		t.Log(err)
	})
}

func TestSwiftNoDependencies(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "Package.swift"), "// swift-tools-version: 6.4\nimport PackageDescription\nlet package = Package(name: \"app\")\n")
	write(t, filepath.Join(src, "Sources/App/main.swift"), "print(\"hi\")\n")
	gitT(t, src, "init", "-q", "-b", "main")
	gitT(t, src, "add", ".")
	gitT(t, src, "commit", "-q", "-m", "app")
	mods, err := Swift{Repo: "github.com/acme/app", Exclude: []string{"docs/**"}}.Modules(context.Background(), src, io.Discard)
	if err != nil || len(mods) != 1 || !mods[0].Main {
		t.Fatalf("%v %v", mods, err)
	}
}

func TestSwiftSurface(t *testing.T) {
	for name, want := range map[string]bool{
		"Package.swift":                      true,
		"Package@swift-6.0.swift":            true,
		"Plugins/Gen/plugin.swift":           true,
		"Sources/Shim/shim.m":                true,
		"Sources/App/net.swift URLSession":   true,
		"Sources/App/run.swift Process()":    true,
		"Sources/App/cdecl.swift @_cdecl":    true,
		"Sources/App/plain.swift":            false,
		"src/lib.rs URLSession":              false, // Swift's markers are for Swift files
		"Sources/App/libc.swift dlopen(nil)": true,
	} {
		file, marker, _ := strings.Cut(name, " ")
		if got := surfaceFile(file, []byte("let x = 1\n"+marker+"\n")); got != want {
			t.Errorf("%s: surface %v, want %v", name, got, want)
		}
	}
}

// TestSwiftFileNames: a path with a space or a non-ASCII byte is one file, under its own name.
func TestSwiftFileNames(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "Package.swift"), "// swift-tools-version: 6.4\nimport PackageDescription\nlet package = Package(name: \"app\")\n")
	write(t, filepath.Join(src, "Sources/App/two words.swift"), "let a = 1\n")
	write(t, filepath.Join(src, "Sources/App/café.swift"), "let b = 2\n")
	gitT(t, src, "init", "-q", "-b", "main")
	gitT(t, src, "add", ".")
	gitT(t, src, "commit", "-q", "-m", "app")
	mods, err := Swift{Repo: "github.com/acme/app"}.Modules(context.Background(), src, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, fs := range mods[0].Files {
		files = append(files, fs...)
	}
	slices.Sort(files)
	if want := []string{"Package.swift", "Sources/App/café.swift", "Sources/App/two words.swift"}; !slices.Equal(files, want) {
		t.Fatalf("files %q, want %q", files, want)
	}
}
