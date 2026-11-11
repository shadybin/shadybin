package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	cleanenv "github.com/shadybin/shadybin/internal/env"
)

// Swift is the Source for Swift packages. Package.swift is a program: evaluating it, as
// `swift package` does, would run the vendor's code in the job that holds the API key and
// attests. So it never runs. The project's files are those git tracks, but for tests and
// Exclude; its dependencies are every package Package.resolved pins, each fetched from its
// repository at the pinned commit, with its submodules, as SwiftPM fetches it. A pin the
// build does not use is reviewed anyway: knowing which ones it uses would mean running the
// manifest. A package's files are all of its tree but for tests and documentation, since
// which targets a product links is also only known by running its manifest.
type Swift struct {
	// Repo names the project's module: github.com/owner/name.
	Repo string
	// Exclude are git pathspecs of project files never compiled in.
	Exclude []string
	// PreviousTag is the last certified release, whose Package.resolved names the commits
	// of older versions.
	PreviousTag string
}

// swiftResolved is Package.resolved, versions 2 and 3: SwiftPM's lockfile, which pins every
// package in the dependency graph, transitive ones included, to a commit.
type swiftResolved struct {
	Version int        `json:"version"`
	Pins    []swiftPin `json:"pins"`
}

type swiftPin struct {
	Identity string `json:"identity"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
	State    struct {
		Revision string `json:"revision"`
		Version  string `json:"version"`
		Branch   string `json:"branch"`
	} `json:"state"`
}

// Modules lists the project's files and fetches every pinned package.
func (s Swift) Modules(ctx context.Context, src string, log io.Writer) ([]*Module, error) {
	files, err := gitOut(ctx, src, log, append([]string{"ls-files", "--", "."}, s.Excludes()...)...)
	if err != nil {
		return nil, err
	}
	mods := []*Module{{Path: s.Repo, Dir: src, Main: true, InRepo: true, Files: byDir(s.Repo, strings.Fields(files))}}
	pins, err := readSwiftResolved(src)
	if err != nil {
		return nil, err
	}
	for _, pin := range pins {
		dir, err := fetchSwiftPackage(ctx, pin.Location, pin.State.Revision, log)
		if err != nil {
			return nil, fmt.Errorf("swift package %s: %w", pin.Identity, err)
		}
		files, err := walkSwiftPackage(dir)
		if err != nil {
			return nil, err
		}
		name, _ := swiftModulePath(pin.Location)
		version := pin.State.Version
		if version == "" {
			version = pin.State.Revision
		}
		mods = append(mods, &Module{Path: name, Version: version, Dir: dir, Provenance: "from its repository", Files: byDir(name, files)})
	}
	return mods, nil
}

// readSwiftResolved reads and checks the project's Package.resolved. A manifest that
// declares packages but has no Package.resolved would have the build resolve them afresh,
// to code nothing pinned, so it is refused.
func readSwiftResolved(src string) ([]swiftPin, error) {
	data, err := os.ReadFile(filepath.Join(src, "Package.resolved"))
	if errors.Is(err, fs.ErrNotExist) {
		manifest, err := os.ReadFile(filepath.Join(src, "Package.swift"))
		if err != nil {
			return nil, fmt.Errorf("no Package.swift: %w", err)
		}
		if strings.Contains(string(manifest), ".package(") {
			return nil, errors.New("Package.swift declares packages but there is no Package.resolved to pin them")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r swiftResolved
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("Package.resolved: %w", err)
	}
	if r.Version != 2 && r.Version != 3 {
		return nil, fmt.Errorf("Package.resolved: version %d: want 2 or 3", r.Version)
	}
	for _, pin := range r.Pins {
		if pin.Kind != "remoteSourceControl" {
			return nil, fmt.Errorf("Package.resolved: %s is a %s package: only packages from a git repository can be checked", pin.Identity, pin.Kind)
		}
		if !swiftRevision.MatchString(pin.State.Revision) {
			return nil, fmt.Errorf("Package.resolved: %s pins no commit", pin.Identity)
		}
		if _, err := swiftModulePath(pin.Location); err != nil {
			return nil, fmt.Errorf("Package.resolved: %s: %w", pin.Identity, err)
		}
	}
	slices.SortFunc(r.Pins, func(a, b swiftPin) int { return strings.Compare(a.Location, b.Location) })
	return r.Pins, nil
}

var swiftRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)

// swiftModulePath names a package by its repository: host/path, without .git. Only https
// repositories are fetched: any other transport could reach the runner's own files or run
// a program.
func swiftModulePath(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil || !slices.Contains(swiftFetchProtocols, u.Scheme) || (u.Host == "" && u.Scheme != "file") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not an https repository", location)
	}
	p := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	if p == "" || strings.Contains(p, "..") {
		return "", fmt.Errorf("%q is not an https repository", location)
	}
	return strings.ToLower(u.Host) + p, nil
}

// swiftFetchProtocols are the URL schemes, and git transports, a package may be fetched
// over. Tests add file, for repositories they make on disk.
var swiftFetchProtocols = []string{"https"}

// fetchSwiftPackage checks out a package's repository at revision, with its submodules, as
// SwiftPM does, into a directory of its own. git runs with no credentials, no prompts, and
// only the allowed transports, for the package and its submodules alike.
func fetchSwiftPackage(ctx context.Context, location, revision string, log io.Writer) (string, error) {
	dir, err := os.MkdirTemp("", "shadybin-swift-")
	if err != nil {
		return "", err
	}
	run := func(args ...string) (string, error) {
		safe := []string{"-c", "protocol.allow=never", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null"}
		for _, p := range swiftFetchProtocols {
			safe = append(safe, "-c", "protocol."+p+".allow=always")
		}
		var out strings.Builder
		cmd := exec.CommandContext(ctx, "git", append(safe, args...)...)
		cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &out, log
		env, _ := cleanenv.Clean(os.Environ())
		cmd.Env = append(env, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(out.String()), nil
	}
	// origin is the package's repository, which relative submodule URLs are resolved against.
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", location}, {"fetch", "-q", "--depth", "1", "origin", revision}} {
		if _, err := run(args...); err != nil {
			return "", err
		}
	}
	if got, err := run("rev-parse", "FETCH_HEAD"); err != nil || got != revision {
		return "", fmt.Errorf("%s fetched %s, but Package.resolved pins %s", location, got, revision)
	}
	if _, err := run("checkout", "-q", "--detach", "FETCH_HEAD"); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitmodules")); err == nil {
		if _, err := run("submodule", "update", "-q", "--init", "--recursive", "--depth", "1"); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// walkSwiftPackage lists a fetched package's files, leaving out what SwiftPM never builds
// into a product: git's own files, tests, benchmarks, examples and documentation catalogs.
func walkSwiftPackage(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, abs)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch {
			case d.Name() == ".git", strings.HasSuffix(d.Name(), ".docc"):
				return filepath.SkipDir
			}
			switch rel {
			case "Tests", "Benchmarks", "Examples", "Snippets", ".build", ".swiftpm":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ".git" {
			return nil // a submodule's gitlink file
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// A link within the package names files listed under their own paths. One that
			// leaves it would have the review read the runner's files, and the build compile
			// code no pin covers.
			target, err := filepath.EvalSymlinks(abs)
			if err != nil || !inside(target, dir) {
				return fmt.Errorf("swift package: %s links outside the package", rel)
			}
			return nil
		}
		files = append(files, rel)
		return nil
	})
	return files, err
}

// Fetch checks out a package at another version: the previous release's Package.resolved
// names its commit.
func (s Swift) Fetch(ctx context.Context, src string, m *Module, version string, log io.Writer) (string, error) {
	if s.PreviousTag == "" {
		return "", fmt.Errorf("swift package %s: no previous release to fetch it from", m.Path)
	}
	data, err := gitOut(ctx, src, log, "show", s.PreviousTag+":Package.resolved")
	if err != nil {
		return "", err
	}
	var r swiftResolved
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return "", fmt.Errorf("Package.resolved of %s: %w", s.PreviousTag, err)
	}
	for _, pin := range r.Pins {
		name, err := swiftModulePath(pin.Location)
		if err != nil || name != m.Path || (pin.State.Version != version && pin.State.Revision != version) {
			continue
		}
		if !swiftRevision.MatchString(pin.State.Revision) {
			return "", fmt.Errorf("Package.resolved of %s: %s pins no commit", s.PreviousTag, pin.Identity)
		}
		return fetchSwiftPackage(ctx, pin.Location, pin.State.Revision, log)
	}
	return "", fmt.Errorf("swift package %s@%s is not in %s's Package.resolved", m.Path, version, s.PreviousTag)
}

// Excludes leave out tests and benchmarks, which SwiftPM never builds into a product, and
// the project's own Exclude.
func (s Swift) Excludes() []string {
	out := []string{":(exclude)Tests/**", ":(exclude)Benchmarks/**"}
	for _, e := range s.Exclude {
		if !strings.HasPrefix(e, ":") {
			e = ":(exclude)" + e
		}
		out = append(out, e)
	}
	return out
}
