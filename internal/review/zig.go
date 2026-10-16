package review

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Zig is the Source for Zig projects. Zig names no list of compiled files, so the project's
// are the files its build.zig.zon .paths name that git tracks, but for Exclude; a package's
// are those its own .paths name. Dependencies are the tree from build.zig.zon, fetched as
// the build needs them: a lazy one the build never asks for is not compiled in.
type Zig struct {
	// Repo names the project's module: github.com/owner/name.
	Repo string
	// Exclude are git pathspecs of project files never compiled in, such as tests.
	Exclude []string
	// PreviousTag is the last certified release, to fetch older dependencies against.
	PreviousTag string
}

// Modules fetches the dependency tree, then lists the project's files and every package's.
func (z Zig) Modules(ctx context.Context, src string, log io.Writer) ([]*Module, error) {
	if err := zigFetch(ctx, src, log); err != nil {
		return nil, err
	}
	root, err := readZon(filepath.Join(src, "build.zig.zon"))
	if err != nil {
		return nil, err
	}
	files, err := gitOut(ctx, src, log, append(append([]string{"ls-files", "--"}, zonPaths(root)...), z.Excludes()...)...)
	if err != nil {
		return nil, err
	}
	main := &Module{Path: z.Repo, Dir: src, Main: true, InRepo: true, Files: byDir(z.Repo, strings.Fields(files))}
	mods := []*Module{main}
	cacheDirs := zigCacheDirs(ctx, src, log)
	seen := map[string]bool{}
	var walk func(zon map[string]any, dir string) error
	walk = func(zon map[string]any, dir string) error {
		deps, _ := zon["dependencies"].(map[string]any)
		for _, name := range slices.Sorted(mapKeys(deps)) {
			dep, _ := deps[name].(map[string]any)
			if p, ok := dep["path"].(string); ok {
				// A path dependency is code beside the project's: in the repository, it is the
				// vendor's, and git's list of the project's files already has it if .paths does.
				local := filepath.Join(dir, filepath.FromSlash(p))
				if !inside(local, src) {
					return fmt.Errorf("zig dependency %s: path %s is outside the repository", name, p)
				}
				continue
			}
			u, _ := dep["url"].(string)
			hash, _ := dep["hash"].(string)
			if u == "" || hash == "" {
				return fmt.Errorf("zig dependency %s: want url and hash, or path", name)
			}
			if seen[hash] {
				continue
			}
			pkgDir := findPackage(cacheDirs, hash)
			if pkgDir == "" {
				if dep["lazy"] == "true" {
					continue // never fetched: the build did not need it
				}
				return fmt.Errorf("zig dependency %s (%s) was not fetched", name, hash)
			}
			seen[hash] = true
			m, sub, err := zigPackage(pkgDir, u, hash)
			if err != nil {
				return fmt.Errorf("zig dependency %s: %w", name, err)
			}
			mods = append(mods, m)
			if err := walk(sub, pkgDir); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, src); err != nil {
		return nil, err
	}
	return mods, nil
}

// zigPackage reads a fetched package: its files, by its .paths, and its manifest.
func zigPackage(dir, rawURL, hash string) (*Module, map[string]any, error) {
	zon := map[string]any{}
	if _, err := os.Stat(filepath.Join(dir, "build.zig.zon")); err == nil {
		var err error
		if zon, err = readZon(filepath.Join(dir, "build.zig.zon")); err != nil {
			return nil, nil, err
		}
	}
	paths := zonPaths(zon)
	if len(paths) == 0 {
		paths = []string{"."}
	}
	var files []string
	for _, p := range paths {
		err := filepath.WalkDir(filepath.Join(dir, filepath.FromSlash(p)), func(abs string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(dir, abs)
			files = append(files, filepath.ToSlash(rel))
			return err
		})
		if err != nil && !os.IsNotExist(err) {
			return nil, nil, err
		}
	}
	modPath, provenance := zigOrigin(rawURL)
	return &Module{Path: modPath, Version: hash, Dir: dir, Provenance: provenance, Files: byDir(modPath, files)}, zon, nil
}

// zigOrigin names a package by where it comes from, and says whether what was fetched
// is its repository's: a git URL is, and so is an archive GitHub makes from a tag or
// commit. Any other archive could hold anything its publisher put in it.
func zigOrigin(raw string) (string, string) {
	s := strings.TrimPrefix(raw, "git+")
	u, err := url.Parse(s)
	if err != nil {
		return raw, "not checkable: " + raw + " is not a URL"
	}
	p := strings.TrimSuffix(u.Path, ".git")
	name := u.Host + p
	switch {
	case strings.HasPrefix(raw, "git+"):
		return name, "from its repository"
	case u.Host == "github.com" && strings.Contains(p, "/archive/"):
		return u.Host + p[:strings.Index(p, "/archive/")], "from its repository (an archive GitHub makes from it)"
	case u.Host == "codeload.github.com":
		parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
		if len(parts) >= 2 {
			return "github.com/" + parts[0] + "/" + parts[1], "from its repository (an archive GitHub makes from it)"
		}
	}
	return name, "not checkable: an archive from " + u.Host + ", not a repository"
}

// Fetch finds a package at another hash: in a cache, or by fetching the previous release's
// dependency tree in a worktree of its tag.
func (z Zig) Fetch(ctx context.Context, src string, m *Module, hash string, log io.Writer) (string, error) {
	if dir := findPackage(zigCacheDirs(ctx, src, log), hash); dir != "" {
		return dir, nil
	}
	if z.PreviousTag == "" {
		return "", fmt.Errorf("zig package %s: no previous release to fetch it from", hash)
	}
	wt, err := os.MkdirTemp("", "shadybin-zig-prev-")
	if err != nil {
		return "", err
	}
	if _, err := gitOut(ctx, src, log, "worktree", "add", "--detach", wt, z.PreviousTag); err != nil {
		return "", err
	}
	if err := zigFetch(ctx, wt, log); err != nil {
		return "", err
	}
	if dir := findPackage(append([]string{filepath.Join(wt, "zig-pkg")}, zigCacheDirs(ctx, src, log)...), hash); dir != "" {
		return dir, nil
	}
	return "", fmt.Errorf("zig package %s is not in %s's dependency tree", hash, z.PreviousTag)
}

// Excludes are the project's Exclude, as git exclude pathspecs.
func (z Zig) Excludes() []string {
	var out []string
	for _, e := range z.Exclude {
		if !strings.HasPrefix(e, ":") {
			e = ":(exclude)" + e
		}
		out = append(out, e)
	}
	return out
}

func zigFetch(ctx context.Context, dir string, log io.Writer) error {
	cmd := exec.CommandContext(ctx, "zig", "build", "--fetch=needed")
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, log, log
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zig build --fetch: %w", err)
	}
	return nil
}

// zigCacheDirs are where fetched packages are: the project's zig-pkg, then Zig's global
// cache.
func zigCacheDirs(ctx context.Context, src string, log io.Writer) []string {
	dirs := []string{filepath.Join(src, "zig-pkg")}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "zig", "env")
	cmd.Stdout, cmd.Stderr = &out, log
	if cmd.Run() == nil {
		if env, err := parseZon(out.String()); err == nil {
			if m, ok := env.(map[string]any); ok {
				if g, ok := m["global_cache_dir"].(string); ok {
					dirs = append(dirs, filepath.Join(g, "p"))
				}
			}
		}
	}
	return dirs
}

func findPackage(dirs []string, hash string) string {
	if strings.ContainsAny(hash, `/\`) || hash == ".." {
		return ""
	}
	for _, d := range dirs {
		p := filepath.Join(d, hash)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}

func readZon(p string) (map[string]any, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	v, err := parseZon(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a struct", p)
	}
	return m, nil
}

func zonPaths(zon map[string]any) []string {
	list, _ := zon["paths"].([]any)
	var out []string
	for _, v := range list {
		if s, ok := v.(string); ok {
			if s == "" {
				s = "."
			}
			out = append(out, s)
		}
	}
	return out
}

// byDir groups files into packages by directory, named module/dir.
func byDir(module string, files []string) map[string][]string {
	out := map[string][]string{}
	for _, f := range files {
		pkg := module
		if d := path.Dir(f); d != "." {
			pkg = module + "/" + d
		}
		out[pkg] = append(out[pkg], f)
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

func mapKeys(m map[string]any) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
