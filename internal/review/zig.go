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

	cleanenv "github.com/shadybin/shadybin/internal/env"
)

// Zig is the Source for Zig projects. Zig names no list of compiled files, so the project's
// are the files its build.zig.zon .paths name that git tracks, but for Exclude; a package's
// are those its own .paths name. Dependencies are the whole tree build.zig.zon names, lazy
// ones too, fetched by URL and checked against their hashes. Nothing here runs a build.zig:
// knowing which lazy dependencies a build asks for would mean running the vendor's code in
// the job that holds the API key and attests, so every one is reviewed instead.
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
	f, err := newZigFetcher(src)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	seenPath := map[string]bool{}
	// walk reads the dependencies of the build.zig.zon in dir, which belongs to the package
	// in pkg: the repository, or a fetched package.
	var walk func(zon map[string]any, dir, pkg string) error
	walk = func(zon map[string]any, dir, pkg string) error {
		deps, _ := zon["dependencies"].(map[string]any)
		for _, name := range slices.Sorted(mapKeys(deps)) {
			dep, _ := deps[name].(map[string]any)
			if p, ok := dep["path"].(string); ok {
				// A path dependency is code beside its package's own: in the repository it is
				// the vendor's, and git's list of the project's files already has it if .paths
				// does; in a fetched package it was fetched and hashed with the package. Its own
				// dependencies are the build's too.
				local := filepath.Join(dir, filepath.FromSlash(p))
				if !inside(local, pkg) {
					where := "its package"
					if pkg == src {
						where = "the repository"
					}
					return fmt.Errorf("zig dependency %s: path %s is outside %s", name, p, where)
				}
				if seenPath[local] {
					continue
				}
				seenPath[local] = true
				if _, err := os.Stat(filepath.Join(local, "build.zig.zon")); err != nil {
					continue
				}
				sub, err := readZon(filepath.Join(local, "build.zig.zon"))
				if err != nil {
					return fmt.Errorf("zig dependency %s: %w", name, err)
				}
				if err := walk(sub, local, pkg); err != nil {
					return err
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
			pkgDir, err := f.get(ctx, u, hash, log)
			if err != nil {
				return fmt.Errorf("zig dependency %s: %w", name, err)
			}
			seen[hash] = true
			m, sub, err := zigPackage(pkgDir, u, hash)
			if err != nil {
				return fmt.Errorf("zig dependency %s: %w", name, err)
			}
			// A copy in the repository's zig-pkg is what the build uses, and the vendor can
			// edit it there: it is the vendor's code, reviewed whole and never cached.
			m.InRepo = inside(pkgDir, src)
			mods = append(mods, m)
			if err := walk(sub, pkgDir, pkgDir); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, src, src); err != nil {
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

// Fetch finds a package at another hash: the previous release's build.zig.zon names it,
// so its tree is fetched, as Modules fetches the current one, without running anything.
func (z Zig) Fetch(ctx context.Context, src string, m *Module, hash string, log io.Writer) (string, error) {
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
	root, err := readZon(filepath.Join(wt, "build.zig.zon"))
	if err != nil {
		return "", err
	}
	f, err := newZigFetcher(wt)
	if err != nil {
		return "", err
	}
	var find func(zon map[string]any, depth int) (string, error)
	find = func(zon map[string]any, depth int) (string, error) {
		deps, _ := zon["dependencies"].(map[string]any)
		for _, name := range slices.Sorted(mapKeys(deps)) {
			dep, _ := deps[name].(map[string]any)
			u, _ := dep["url"].(string)
			h, _ := dep["hash"].(string)
			if u == "" || h == "" {
				continue
			}
			dir, err := f.get(ctx, u, h, log)
			if err != nil {
				return "", fmt.Errorf("zig dependency %s of %s: %w", name, z.PreviousTag, err)
			}
			if h == hash {
				return dir, nil
			}
			if depth < 32 {
				sub := map[string]any{}
				if _, err := os.Stat(filepath.Join(dir, "build.zig.zon")); err == nil {
					if sub, err = readZon(filepath.Join(dir, "build.zig.zon")); err != nil {
						return "", err
					}
				}
				if d, err := find(sub, depth+1); err != nil || d != "" {
					return d, err
				}
			}
		}
		return "", nil
	}
	dir, err := find(root, 0)
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", fmt.Errorf("zig package %s is not in %s's dependency tree", hash, z.PreviousTag)
	}
	return dir, nil
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

// zigFetcher fetches packages by URL, in a directory of shadybin's own with an empty
// build.zig, so no build.zig of the vendor's or of a dependency's runs, and checks each
// against the hash build.zig.zon pins. A package the repository carries in its own zig-pkg
// is used from there, as the build would.
//
// Zig 0.17's `zig fetch` keeps only a compressed copy in the global cache; the unpacked
// tree a build uses appears in zig-pkg only when a build's dependency tree is fetched. So
// shadybin's own build.zig.zon names the package and `zig build --fetch`, which exits
// before any build.zig is compiled, fetches it, checks its hash and unpacks it. It uses a
// global cache of its own: a package `zig fetch` stored is read back with another hash.
type zigFetcher struct {
	repoPkgs string // the repository's zig-pkg
	work     string // shadybin's own directory to fetch in
}

func newZigFetcher(src string) (*zigFetcher, error) {
	work, err := os.MkdirTemp("", "shadybin-zig-fetch-")
	if err != nil {
		return nil, err
	}
	const empty = "const std = @import(\"std\");\npub fn build(b: *std.Build) void {\n    _ = b;\n}\n"
	if err := os.WriteFile(filepath.Join(work, "build.zig"), []byte(empty), 0o644); err != nil {
		return nil, err
	}
	return &zigFetcher{repoPkgs: filepath.Join(src, "zig-pkg"), work: work}, nil
}

// get returns the directory holding the package url names, which must hash to hash.
func (f *zigFetcher) get(ctx context.Context, url, hash string, log io.Writer) (string, error) {
	if !validZigHash(hash) {
		return "", fmt.Errorf("%q is not a package hash", hash)
	}
	if dir := filepath.Join(f.repoPkgs, hash); isDir(dir) {
		return dir, nil
	}
	dir := filepath.Join(f.work, "zig-pkg", hash)
	if isDir(dir) {
		return dir, nil
	}
	if err := f.fetch(ctx, url, hash, log); err != nil {
		return "", err
	}
	if !isDir(dir) {
		return "", fmt.Errorf("zig build --fetch %s left nothing in %s", url, dir)
	}
	return dir, nil
}

// fetchZon is shadybin's own build.zig.zon in the fetch directory, naming one package.
// The fingerprint is the one Zig requires for the name shadybin_fetch.
const fetchZon = `.{
    .name = .shadybin_fetch,
    .version = "0.0.0",
    .fingerprint = 0x95488693096f1dc4,
    .dependencies = .{
        .pkg = .{ .url = "%s", .hash = "%s" },
    },
    .paths = .{""},
}
`

// fetch has Zig fetch the package url names into the fetch directory's zig-pkg, as a
// build would, checked against hash. The url comes from the vendor's build.zig.zon, so
// anything that could end its string in shadybin's is refused rather than escaped.
func (f *zigFetcher) fetch(ctx context.Context, url, hash string, log io.Writer) error {
	if strings.ContainsFunc(url+hash, func(r rune) bool { return r == '"' || r == '\\' || r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%q cannot be named in a build.zig.zon", url)
	}
	zon := fmt.Sprintf(fetchZon, url, hash)
	if err := os.WriteFile(filepath.Join(f.work, "build.zig.zon"), []byte(zon), 0o644); err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "zig", "build", "--fetch")
	cmd.Dir, cmd.Stdout, cmd.Stderr = f.work, log, io.MultiWriter(log, &stderr)
	env, _ := cleanenv.Clean(os.Environ())
	cmd.Env = append(env, "ZIG_GLOBAL_CACHE_DIR="+filepath.Join(f.work, "cache"))
	if err := cmd.Run(); err != nil {
		if _, got, ok := strings.Cut(stderr.String(), "but the fetched package has "); ok {
			got, _, _ = strings.Cut(got, "\n")
			return fmt.Errorf("%s fetched as %s, but build.zig.zon pins %s", url, strings.TrimSpace(got), hash)
		}
		return fmt.Errorf("zig build --fetch %s: %w", url, err)
	}
	return nil
}

// validZigHash keeps a hash from naming a path outside the package directory.
func validZigHash(hash string) bool {
	return hash != "" && hash != "." && hash != ".." && !strings.ContainsAny(hash, `/\`)
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
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
