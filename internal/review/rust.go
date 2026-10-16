package review

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"

	cleanenv "github.com/shadybin/shadybin/internal/env"
)

// Rust is the Source for Rust projects: the crates cargo metadata says the release's
// binaries are built from, for each target, through normal and build dependencies (build
// scripts and proc macros run at build time, so their code counts). Dev-dependencies are
// never compiled in.
type Rust struct {
	// Repo names the project: github.com/owner/name.
	Repo string
	// Packages are the binary crates released; empty means every workspace member.
	Packages []string
	// Targets are target triples; empty means the host.
	Targets []string
	// Exclude are git pathspecs of project files never compiled in.
	Exclude []string
}

type cargoMetadata struct {
	Packages []struct {
		Name, Version, ID string
		Source            *string
		Repository        *string
		ManifestPathJSON  string `json:"manifest_path"`
	} `json:"packages"`
	WorkspaceMembers []string `json:"workspace_members"`
	Resolve          struct {
		Nodes []struct {
			ID   string `json:"id"`
			Deps []struct {
				Pkg      string `json:"pkg"`
				DepKinds []struct {
					Kind *string `json:"kind"`
				} `json:"dep_kinds"`
			} `json:"deps"`
		} `json:"nodes"`
	} `json:"resolve"`
}

// Modules lists every crate compiled into the released binaries, for each target.
func (r Rust) Modules(ctx context.Context, src string, log io.Writer) ([]*Module, error) {
	targets := r.Targets
	if len(targets) == 0 {
		targets = []string{""}
	}
	mods := map[string]*Module{}
	for _, target := range targets {
		args := []string{"metadata", "--format-version", "1", "--locked"}
		if target != "" {
			args = append(args, "--filter-platform", target)
		}
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "cargo", args...)
		cmd.Dir, cmd.Stdout, cmd.Stderr = src, &out, log
		cmd.Env = cargoEnv()
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("cargo metadata %s: %w", target, err)
		}
		var md cargoMetadata
		if err := json.Unmarshal(out.Bytes(), &md); err != nil {
			return nil, fmt.Errorf("cargo metadata: %w", err)
		}
		if err := r.add(ctx, src, &md, mods, log); err != nil {
			return nil, err
		}
	}
	var out []*Module
	for _, k := range slices.Sorted(maps.Keys(mods)) {
		out = append(out, mods[k])
	}
	return out, nil
}

func (r Rust) add(ctx context.Context, src string, md *cargoMetadata, mods map[string]*Module, log io.Writer) error {
	byID := map[string]int{}
	for i, p := range md.Packages {
		byID[p.ID] = i
	}
	deps := map[string][]string{}
	for _, n := range md.Resolve.Nodes {
		for _, d := range n.Deps {
			for _, k := range d.DepKinds {
				if k.Kind == nil || *k.Kind == "build" {
					deps[n.ID] = append(deps[n.ID], d.Pkg)
					break
				}
			}
		}
	}
	var queue []string
	for _, id := range md.WorkspaceMembers {
		if len(r.Packages) == 0 || slices.Contains(r.Packages, md.Packages[byID[id]].Name) {
			queue = append(queue, id)
		}
	}
	if len(queue) == 0 {
		return fmt.Errorf("cargo metadata: no workspace member is one of %v", r.Packages)
	}
	first := queue[0]
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		queue = append(queue, deps[id]...)
		p := md.Packages[byID[id]]
		dir := filepath.Dir(p.ManifestPathJSON)
		key := p.Name + "@" + p.Version
		if mods[key] != nil {
			continue
		}
		var m *Module
		switch {
		case p.Source == nil:
			// A path crate: in the repository, it is the vendor's code.
			rel, err := filepath.Rel(realPath(src), realPath(dir))
			if err != nil || strings.HasPrefix(rel, "..") {
				return fmt.Errorf("crate %s: path %s is outside the repository", p.Name, dir)
			}
			name := r.Repo
			if rel != "." {
				name = r.Repo + "/" + filepath.ToSlash(rel)
			}
			files, err := gitOut(ctx, src, log, append([]string{"ls-files", "--", rel}, r.Excludes()...)...)
			if err != nil {
				return err
			}
			m = &Module{Path: name, Dir: src, Main: id == first, InRepo: true, Files: byDir(name, strings.Fields(files))}
		case strings.HasPrefix(*p.Source, "git+"):
			repo, commit := gitSource(*p.Source)
			files, err := walkCrate(dir)
			if err != nil {
				return err
			}
			name := repo + "#" + p.Name
			m = &Module{Path: name, Version: commit, Dir: dir, InRepo: inside(dir, src), Provenance: "from its repository", Files: byDir(name, files)}
		default:
			files, err := walkCrate(dir)
			if err != nil {
				return err
			}
			// Source replacement in .cargo/config.toml can serve a crates.io crate from a
			// directory in the repository, and cargo still names crates.io as its source.
			// There the vendor can edit it, so it is the vendor's code, reviewed whole.
			name := "crates.io/" + p.Name
			m = &Module{Path: name, Version: p.Version, Dir: dir, InRepo: inside(dir, src), Files: byDir(name, files)}
			if p.Repository != nil {
				m.repository = *p.Repository
			}
		}
		mods[key] = m
	}
	return nil
}

// walkCrate lists a published crate's files, leaving out what cargo never builds into a
// binary: tests, benches and examples.
func walkCrate(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, abs)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch rel {
			case "tests", "benches", "examples", "target", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		switch rel {
		case ".cargo-ok", ".cargo_vcs_info.json":
			return nil
		}
		files = append(files, rel)
		return nil
	})
	return files, err
}

func gitSource(src string) (repo, commit string) {
	s := strings.TrimPrefix(src, "git+")
	s, commit, _ = strings.Cut(s, "#")
	if u, err := url.Parse(s); err == nil {
		return u.Host + strings.TrimSuffix(u.Path, ".git"), commit
	}
	return s, commit
}

// Fetch downloads a crate at another version from crates.io.
func (Rust) Fetch(ctx context.Context, _ string, m *Module, version string, _ io.Writer) (string, error) {
	name, ok := strings.CutPrefix(m.Path, "crates.io/")
	if !ok {
		return "", fmt.Errorf("%s: only crates.io crates can be fetched at another version", m.Path)
	}
	a, err := fetchCrate(ctx, name, version)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "shadybin-crate-")
	if err != nil {
		return "", err
	}
	return writeArchive(a, dir)
}

func fetchCrate(ctx context.Context, name, version string) (archive, error) {
	u := "https://static.crates.io/crates/" + url.PathEscape(name) + "/" + url.PathEscape(name) + "-" + url.PathEscape(version) + ".crate"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive))
	if err != nil {
		return nil, err
	}
	return readArchive(u, data)
}

// Excludes leave out tests, benches and examples, which cargo build never compiles into a
// binary, and the project's own Exclude.
func (r Rust) Excludes() []string {
	out := []string{":(exclude)**/tests/**", ":(exclude)**/benches/**", ":(exclude)**/examples/**", ":(exclude)tests/**", ":(exclude)benches/**", ":(exclude)examples/**"}
	for _, e := range r.Exclude {
		if !strings.HasPrefix(e, ":") {
			e = ":(exclude)" + e
		}
		out = append(out, e)
	}
	return out
}

// CheckProvenance compares a crates.io crate with its repository at the commit its
// .cargo_vcs_info.json names. cargo publish uploads whatever the maintainer's directory
// holds, so a crate can carry files its repository never had, as the xz release tarball
// did; those are Foreign. A crate that names no repository or commit is not checkable.
func (Rust) CheckProvenance(ctx context.Context, m *Module, log io.Writer) error {
	if !strings.HasPrefix(m.Path, "crates.io/") {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(m.Dir, ".cargo_vcs_info.json"))
	if err != nil {
		m.Provenance = "not checkable: the crate names no commit (no .cargo_vcs_info.json)"
		return nil
	}
	var info struct {
		Git struct {
			SHA1 string `json:"sha1"`
		} `json:"git"`
		PathInVCS string `json:"path_in_vcs"`
	}
	if json.Unmarshal(data, &info) != nil || info.Git.SHA1 == "" || m.repository == "" {
		m.Provenance = "not checkable: the crate names no repository or commit"
		return nil
	}
	tmp, err := os.MkdirTemp("", "shadybin-vcs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, args := range [][]string{{"init", "-q"}, {"fetch", "-q", "--depth", "1", m.repository, info.Git.SHA1}} {
		if _, err := gitOut(ctx, tmp, log, args...); err != nil {
			m.Provenance = "not checkable: " + m.repository + " at " + info.Git.SHA1 + " could not be fetched"
			return nil
		}
	}
	where := strings.TrimSuffix(m.repository, ".git") + "@" + info.Git.SHA1
	var foreign []string
	for _, files := range m.Files {
		for _, f := range files {
			repoFile := f
			switch f {
			case "Cargo.toml", "Cargo.lock":
				continue // cargo publish rewrites the manifest and may add a lockfile
			case "Cargo.toml.orig":
				repoFile = "Cargo.toml"
			}
			want, err := os.ReadFile(filepath.Join(m.Dir, filepath.FromSlash(f)))
			if err != nil {
				return err
			}
			got, err := gitOut(ctx, tmp, io.Discard, "show", "FETCH_HEAD:"+path.Join(info.PathInVCS, repoFile))
			if err != nil || got != string(want) {
				foreign = append(foreign, f)
			}
		}
	}
	slices.Sort(foreign)
	m.Foreign = foreign
	if len(foreign) == 0 {
		m.Provenance = "matches " + where
	} else {
		m.Provenance = fmt.Sprintf("differs from %s: %d files", where, len(foreign))
	}
	return nil
}

// cargoEnv is the environment cargo metadata runs in. cargo reads the vendor's
// .cargo/config.toml and rustup its rust-toolchain.toml, and either can name a program to
// run (a rustc wrapper, a rustc, a toolchain at a path), so the variables that outrank them
// pin rustc and turn wrappers off, and the toolchain is the one the caller chose, or
// stable: reading metadata needs no particular one.
func cargoEnv() []string {
	env, _ := cleanenv.Clean(os.Environ())
	toolchain := os.Getenv("RUSTUP_TOOLCHAIN")
	if toolchain == "" {
		toolchain = "stable"
	}
	return append(env, "RUSTUP_TOOLCHAIN="+toolchain, "RUSTC=rustc", "CARGO_BUILD_RUSTC=rustc",
		"RUSTC_WRAPPER=", "CARGO_BUILD_RUSTC_WRAPPER=", "RUSTC_WORKSPACE_WRAPPER=", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=")
}
