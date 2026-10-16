package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	cleanenv "github.com/shadybin/shadybin/internal/env"
)

// Go is the Source for Go projects: what go list says the patterns compile, for each GOOS.
type Go struct {
	Patterns, GOOS []string
}

// Modules lists the packages the patterns build for each GOOS, and the files compiled into
// each, by module. Tests and testdata are never compiled in.
func (g Go) Modules(ctx context.Context, src string, log io.Writer) ([]*Module, error) {
	mods := map[string]*Module{}
	for _, target := range g.GOOS {
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "go", append([]string{"list", "-deps", "-json"}, g.Patterns...)...)
		cmd.Dir, cmd.Stdout, cmd.Stderr = src, &out, log
		env, _ := cleanenv.Clean(os.Environ())
		cmd.Env = append(env, "GOOS="+target)
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("go list for %s: %w", target, err)
		}
		dec := json.NewDecoder(&out)
		for {
			var p struct {
				ImportPath, Dir string
				Standard        bool
				Module          *struct {
					Path, Version, Dir string
					Main               bool
					Replace            *struct{ Path, Version, Dir string }
				}
				GoFiles, CgoFiles, CFiles, CXXFiles, HFiles, SFiles, SysoFiles, EmbedFiles []string
			}
			if err := dec.Decode(&p); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("go list for %s: %w", target, err)
			}
			if p.Standard || p.Module == nil {
				continue
			}
			version, dir := p.Module.Version, p.Module.Dir
			if r := p.Module.Replace; r != nil {
				// A replacement is the code compiled in; a local one has no version.
				version, dir = r.Version, r.Dir
			}
			if dir == "" && inside(p.Dir, filepath.Join(src, "vendor")) {
				// With a vendor directory, go list names no module directory: the module's
				// copy is in the repository, where the vendor can edit it.
				dir = filepath.Join(src, "vendor", filepath.FromSlash(p.Module.Path))
			}
			m := mods[p.Module.Path]
			if m == nil {
				// proxy.golang.org builds a module's zip from its repository, and the checksum
				// database pins it, so a Go module cannot carry files its repository lacks.
				m = &Module{Path: p.Module.Path, Version: version, Dir: dir, Main: p.Module.Main,
					InRepo: inside(dir, src), Provenance: "from its repository", Files: map[string][]string{}}
				mods[p.Module.Path] = m
			}
			rel, err := filepath.Rel(dir, p.Dir)
			if err != nil {
				return nil, err
			}
			for _, list := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.HFiles, p.SFiles, p.SysoFiles, p.EmbedFiles} {
				for _, f := range list {
					f = filepath.ToSlash(filepath.Join(rel, f))
					if !slices.Contains(m.Files[p.ImportPath], f) {
						m.Files[p.ImportPath] = append(m.Files[p.ImportPath], f)
					}
				}
			}
		}
	}
	var out []*Module
	for _, path := range slices.Sorted(maps.Keys(mods)) {
		for p := range mods[path].Files {
			slices.Sort(mods[path].Files[p])
		}
		out = append(out, mods[path])
	}
	return out, nil
}

// Fetch downloads the module at another version into the module cache.
func (Go) Fetch(ctx context.Context, src string, m *Module, version string, log io.Writer) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "go", "mod", "download", "-json", m.Path+"@"+version)
	cmd.Dir, cmd.Stdout, cmd.Stderr = src, &out, log
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go mod download %s@%s: %w", m.Path, version, err)
	}
	var d struct{ Dir string }
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || d.Dir == "" {
		return "", fmt.Errorf("go mod download %s@%s: no directory", m.Path, version)
	}
	return d.Dir, nil
}

// Excludes leaves out tests, which go build never compiles in.
func (Go) Excludes() []string {
	return []string{":(exclude)*_test.go", ":(exclude)**/testdata/**"}
}
