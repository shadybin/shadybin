package cli

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/shadybin/shadybin/internal/manifest"
	"github.com/shadybin/shadybin/internal/registry"
	"github.com/shadybin/shadybin/internal/review"
)

// sourceFor is how a project's language finds the code compiled in. previousTag is the
// last certified release, which some languages fetch older dependencies against.
func sourceFor(p *registry.Project, previousTag string) review.Source {
	switch p.Language {
	case "go":
		return review.Go{Patterns: p.Analyze.Packages, GOOS: p.Analyze.Targets}
	case "zig":
		return review.Zig{Repo: p.Repo, Exclude: p.Analyze.Exclude, PreviousTag: previousTag}
	case "rust":
		return review.Rust{Repo: p.Repo, Packages: p.Analyze.Packages, Targets: p.Analyze.Targets, Exclude: p.Analyze.Exclude}
	}
	panic(fmt.Sprintf("no source for %q", p.Language))
}

// vendoredFor converts shadybin.json's vendored copies for the review.
func vendoredFor(p *registry.Project) []review.Vendored {
	var out []review.Vendored
	for _, v := range p.Vendored {
		out = append(out, review.Vendored{Path: v.Path, Name: v.Name, Version: v.Version, URL: v.URL, SHA256: v.SHA256})
	}
	return out
}

// buildManifest records what the code can do. Go has Capslock for capabilities; for other
// languages the manifest lists the packages and module versions compiled in.
func buildManifest(ctx context.Context, p *registry.Project, src string, log io.Writer) (*manifest.Manifest, error) {
	if p.Language == "go" {
		m, err := manifest.Build(ctx, src, p.Analyze.Packages, p.Analyze.Targets, log)
		if err != nil {
			return nil, err
		}
		for _, v := range p.Vendored {
			m.Modules[v.Name] = v.Version
		}
		return m, nil
	}
	mods, err := sourceFor(p, "").Modules(ctx, src, log)
	if err != nil {
		return nil, err
	}
	m := &manifest.Manifest{Tool: "none", GOOS: p.Analyze.Targets, Modules: map[string]string{}, Capabilities: map[string][]string{}}
	pkgs := map[string]bool{}
	for _, mod := range mods {
		if mod.Main {
			m.Module = mod.Path
		} else if mod.Version != "" {
			m.Modules[mod.Path] = mod.Version
		}
		for pkg := range mod.Files {
			pkgs[pkg] = true
		}
	}
	for _, v := range p.Vendored {
		m.Modules[v.Name] = v.Version
	}
	m.Packages = slices.Sorted(maps.Keys(pkgs))
	return m, nil
}
