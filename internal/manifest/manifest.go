// Package manifest records what a release's code can do: for every package in the binary,
// the capabilities it uses directly (files, network, running programs, ...), as Capslock
// finds them. Two releases' manifests diff into what a release newly does.
package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// Capslock is the analyser, pinned: a different version can classify the same code
// differently, and the manifests of two releases must be comparable.
const Capslock = "github.com/google/capslock/cmd/capslock@v0.3.4"

// Manifest is a release's manifest.json.
type Manifest struct {
	// Tool is the analyser that made it, Capslock's module and version.
	Tool string `json:"tool"`
	// Module is the main module's path, which the report shortens to ./.
	Module string `json:"module"`
	// GOOS are the target systems analysed; a package's capabilities are their union.
	GOOS []string `json:"goos"`
	// Packages are every package compiled into the binary outside the standard library.
	Packages []string `json:"packages"`
	// Modules map each dependency module compiled in to its version. The Go checksum
	// database makes module@version name the same code for everyone, so it is the key a
	// dependency's review is cached under and shared across projects.
	Modules map[string]string `json:"modules"`
	// Capabilities maps a package to the capabilities it uses directly, without the CAPABILITY_ prefix.
	Capabilities map[string][]string `json:"capabilities"`
}

// Marshal returns the manifest's bytes: sorted, indented, ending in a newline, so the same
// analysis always gives the same file.
func (m *Manifest) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Load reads a manifest.json.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Build analyses the packages (patterns, as for go list) in the module at src, for each
// GOOS. Capslock runs with go run, so the go on PATH must be able to build it.
func Build(ctx context.Context, src string, patterns, goos []string, log io.Writer) (*Manifest, error) {
	module, err := goCmd(ctx, src, nil, log, "list", "-m")
	if err != nil {
		return nil, err
	}
	m := &Manifest{Tool: Capslock, Module: module, GOOS: slices.Sorted(slices.Values(goos)),
		Modules: map[string]string{}, Capabilities: map[string][]string{}}
	pkgs := map[string]bool{}
	caps := map[string]map[string]bool{}
	for _, target := range m.GOOS {
		env := []string{"GOOS=" + target}
		deps, err := goCmd(ctx, src, env, log, append([]string{"list", "-deps", "-f",
			"{{if not .Standard}}{{.ImportPath}} {{with .Module}}{{.Path}} {{.Version}}{{end}}{{end}}"}, patterns...)...)
		if err != nil {
			return nil, err
		}
		var list []string
		for line := range strings.Lines(deps) {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			list = append(list, f[0])
			pkgs[f[0]] = true
			// The main module has no version; it is what the release itself reviews.
			if len(f) == 3 && f[1] != module {
				m.Modules[f[1]] = f[2]
			}
		}
		if len(list) == 0 {
			continue
		}
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "go", "run", Capslock, "-goos", target,
			"-packages", strings.Join(list, ","), "-output", "json", "-omit_paths")
		cmd.Dir, cmd.Stdout, cmd.Stderr = src, &out, log
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("capslock for %s: %w", target, err)
		}
		if err := merge(out.Bytes(), caps); err != nil {
			return nil, fmt.Errorf("capslock for %s: %w", target, err)
		}
	}
	m.Packages = slices.Sorted(maps.Keys(pkgs))
	for p, set := range caps {
		m.Capabilities[p] = slices.Sorted(maps.Keys(set))
	}
	return m, nil
}

// merge adds the direct capabilities in Capslock's JSON output to caps.
func merge(data []byte, caps map[string]map[string]bool) error {
	var out struct {
		CapabilityInfo []struct {
			PackageDir     string `json:"packageDir"`
			Capability     string `json:"capability"`
			CapabilityType string `json:"capabilityType"`
		} `json:"capabilityInfo"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	for _, c := range out.CapabilityInfo {
		// Transitive capabilities are everything a package can reach through its imports;
		// in any real binary nearly every package reaches nearly everything.
		if c.CapabilityType != "CAPABILITY_TYPE_DIRECT" || c.PackageDir == "" {
			continue
		}
		if caps[c.PackageDir] == nil {
			caps[c.PackageDir] = map[string]bool{}
		}
		caps[c.PackageDir][strings.TrimPrefix(c.Capability, "CAPABILITY_")] = true
	}
	return nil
}

func goCmd(ctx context.Context, dir string, env []string, log io.Writer, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &out, log
	cmd.Env = append(os.Environ(), env...)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(out.String()), nil
}
