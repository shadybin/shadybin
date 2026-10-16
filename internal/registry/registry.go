// Package registry lays out the registry repository: one directory per project, holding
// how to rebuild it and one directory per certified release.
//
//	<repo>/project.json            how to rebuild the project
//	<repo>/badge.json              shields.io endpoint badge: the latest release, its standing
//	<repo>/<tag>/badge.json        the release's own badge
//	<repo>/latest                  the newest certified release's tag: the next review's base
//	<repo>/<tag>/statement.txt     what was certified (package verify)
//	<repo>/<tag>/statement.txt.sig shadybin's signatures over it
//	<repo>/<tag>/manifest.json     what the code can do (package manifest)
//	<repo>/<tag>/review.json       the reviewer's answers (package review)
//	<repo>/<tag>/report.md         all of it, for people
//	deps/<module>@<version>/       the shared cache of dependency reviews (package review)
package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shadybin/shadybin/verify"
)

// Project is a project's project.json: how shadybin rebuilds and reviews a release. It
// lives in the registry, not the vendor's repository, so a vendor cannot change how its own
// release is checked from the release it is checking.
type Project struct {
	// Repo is the source repository, host/owner/name, lowercase.
	Repo string `json:"repo"`
	// Clone is the URL to clone; empty means https://<repo>.git.
	Clone string `json:"clone,omitempty"`
	// Language is go, zig or rust: how the code compiled in is found.
	Language string `json:"language"`
	// Builds rebuild the release; each runs on its own runner, as the vendor's release
	// does, since a binary for macOS may need macOS to build.
	Builds []Build `json:"builds"`
	// Checksums names the release assets listing the published files' digests, in
	// sha256sum's format: one file (checksums.txt), or a pattern for one per asset (*.sha256).
	Checksums string `json:"checksums"`
	// Analyze says what goes into the binaries.
	Analyze Analyze `json:"analyze"`
	// Owned are module prefixes the vendor controls besides its repository; empty means
	// everything under the repository's owner, github.com/owner/.
	Owned []string `json:"owned,omitempty"`
	// Vendored are third-party copies in the repository, each checked against the
	// upstream release it claims to be. One that matches is third-party code; one that
	// does not is the vendor's, and reviewed whole.
	Vendored []Vendored `json:"vendored,omitempty"`
}

// Build is one rebuild: a runner, its toolchain, the commands, and the files they make.
type Build struct {
	// Runner is the GitHub-hosted runner label, such as ubuntu-24.04 or macos-15.
	Runner string `json:"runner"`
	// Toolchain names versions to install, by tool: go (a version, or "go.mod"), zig, rust
	// (a version, or "rust-toolchain.toml").
	Toolchain map[string]string `json:"toolchain,omitempty"`
	// Run are shell commands run in order in the checked-out tag.
	Run []string `json:"run"`
	// Artifacts are globs, relative to the checkout, of the files the build makes.
	Artifacts []string `json:"artifacts"`
	// Env is set for the build, on top of SOURCE_DATE_EPOCH.
	Env map[string]string `json:"env,omitempty"`
}

// Analyze names what is built into the release's binaries.
type Analyze struct {
	// Packages are, for Go, the main packages; for Rust, the binary crates (empty: all).
	Packages []string `json:"packages,omitempty"`
	// Targets are, for Go, the GOOS values; for Rust, the target triples.
	Targets []string `json:"targets,omitempty"`
	// Files are other files that shape the binary, such as the release tool's
	// configuration, reviewed with the project's code.
	Files []string `json:"files,omitempty"`
	// Exclude are git pathspecs of files in the repository never compiled in, such as
	// tests, for languages whose build does not say which files it reads.
	Exclude []string `json:"exclude,omitempty"`
}

// Vendored is a third-party copy kept in the repository.
type Vendored struct {
	// Path is the directory in the repository.
	Path string `json:"path"`
	// Name and Version name the upstream release.
	Name    string `json:"name"`
	Version string `json:"version"`
	// URL is the upstream release archive, and SHA256 its digest.
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// CloneURL is where the project's source is cloned from.
func (p *Project) CloneURL() string {
	if p.Clone != "" {
		return p.Clone
	}
	return "https://" + p.Repo + ".git"
}

// LoadProject reads and checks a project.json.
func LoadProject(path string) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Project
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := verify.ValidRepo(p.Repo); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch p.Language {
	case "go":
		if len(p.Analyze.Packages) == 0 || len(p.Analyze.Targets) == 0 {
			return nil, fmt.Errorf("%s: a go project names its analyze packages and targets", path)
		}
	case "zig", "rust":
	default:
		return nil, fmt.Errorf("%s: language %q: want go, zig or rust", path, p.Language)
	}
	if len(p.Builds) == 0 || p.Checksums == "" {
		return nil, fmt.Errorf("%s: builds and checksums are required", path)
	}
	for i, b := range p.Builds {
		if b.Runner == "" || len(b.Run) == 0 || len(b.Artifacts) == 0 {
			return nil, fmt.Errorf("%s: build %d needs a runner, run and artifacts", path, i)
		}
	}
	return &p, nil
}

// ProjectDir is a project's directory in the registry.
func ProjectDir(root, repo string) (string, error) {
	if err := verify.ValidRepo(repo); err != nil {
		return "", err
	}
	return filepath.Join(root, filepath.FromSlash(repo)), nil
}

// ReleaseDir is a release's directory in the registry.
func ReleaseDir(root, repo, tag string) (string, error) {
	dir, err := ProjectDir(root, repo)
	if err != nil {
		return "", err
	}
	if err := verify.ValidTag(tag); err != nil {
		return "", err
	}
	return filepath.Join(dir, tag), nil
}

// Badge is shields.io's endpoint badge schema.
type Badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

// Published records a newly signed release: its own badge shows its verdict, and
// latest, the base the next release is reviewed against, moves only to a certified one.
// Rejected code never becomes the base, or what it hid would never be shown to a reviewer
// again. The project's badge follows the project's latest release, signed or not: see
// WriteBadges.
func Published(root, repo, tag, verdict string) error {
	release, err := ReleaseDir(root, repo, tag)
	if err != nil {
		return err
	}
	if err := writeBadge(filepath.Join(release, BadgeName), badgeFor(tag, verdict)); err != nil {
		return err
	}
	if verdict != verify.Certified {
		return nil
	}
	dir, _ := ProjectDir(root, repo)
	return os.WriteFile(filepath.Join(dir, "latest"), []byte(tag+"\n"), 0o644)
}

// PendingFor is how long a release may go unsigned before its badge says so: time for
// the vendor's certify run and the next intake.
const PendingFor = 24 * time.Hour

// Badge states, beyond the verdicts.
const (
	// Pending is a release published under PendingFor ago with no statement yet.
	Pending = "pending"
	// NotCertified is a release with no statement after PendingFor: never certified, or
	// its certification failed.
	NotCertified = "not certified"
)

// WriteBadges points the project's badge at its latest release, the one users are
// getting, whatever shadybin has made of it: its verdict once signed, pending at first,
// then not certified. A vendor cannot keep an old release's badge by not certifying a
// new one. It also writes the release's own badge, if it has none yet.
func WriteBadges(root, repo, tag string, published, now time.Time) error {
	dir, err := ProjectDir(root, repo)
	if err != nil {
		return err
	}
	release, err := ReleaseDir(root, repo, tag)
	if err != nil {
		return err
	}
	state := State(root, repo, tag, published, now)
	b := badgeFor(tag, state)
	if err := writeBadge(filepath.Join(dir, BadgeName), b); err != nil {
		return err
	}
	if state == Pending || state == NotCertified {
		if err := os.MkdirAll(release, 0o755); err != nil {
			return err
		}
		return writeBadge(filepath.Join(release, BadgeName), b)
	}
	return nil
}

// State is a release's standing: its verdict when the registry holds its signed
// statement, otherwise Pending or NotCertified, by how long ago it was published.
func State(root, repo, tag string, published, now time.Time) string {
	if release, err := ReleaseDir(root, repo, tag); err == nil {
		data, err := os.ReadFile(filepath.Join(release, verify.StatementName))
		_, sigErr := os.Stat(filepath.Join(release, verify.SignatureName))
		if err == nil && sigErr == nil {
			if s, err := verify.ParseStatement(data); err == nil {
				return s.Verdict
			}
		}
	}
	if now.Sub(published) < PendingFor {
		return Pending
	}
	return NotCertified
}

func badgeFor(tag, state string) Badge {
	b := Badge{SchemaVersion: 1, Label: "shadybin"}
	switch state {
	case verify.Certified:
		b.Message, b.Color = tag+" not shady", "brightgreen"
	case verify.Rejected:
		b.Message, b.Color = tag+" shady", "red"
	case Pending:
		b.Message, b.Color = tag+" pending", "lightgrey"
	default:
		b.Message, b.Color = tag+" not certified", "orange"
	}
	return b
}

func writeBadge(path string, b Badge) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// BadgeName is a badge's file, for shields.io's endpoint badge:
// https://img.shields.io/endpoint?url=https://shadybin.dev/registry/<repo>/badge.json
const BadgeName = "badge.json"

// ErrExists means a release directory already holds a statement: a certified release is
// never rewritten, only a new tag is certified.
var ErrExists = errors.New("the registry already has a statement for this release")
