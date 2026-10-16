package review

import (
	"context"
	"io"
	"path/filepath"
	"strings"
)

// Module is code compiled into a release, grouped the way its language groups it: a Go
// module, a Zig package, a Rust crate.
type Module struct {
	// Path names the module: its import path, package name or crate name.
	Path string
	// Version is the version compiled in; empty for the project and for local code.
	Version string
	// Dir holds the module's files.
	Dir string
	// Main is the project itself.
	Main bool
	// InRepo means the module's files are tracked in the vendor's repository, where the
	// vendor can edit them, whatever their origin.
	InRepo bool
	// Upstream, set for code in the repository that a check found identical to a
	// third-party release, names that release. Such code is third-party, not the vendor's.
	Upstream string
	// Provenance says whether the published package was checked against its source
	// repository: "", "from its repository" (built or fetched from it), "matches <repo>@<commit>",
	// "differs from <repo>@<commit>" or "not checkable: <why>".
	Provenance string
	// Foreign are files, relative to Dir, in the published package but not in its source
	// repository at the commit it claims, or different there: where the xz backdoor hid.
	// They are always shown to the reviewer.
	Foreign []string
	// Files maps each package of the module compiled in to its files, relative to Dir.
	Files map[string][]string

	// repoPath is where a vendored copy sits in the repository; an older version of it
	// comes from git, not from its language's package source.
	repoPath string
	// repository is the source repository a published package names, for its provenance.
	repository string
}

// provenanceChecker is a Source that can compare a published package with its source
// repository, filling in Provenance and Foreign. It runs only for a third-party package
// about to be reviewed: one new to the project or at a new version.
type provenanceChecker interface {
	CheckProvenance(ctx context.Context, m *Module, log io.Writer) error
}

// Source lists what a project compiles into its release. There is one per language.
type Source interface {
	// Modules returns every module compiled in, the project's own and its dependencies'.
	Modules(ctx context.Context, src string, log io.Writer) ([]*Module, error)
	// Fetch returns a directory holding a dependency at another version, to diff against.
	Fetch(ctx context.Context, src string, m *Module, version string, log io.Writer) (string, error)
	// Excludes are git pathspecs, relative to the checkout, of files in the project that are
	// never compiled in, such as tests, left out of the project's diff.
	Excludes() []string
}

// owned reports whether the vendor controls a module's code, so it is reviewed: the
// project, anything in the project's repository (vendored or replaced code, whatever its
// origin, since the vendor can edit it there), and modules under the vendor's own
// prefixes. Everything else is third-party: fetched by a checksum someone else's
// published code has to match, so pinned and listed, but not reviewed.
func owned(m *Module, src string, prefixes []string) bool {
	if m.Upstream != "" {
		return false
	}
	if m.Main || m.InRepo {
		return true
	}
	for _, p := range prefixes {
		if m.Path == strings.TrimSuffix(p, "/") || strings.HasPrefix(m.Path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

func inside(dir, root string) bool {
	if dir == "" || root == "" {
		return false
	}
	d, r := realPath(dir), realPath(root)
	return d == r || strings.HasPrefix(d, r+string(filepath.Separator))
}

// realPath is a path made absolute with its symlinks resolved, so paths from different tools
// (go list reports /private/var where a temporary directory says /var) compare.
func realPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

// OwnedPrefixes is the default for a repository: everything under its owner,
// github.com/owner/.
func OwnedPrefixes(repo string) []string {
	parts := strings.Split(repo, "/")
	if len(parts) < 3 {
		return nil
	}
	return []string{parts[0] + "/" + parts[1] + "/"}
}
