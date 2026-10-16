package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/shadybin/shadybin/internal/manifest"
)

// maxPart bounds one call's code, about 300k tokens: a unit larger than this is split by
// package, and a package larger than this by file.
const maxPart = 1_200_000

// maxReadme bounds the project README given as the vendor's own account of the tool.
const maxReadme = 20_000

// maxSurface bounds a third-party module's surface, about 500k tokens. Of a module whose
// surface is larger, only the packages with a sensitive capability are reviewed when it
// first appears, since the verdict needs each of them reviewed: a 5 MB generated API
// client is still read. The rest, such as SQLite's single 9 MB C file, stays pinned to
// the exact upstream release, the report says so, and every later version change is
// reviewed as a diff. A variable, so tests can make it small.
var maxSurface = 2_000_000

// Inputs is what the units are gathered from.
type Inputs struct {
	// Src is a clean checkout of the release's tag, with its tags fetched.
	Src string
	// Source lists what the project compiles in; one per language.
	Source Source
	// Owned are module path prefixes the vendor controls, beyond its repository.
	Owned []string
	// Extra are files outside the modules that shape the binary, such as the release
	// tool's configuration, relative to Src.
	Extra []string
	// Vendored are third-party copies in the repository to check against upstream.
	Vendored []Vendored
	// Manifest is the release's; Previous is the last certified release's, nil for none.
	Manifest, Previous *manifest.Manifest
	// PreviousTag is the last certified release's tag, empty for none.
	PreviousTag string
}

// Scopes: how much of a unit's code the model is shown.
const (
	// ScopeWhole is all of the code compiled in.
	ScopeWhole = "whole"
	// ScopeDiff is what changed since the version last reviewed.
	ScopeDiff = "diff"
	// ScopeSurface is the parts of a third-party module through which a supply-chain attack
	// gets in: what runs at build or load time, what is not plain source, and the packages
	// that can act on the world.
	ScopeSurface = "surface"
	// ScopeCapabilities is a third-party module whose surface is over maxSurface: its
	// packages with a sensitive capability reviewed whole, the rest of its surface pinned,
	// and reviewed as a diff when its version changes.
	ScopeCapabilities = "capabilities"
	// ScopeTooLarge is a third-party module whose surface is over maxSurface and has no
	// package with a sensitive capability: pinned, and not reviewed until its version
	// changes.
	ScopeTooLarge = "too large"
)

// ModuleInfo records how the review treated each module compiled in.
type ModuleInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	// Owned means the vendor controls the code.
	Owned bool `json:"owned"`
	// Scope is how it was reviewed: whole, diff or surface; "unchanged" when it is as the
	// last certified release had it, "none" when nothing in it needed review.
	Scope string `json:"scope"`
	// Provenance and Foreign are what the check of a published package against its
	// repository found (see Module).
	Provenance string   `json:"provenance,omitempty"`
	Foreign    []string `json:"foreign,omitempty"`
}

// Plan is the units to review, and how each module compiled in is treated.
type Plan struct {
	Units   []Unit
	Modules []ModuleInfo
}

// Gather plans the review. The vendor's code is reviewed whole, or as its diff since the
// last certified release. A third-party module is reviewed as its diff when its version
// changed, and at its surface when it first appears; at the version last certified, it was
// reviewed then and needs nothing.
func Gather(ctx context.Context, in Inputs, log io.Writer) (*Plan, error) {
	mods, err := in.Source.Modules(ctx, in.Src, log)
	if err != nil {
		return nil, err
	}
	mods, upstream, err := carveVendored(ctx, in.Src, in.Vendored, mods)
	if err != nil {
		return nil, err
	}
	plan := &Plan{}
	var inRepo []*Module
	for _, m := range mods {
		info := ModuleInfo{Path: m.Path, Version: m.Version, Owned: owned(m, in.Src, in.Owned)}
		var units []Unit
		switch {
		case info.Owned && (m.Main || m.InRepo):
			// Reviewed with the project: one diff covers everything in the repository.
			inRepo = append(inRepo, m)
			info.Scope = "project"
		default:
			units, info.Scope, err = moduleUnits(ctx, in, m, info.Owned, log)
		}
		if err != nil {
			return nil, err
		}
		info.Provenance, info.Foreign = m.Provenance, m.Foreign
		plan.Modules = append(plan.Modules, info)
		plan.Units = append(plan.Units, units...)
	}
	project, err := projectUnits(ctx, in, inRepo, upstream, log)
	if err != nil {
		return nil, err
	}
	plan.Units = append(project, plan.Units...)
	return plan, nil
}

// projectUnits review everything in the repository the binary compiles in, but for
// vendored files identical to upstream, which exclude keeps out of the diff.
func projectUnits(ctx context.Context, in Inputs, mods []*Module, exclude []string, log io.Writer) ([]Unit, error) {
	if len(mods) == 0 {
		return nil, nil
	}
	main := mods[0]
	for _, m := range mods {
		if m.Main {
			main = m
		}
	}
	var pkgs []string
	var dirs []string
	var pieces []piece
	for _, m := range mods {
		for _, pkg := range slices.Sorted(maps.Keys(m.Files)) {
			pkgs = append(pkgs, pkg)
			for _, f := range m.Files[pkg] {
				abs := filepath.Join(m.Dir, filepath.FromSlash(f))
				rel, err := filepath.Rel(realPath(in.Src), filepath.Join(realPath(m.Dir), filepath.FromSlash(f)))
				if err != nil {
					return nil, err
				}
				rel = filepath.ToSlash(rel)
				dirs = append(dirs, filepath.ToSlash(filepath.Dir(rel)))
				text, err := fileText(abs)
				if err != nil {
					return nil, err
				}
				pieces = append(pieces, piece{pkg: pkg, text: marker("file", rel, text)})
			}
		}
	}
	slices.Sort(pkgs)
	header := "Review unit: the project's own code, module " + main.Path
	readme := readmeExcerpt(in.Src)
	base := Unit{Kind: KindProject, Module: main.Path}

	if in.PreviousTag != "" && tagExists(ctx, in.Src, in.PreviousTag) {
		slices.Sort(dirs)
		args := append([]string{"diff", "--no-color", "--no-ext-diff", in.PreviousTag, "HEAD", "--"}, slices.Compact(dirs)...)
		args = append(args, in.Extra...)
		args = append(args, in.Source.Excludes()...)
		args = append(args, exclude...)
		diff, err := gitOut(ctx, in.Src, log, args...)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(diff) == "" {
			return nil, nil
		}
		u := base
		u.From, u.Scope, u.Part, u.Parts, u.Packages = in.PreviousTag, ScopeDiff, 1, 1, pkgs
		u.input = intro(u, header+", as a diff since "+in.PreviousTag+", which was reviewed and certified", readme,
			Required(in.Manifest, in.Previous, pkgs)) + marker("diff", main.Path+" since "+in.PreviousTag, diff)
		return digest([]Unit{u}), nil
	}
	for _, f := range in.Extra {
		if data, err := os.ReadFile(filepath.Join(in.Src, f)); err == nil {
			pieces = append(pieces, piece{text: marker("file", f, string(data))})
		}
	}
	base.Scope = ScopeWhole
	return split(base, header+", whole", readme, pieces, in), nil
}

// moduleUnits review a module from outside the repository: the vendor's own whole, or as
// a diff; a third party's as a diff, or at its surface.
func moduleUnits(ctx context.Context, in Inputs, m *Module, isOwned bool, log io.Writer) ([]Unit, string, error) {
	var prevVersion string
	if in.Previous != nil {
		prevVersion = in.Previous.Modules[m.Path]
	}
	if m.Version != "" && prevVersion == m.Version {
		return nil, "unchanged", nil
	}
	kind, who := KindThirdParty, "third-party module"
	if isOwned {
		kind, who = KindOwned, "module the vendor controls"
	} else if pc, ok := in.Source.(provenanceChecker); ok {
		if err := pc.CheckProvenance(ctx, m, log); err != nil {
			return nil, "", err
		}
	}
	base := Unit{Kind: kind, Module: m.Path, To: m.Version}
	header := fmt.Sprintf("Review unit: %s %s %s", who, m.Path, m.Version)

	if prevVersion != "" && m.Version != "" {
		var old string
		var err error
		if m.repoPath != "" && in.PreviousTag != "" {
			old, err = fromGit(ctx, in.Src, in.PreviousTag, m.repoPath, log)
		} else {
			old, err = in.Source.Fetch(ctx, in.Src, m, prevVersion, log)
		}
		if err != nil {
			return nil, "", err
		}
		pieces, err := diffPieces(ctx, m, old, log)
		if err != nil {
			return nil, "", err
		}
		if len(pieces) == 0 {
			return nil, "none", nil
		}
		base.From, base.Scope = prevVersion, ScopeDiff
		return split(base, header+", as a diff since "+prevVersion+", which was reviewed", "", pieces, in), ScopeDiff, nil
	}

	pieces, err := filePieces(m)
	if err != nil {
		return nil, "", err
	}
	if isOwned || m.Version == "" {
		base.Scope = ScopeWhole
		return split(base, header+", whole", "", pieces, in), ScopeWhole, nil
	}
	pieces = surface(in, m, pieces)
	if len(pieces) == 0 {
		return nil, "none", nil
	}
	size := 0
	for _, p := range pieces {
		size += len(p.text)
	}
	if size > maxSurface {
		// The verdict requires every package with a sensitive capability to be reviewed, so
		// those are, however large; only the rest of the surface waits for a diff.
		pieces = slices.DeleteFunc(pieces, func(p piece) bool { return !sensitivePackage(in, p.pkg) })
		if len(pieces) == 0 {
			return nil, ScopeTooLarge, nil
		}
		base.Scope = ScopeCapabilities
		return split(base, header+", newly compiled in, with a surface too large to review whole: only its packages that can act on the world", "", pieces, in), ScopeCapabilities, nil
	}
	base.Scope = ScopeSurface
	return split(base, header+", newly compiled in: only its surface, the parts through which a supply-chain attack gets in", "", pieces, in), ScopeSurface, nil
}

// surface keeps, of a third-party module first compiled in, the files of packages with a
// sensitive capability, whole, and every other file the Source or the file itself marks
// as surface: build-time code, code that runs when loaded, binaries, assembly, C.
func surface(in Inputs, m *Module, pieces []piece) []piece {
	var keep []piece
	for _, p := range pieces {
		if sensitivePackage(in, p.pkg) || p.surface {
			keep = append(keep, p)
		}
	}
	return keep
}

// sensitivePackage reports whether a package has a sensitive capability in the release's
// manifest: one the verdict needs a review to explain.
func sensitivePackage(in Inputs, pkg string) bool {
	if in.Manifest == nil {
		return false
	}
	return slices.ContainsFunc(in.Manifest.Notable(pkg), sensitive)
}

// diffPieces are a module's changes between an older copy, in old, and the one compiled in.
func diffPieces(ctx context.Context, m *Module, old string, log io.Writer) ([]piece, error) {
	var pieces []piece
	for _, pkg := range slices.Sorted(maps.Keys(m.Files)) {
		for _, f := range m.Files[pkg] {
			newPath := filepath.Join(m.Dir, filepath.FromSlash(f))
			oldPath := filepath.Join(old, filepath.FromSlash(f))
			name := m.Path + "@" + m.Version + "/" + f
			if slices.Contains(m.Foreign, f) {
				name += foreignNote
			}
			if _, err := os.Stat(oldPath); err != nil {
				text, err := fileText(newPath)
				if err != nil {
					return nil, err
				}
				pieces = append(pieces, piece{pkg: pkg, text: marker("file", name+" (new in this version)", text)})
				continue
			}
			diff, err := diffFiles(ctx, oldPath, newPath, log)
			if err != nil {
				return nil, err
			}
			if diff != "" {
				pieces = append(pieces, piece{pkg: pkg, text: marker("diff", name, diff)})
			}
		}
	}
	return pieces, nil
}

// foreignNote marks a file the published package has but its source repository does not,
// at the commit the package claims: how the xz backdoor reached its builds.
const foreignNote = " (NOT IN THE SOURCE REPOSITORY: the published package has this file, or this content, but its repository at the commit the package names does not)"

type piece struct {
	pkg  string
	text string
	// surface marks a file a supply-chain attack would use: see surface.
	surface bool
}

// filePieces holds each of a module's files whole, in package order, named by
// module@version/path.
func filePieces(m *Module) ([]piece, error) {
	var pieces []piece
	for _, pkg := range slices.Sorted(maps.Keys(m.Files)) {
		for _, f := range m.Files[pkg] {
			data, err := os.ReadFile(filepath.Join(m.Dir, filepath.FromSlash(f)))
			if err != nil {
				return nil, err
			}
			text := sourceText(data)
			name := m.Path + "/" + f
			if m.Version != "" {
				name = m.Path + "@" + m.Version + "/" + f
			}
			foreign := slices.Contains(m.Foreign, f)
			if foreign {
				name += foreignNote
			}
			pieces = append(pieces, piece{pkg: pkg, text: marker("file", name, text), surface: foreign || surfaceFile(f, data)})
		}
	}
	return pieces, nil
}

// surfaceMarkers are what makes a file part of a module's surface in any language: code
// run at build or load time, links below the language, and data the compiler embeds.
var surfaceMarkers = []string{
	"func init(", "//go:linkname", "//go:embed", "import \"C\"", // Go
	"build.rs", "#[proc_macro", "include_bytes!", "include_str!", "#[link(", "extern \"C\"", // Rust
	"@embedFile", "@cImport", "b.addSystemCommand", "b.addRunArtifact", // Zig
	// Acting on the world, for languages with no capability analysis: running programs,
	// the network, and loading code.
	"std::process::Command", "Command::new(", "std::net::", "TcpStream", "UdpSocket", "libloading", "dlopen", // Rust, C
	"std.process.Child", "std.http.", "std.net.", "std.posix.execve", "std.DynLib", // Zig
}

// surfaceFile reports whether a file is surface: not plain source, a build script, or
// containing a surface marker.
func surfaceFile(name string, data []byte) bool {
	if !isText(data) {
		return true
	}
	base := filepath.Base(name)
	switch {
	case base == "build.rs", base == "build.zig", base == "build.zig.zon":
		return true
	case strings.HasSuffix(base, ".s"), strings.HasSuffix(base, ".S"), strings.HasSuffix(base, ".syso"),
		strings.HasSuffix(base, ".c"), strings.HasSuffix(base, ".h"), strings.HasSuffix(base, ".cc"), strings.HasSuffix(base, ".cpp"):
		return true
	}
	for _, mk := range surfaceMarkers {
		if bytes.Contains(data, []byte(mk)) {
			return true
		}
	}
	return false
}

// split packs pieces into units of at most maxPart bytes of code, keeping each package
// together where it fits.
func split(base Unit, header, readme string, pieces []piece, in Inputs) []Unit {
	pieces = splitLarge(pieces)
	var parts [][]piece
	var cur []piece
	size := 0
	for i, p := range pieces {
		newPkg := i == 0 || p.pkg != pieces[i-1].pkg
		pkgSize := 0
		if newPkg {
			for _, q := range pieces[i:] {
				if q.pkg != p.pkg {
					break
				}
				pkgSize += len(q.text)
			}
		}
		if len(cur) > 0 && ((newPkg && size+pkgSize > maxPart) || size+len(p.text) > maxPart) {
			parts = append(parts, cur)
			cur, size = nil, 0
		}
		cur = append(cur, p)
		size += len(p.text)
	}
	if len(cur) > 0 {
		parts = append(parts, cur)
	}
	var units []Unit
	for i, part := range parts {
		u := base
		u.Part, u.Parts = i+1, len(parts)
		u.Packages = nil
		var body strings.Builder
		for _, p := range part {
			if p.pkg != "" && !slices.Contains(u.Packages, p.pkg) {
				u.Packages = append(u.Packages, p.pkg)
			}
			body.WriteString(p.text)
		}
		h := header
		if u.Parts > 1 {
			h += fmt.Sprintf(" (part %d of %d; the other parts are reviewed separately)", u.Part, u.Parts)
		}
		u.input = intro(u, h, readme, Required(in.Manifest, in.Previous, u.Packages)) + body.String()
		units = append(units, u)
	}
	return digest(units)
}

// splitLarge breaks a piece holding several markers, a large file in pieces, into one
// piece per marker, so split can spread them across units.
func splitLarge(pieces []piece) []piece {
	var out []piece
	for _, p := range pieces {
		if len(p.text) <= maxPart {
			out = append(out, p)
			continue
		}
		text := p.text
		for len(text) > 0 {
			next := strings.Index(text[1:], "<<<shadybin ")
			if next < 0 {
				out = append(out, piece{pkg: p.pkg, text: text, surface: p.surface})
				break
			}
			out = append(out, piece{pkg: p.pkg, text: text[:next+1], surface: p.surface})
			text = text[next+1:]
		}
	}
	return out
}

func intro(u Unit, header, readme string, required []Pair) string {
	var b strings.Builder
	b.WriteString(header + ".\n\nPackages in this unit:\n")
	for _, p := range u.Packages {
		b.WriteString("- " + p + "\n")
	}
	b.WriteString("\nCapabilities to explain:\n")
	if len(required) == 0 {
		b.WriteString("(none)\n")
	}
	for _, r := range required {
		b.WriteString("- " + r.Package + ": " + r.Capability + "\n")
	}
	if readme != "" {
		b.WriteString("\n" + marker("file", "README (the vendor's own description of the tool)", readme))
	}
	b.WriteString("\n")
	return b.String()
}

// Tokens estimates a unit's input tokens, at four bytes each.
func Tokens(u *Unit) int { return len(u.input) / 4 }

// marker encloses text between markers that carry its digest, so no text can close its
// own marker early. Text too large for one call is split, at line ends, into numbered
// pieces, each in its own marker.
func marker(kind, path, text string) string {
	if len(text) <= maxPart {
		return oneMarker(kind, path, text)
	}
	var pieces []string
	for len(text) > 0 {
		cut := min(len(text), maxPart-4096)
		if nl := strings.LastIndexByte(text[:cut], '\n'); nl > 0 && cut < len(text) {
			cut = nl + 1
		}
		pieces = append(pieces, text[:cut])
		text = text[cut:]
	}
	var b strings.Builder
	for i, p := range pieces {
		b.WriteString(oneMarker(kind, fmt.Sprintf("%s (piece %d of %d)", path, i+1, len(pieces)), p))
	}
	return b.String()
}

func oneMarker(kind, path, text string) string {
	sum := sha256.Sum256([]byte(text))
	d := hex.EncodeToString(sum[:])
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return fmt.Sprintf("<<<shadybin %s %s sha256:%s>>>\n%s<<<end sha256:%s>>>\n", kind, path, d, text, d)
}

// digest sets each unit's digest: of the model, prompt and exact input, so a cached result
// is reused only for the same question.
func digest(units []Unit) []Unit {
	for i := range units {
		sum := sha256.Sum256([]byte(Model + "\n" + PromptVersion + "\n" + units[i].input))
		units[i].Digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	return units
}

func isText(data []byte) bool {
	return utf8.Valid(data) && bytes.IndexByte(data, 0) < 0
}

// sourceText is a file as the model sees it; a binary file, such as a .syso object, is
// named, not shown.
func sourceText(data []byte) string {
	if !isText(data) {
		return fmt.Sprintf("[binary file, %d bytes, sha256:%x: it cannot be reviewed as source]\n", len(data), sha256.Sum256(data))
	}
	return string(data)
}

func fileText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sourceText(data), nil
}

func readmeExcerpt(src string) string {
	for _, name := range []string{"README.md", "README", "README.txt"} {
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			continue
		}
		if len(data) > maxReadme {
			data = append(data[:maxReadme], "\n[README truncated]\n"...)
		}
		return string(data)
	}
	return ""
}

func tagExists(ctx context.Context, src, tag string) bool {
	_, err := gitOut(ctx, src, io.Discard, "rev-parse", "-q", "--verify", "refs/tags/"+tag+"^{commit}")
	return err == nil
}

// diffFiles diffs two versions of a file. It runs from the directory both are under and
// names them relative to it (module@version/path), so the diff, and the cache key made
// from it, is the same on every machine.
func diffFiles(ctx context.Context, old, new string, log io.Writer) (string, error) {
	root := filepath.Dir(old)
	for !strings.HasPrefix(new, root+string(filepath.Separator)) && root != filepath.Dir(root) {
		root = filepath.Dir(root)
	}
	relOld, _ := filepath.Rel(root, old)
	relNew, _ := filepath.Rel(root, new)
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "diff", "--no-index", "--no-color", "--no-ext-diff", "--",
		filepath.ToSlash(relOld), filepath.ToSlash(relNew))
	cmd.Dir, cmd.Stdout, cmd.Stderr = root, &out, log
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
		return "", fmt.Errorf("diff %s: %w", new, err)
	}
	return out.String(), nil
}

func execGit(ctx context.Context, dir string, stdout, stderr io.Writer, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, stdout, stderr
	return cmd
}

func gitOut(ctx context.Context, dir string, log io.Writer, args ...string) (string, error) {
	var out bytes.Buffer
	if err := execGit(ctx, dir, &out, log, args...).Run(); err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out.String(), nil
}
