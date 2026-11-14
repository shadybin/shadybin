package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/shadybin/shadybin/internal/registry"
)

// A sealed rebuild runs on files the review covered, and nothing else: seal empties every
// file of the checkout outside the review's scope and removes .git, whose objects hold them
// too, before any of the vendor's code runs. Then a file the review never saw cannot be
// compiled in, whatever a build script or manifest would choose: a build that needed one
// fails, or makes a binary that does not match the published one.
//
// seal writes a record of what it did. The certify job recomputes the scope from its own
// checkout and checks it against the record, so a rebuild sealed against another scope, or
// not sealed, never certifies.

const sealHeader = "shadybin seal v1"

// sealRecord is what seal did to a checkout.
type sealRecord struct {
	Repo, Tag, Commit string
	Epoch             int64
	// Scope is the digest of the files kept: see scopeDigest.
	Scope string
	// Emptied counts the files emptied.
	Emptied int
}

func (r sealRecord) marshal() []byte {
	return fmt.Appendf(nil, "%s\nrepo %s\ntag %s\ncommit %s\nepoch %d\nscope %s\nemptied %d\n",
		sealHeader, r.Repo, r.Tag, r.Commit, r.Epoch, r.Scope, r.Emptied)
}

func parseSealRecord(data []byte) (sealRecord, error) {
	var r sealRecord
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 7 || lines[0] != sealHeader {
		return r, errors.New("not a shadybin seal record")
	}
	field := func(i int, name string) (string, error) {
		v, ok := strings.CutPrefix(lines[i], name+" ")
		if !ok {
			return "", fmt.Errorf("seal record: line %d is not %s", i+1, name)
		}
		return v, nil
	}
	var err error
	var epoch, emptied string
	for i, f := range []struct {
		name string
		to   *string
	}{{"repo", &r.Repo}, {"tag", &r.Tag}, {"commit", &r.Commit}, {"epoch", &epoch}, {"scope", &r.Scope}, {"emptied", &emptied}} {
		if *f.to, err = field(i+1, f.name); err != nil {
			return r, err
		}
	}
	if r.Epoch, err = strconv.ParseInt(epoch, 10, 64); err != nil {
		return r, fmt.Errorf("seal record: epoch: %w", err)
	}
	if r.Emptied, err = strconv.Atoi(emptied); err != nil {
		return r, fmt.Errorf("seal record: emptied: %w", err)
	}
	if !bytes.Equal(r.marshal(), data) {
		return r, errors.New("seal record: not in its one encoding")
	}
	return r, nil
}

// scope lists the files of the checkout the review covers, relative to src and sorted:
// every file of the modules in the repository, by the project's language's own account of
// what is compiled in, the analysis's other files, and the lockfiles its analysis reads.
func scope(ctx context.Context, p *registry.Project, src string, log io.Writer) ([]string, error) {
	mods, err := sourceFor(p, "").Modules(ctx, src, log)
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(src)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	add := func(rel string) error {
		rel = filepath.ToSlash(filepath.Clean(rel))
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
			return fmt.Errorf("%s is outside the repository", rel)
		}
		set[rel] = true
		return nil
	}
	for _, m := range mods {
		if !m.InRepo {
			continue
		}
		dir, err := filepath.EvalSymlinks(m.Dir)
		if err != nil {
			return nil, err
		}
		for _, files := range m.Files {
			for _, f := range files {
				rel, err := filepath.Rel(root, filepath.Join(dir, filepath.FromSlash(f)))
				if err != nil {
					return nil, err
				}
				if err := add(rel); err != nil {
					return nil, fmt.Errorf("module %s: %w", m.Path, err)
				}
			}
		}
	}
	extra := slices.Clone(p.Analyze.Files)
	if p.Language == "go" {
		extra = append(extra, "go.mod", "go.sum", "go.work", "go.work.sum")
	}
	for _, v := range p.Vendored {
		files, err := git(ctx, src, log, "ls-files", "-z", "--", v.Path)
		if err != nil {
			return nil, err
		}
		extra = append(extra, splitZ(files)...)
	}
	for _, f := range extra {
		if _, err := os.Lstat(filepath.Join(src, filepath.FromSlash(f))); err == nil {
			if err := add(f); err != nil {
				return nil, err
			}
		}
	}
	return slices.Sorted(func(yield func(string) bool) {
		for f := range set {
			if !yield(f) {
				return
			}
		}
	}), nil
}

// scopeDigest is the SHA-256 of the scope's paths, one per line, in byte order.
func scopeDigest(files []string) string {
	h := sha256.New()
	for _, f := range files {
		io.WriteString(h, f+"\n")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// seal empties every tracked file of src outside the scope, removes every untracked one and
// .git, and returns the record. src must be a checkout of tag with no tracked file changed.
func seal(ctx context.Context, p *registry.Project, tag, src string, log io.Writer) (sealRecord, error) {
	// Untracked files go before the check, which then sees only changes to tracked ones, and
	// again after the analysis, which may leave some of its own.
	if err := cleanUntracked(ctx, src, log); err != nil {
		return sealRecord{}, err
	}
	commit, epoch, err := checkCheckout(ctx, src, tag, log)
	if err != nil {
		return sealRecord{}, err
	}
	keep, err := scope(ctx, p, src, log)
	if err != nil {
		return sealRecord{}, err
	}
	tracked, err := git(ctx, src, log, "ls-files", "-z")
	if err != nil {
		return sealRecord{}, err
	}
	r := sealRecord{Repo: p.Repo, Tag: tag, Commit: commit, Epoch: epoch, Scope: scopeDigest(keep)}
	for _, f := range splitZ(tracked) {
		if _, ok := slices.BinarySearch(keep, f); ok {
			continue
		}
		if err := empty(filepath.Join(src, filepath.FromSlash(f))); err != nil {
			return sealRecord{}, err
		}
		fmt.Fprintf(log, "seal: emptied %s\n", f)
		r.Emptied++
	}
	if err := cleanUntracked(ctx, src, log); err != nil {
		return sealRecord{}, err
	}
	if err := os.RemoveAll(filepath.Join(src, ".git")); err != nil {
		return sealRecord{}, err
	}
	return r, nil
}

// cleanUntracked removes whatever git does not track from src: it is no part of the tag, and
// the review never saw it. A cache an earlier step restored into the checkout (setup-zig
// restores .zig-cache) is such a file. Ignored files and nested repositories go too.
func cleanUntracked(ctx context.Context, src string, log io.Writer) error {
	cleaned, err := git(ctx, src, log, "clean", "-ffdx")
	if err != nil {
		return err
	}
	if cleaned != "" {
		fmt.Fprintf(log, "seal: removed what the tag does not track:\n%s\n", cleaned)
	}
	return nil
}

// empty leaves an empty regular file where a file or link was. A submodule's directory is
// emptied of everything.
func empty(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(path, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if fi.Mode().IsRegular() {
		return os.Truncate(path, 0)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.WriteFile(path, nil, 0o644)
}

// checkSeal checks a rebuild's seal record against the project at src, a git checkout of
// the same tag: the same release, and the same scope, by this job's own analysis.
func checkSeal(ctx context.Context, p *registry.Project, tag, src string, record []byte, log io.Writer) (sealRecord, error) {
	r, err := parseSealRecord(record)
	if err != nil {
		return r, err
	}
	commit, epoch, err := checkCheckout(ctx, src, tag, log)
	if err != nil {
		return r, err
	}
	if r.Repo != p.Repo || r.Tag != tag || r.Commit != commit || r.Epoch != epoch {
		return r, fmt.Errorf("the rebuild was sealed for %s %s at %s, not %s %s at %s", r.Repo, r.Tag, r.Commit, p.Repo, tag, commit)
	}
	keep, err := scope(ctx, p, src, log)
	if err != nil {
		return r, err
	}
	if d := scopeDigest(keep); d != r.Scope {
		return r, fmt.Errorf("the rebuild was sealed to scope %s, but the review's is %s", r.Scope, d)
	}
	return r, nil
}

// checkCheckout checks src is a clean checkout of tag and returns its commit and time.
func checkCheckout(ctx context.Context, src, tag string, log io.Writer) (string, int64, error) {
	head, err := git(ctx, src, log, "rev-parse", "HEAD")
	if err != nil {
		return "", 0, err
	}
	tagged, err := git(ctx, src, log, "rev-parse", "refs/tags/"+tag+"^{commit}")
	if err != nil {
		return "", 0, err
	}
	if head != tagged {
		return "", 0, fmt.Errorf("%s is at %s, not at %s (%s)", src, head, tag, tagged)
	}
	if dirty, err := git(ctx, src, log, "status", "--porcelain"); err != nil {
		return "", 0, err
	} else if dirty != "" {
		return "", 0, fmt.Errorf("%s has changes the tag does not:\n%s", src, dirty)
	}
	epoch, err := git(ctx, src, log, "log", "-1", "--format=%ct")
	if err != nil {
		return "", 0, err
	}
	t, err := strconv.ParseInt(epoch, 10, 64)
	return head, t, err
}

func splitZ(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(nil, 1<<20)
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, 0); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// runSeal seals a checkout for a rebuild, writing the record to -o; or, with -check, checks a
// rebuild's record against this checkout's own scope, printing the report's line about it.
func runSeal(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("seal", "", stderr)
	project := fs.String("project", "", "the project's shadybin.json")
	tag := fs.String("tag", "", "the tag checked out")
	src := fs.String("src", "", "a clean git checkout of the tag")
	out := fs.String("o", "", "file to write the seal record to")
	check := fs.String("check", "", "a rebuild's seal record, to check against src instead of sealing it")
	if err := parse(fs, args, "project", "tag", "src"); err != nil {
		return err
	}
	p, err := registry.LoadProject(*project)
	if err != nil {
		return err
	}
	if *check != "" {
		data, err := os.ReadFile(*check)
		if err != nil {
			return err
		}
		r, err := checkSeal(ctx, p, *tag, *src, data, stderr)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Rebuilt offline, as a user without privileges, from the files the review covers: %d other files of the repository emptied and `.git` removed first (scope `%s`).\n", r.Emptied, r.Scope)
		return nil
	}
	if *out == "" {
		fmt.Fprintln(stderr, "shadybin seal: give -o for the record, or -check")
		return errUsage
	}
	r, err := seal(ctx, p, *tag, *src, stderr)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, r.marshal(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "seal: kept the %s scope, emptied %d files, removed .git\n", r.Scope, r.Emptied)
	return nil
}
