// Package verify checks that a release file is one shadybin certified: rebuilt from the
// tagged source, byte for byte, and reviewed. It is what a vendor's updater imports, so it
// uses the standard library only.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// header opens every statement. It names the format and version, and since the signature
// covers it, a shadybin signature can never be mistaken for one over anything else.
const header = "shadybin statement v1"

// maxStatement bounds a statement: a few hundred files at most.
const maxStatement = 1 << 20

var (
	repoSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

// Digest is a SHA-256 digest.
type Digest [sha256.Size]byte

// String is the digest as sha256:<hex>, the form a statement holds.
func (d Digest) String() string { return "sha256:" + hex.EncodeToString(d[:]) }

// ParseDigest reads sha256:<hex>.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return d, fmt.Errorf("digest %q: want sha256:<hex>", s)
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != len(d) || h != strings.ToLower(h) {
		return d, fmt.Errorf("digest %q: want %d lowercase hex bytes", s, len(d))
	}
	copy(d[:], b)
	return d, nil
}

// File is one release file a statement certifies.
type File struct {
	Name   string
	Digest Digest
}

// Verdicts a statement can carry.
const (
	// Certified: rebuilt byte for byte from the tag, and passed review.
	Certified = "certified"
	// Rejected: rebuilt byte for byte from the tag, and failed review. The files are
	// listed so it is clear which bytes were judged; an updater must not install them.
	Rejected = "rejected"
)

// Statement is what shadybin signs for one release: the files it rebuilt from the tag and
// found identical to the vendor's, the verdict of the review, and the digests of the
// report, manifest and review published beside it.
type Statement struct {
	// Repo is the source repository, host and path, lowercase: github.com/owner/name.
	Repo string
	// Tag is the git tag the files were rebuilt from.
	Tag string
	// Verdict is Certified or Rejected.
	Verdict string
	// Report is the digest of report.md, the review written out for people.
	Report Digest
	// Manifest is the digest of manifest.json, what the code can do.
	Manifest Digest
	// Review is the digest of review.json, the reviewer's answers the verdict follows from.
	Review Digest
	// Files are the release's files, sorted by name, each name once.
	Files []File
}

// Marshal returns the statement's canonical bytes, the bytes that are signed. It sorts
// Files and rejects a statement that names anything it could not parse back.
func (s *Statement) Marshal() ([]byte, error) {
	if err := ValidRepo(s.Repo); err != nil {
		return nil, err
	}
	if err := ValidTag(s.Tag); err != nil {
		return nil, err
	}
	if s.Verdict != Certified && s.Verdict != Rejected {
		return nil, fmt.Errorf("verdict %q: want %s or %s", s.Verdict, Certified, Rejected)
	}
	if len(s.Files) == 0 {
		return nil, errors.New("statement lists no files")
	}
	files := slices.Clone(s.Files)
	slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Name, b.Name) })
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\nrepo %s\ntag %s\nverdict %s\nreport %s\nmanifest %s\nreview %s\n",
		header, s.Repo, s.Tag, s.Verdict, s.Report, s.Manifest, s.Review)
	for i, f := range files {
		if !namePattern.MatchString(f.Name) {
			return nil, fmt.Errorf("file name %q: want letters, digits and ._+- only", f.Name)
		}
		if i > 0 && files[i-1].Name == f.Name {
			return nil, fmt.Errorf("file %q listed twice", f.Name)
		}
		fmt.Fprintf(&b, "file %s %s\n", f.Digest, f.Name)
	}
	if b.Len() > maxStatement {
		return nil, errors.New("statement too large")
	}
	return b.Bytes(), nil
}

// headerFields are the lines between the header and the files, in order.
var headerFields = []string{"repo", "tag", "verdict", "report", "manifest", "review"}

// ParseStatement reads a statement. It accepts only canonical bytes, what Marshal writes,
// so one statement has exactly one encoding.
func ParseStatement(data []byte) (*Statement, error) {
	if len(data) > maxStatement {
		return nil, errors.New("statement too large")
	}
	text, ok := strings.CutSuffix(string(data), "\n")
	if !ok {
		return nil, errors.New("statement does not end in a newline")
	}
	lines := strings.Split(text, "\n")
	if len(lines) < 2+len(headerFields) || lines[0] != header {
		return nil, fmt.Errorf("not a statement: want %q, then %s and files", header, strings.Join(headerFields, ", "))
	}
	values := map[string]string{}
	for i, name := range headerFields {
		v, ok := strings.CutPrefix(lines[1+i], name+" ")
		if !ok {
			return nil, fmt.Errorf("statement line %d: want %s", i+2, name)
		}
		values[name] = v
	}
	s := Statement{Repo: values["repo"], Tag: values["tag"], Verdict: values["verdict"]}
	for name, d := range map[string]*Digest{"report": &s.Report, "manifest": &s.Manifest, "review": &s.Review} {
		var err error
		if *d, err = ParseDigest(values[name]); err != nil {
			return nil, fmt.Errorf("statement %s: %w", name, err)
		}
	}
	first := 1 + len(headerFields)
	for i, line := range lines[first:] {
		fields := strings.Split(line, " ")
		if len(fields) != 3 || fields[0] != "file" {
			return nil, fmt.Errorf("statement line %d: want file sha256:<hex> <name>", first+i+1)
		}
		d, err := ParseDigest(fields[1])
		if err != nil {
			return nil, fmt.Errorf("statement line %d: %w", first+i+1, err)
		}
		s.Files = append(s.Files, File{Name: fields[2], Digest: d})
	}
	again, err := s.Marshal()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, data) {
		return nil, errors.New("statement is not canonical: files must be sorted by name")
	}
	return &s, nil
}

// Covers reports whether the statement certifies a file of that name and digest.
func (s *Statement) Covers(name string, digest Digest) error {
	if s.Verdict != Certified {
		return fmt.Errorf("%w: shadybin rejected %s %s on review", ErrRejected, s.Repo, s.Tag)
	}
	for _, f := range s.Files {
		if f.Name == name {
			if f.Digest != digest {
				return fmt.Errorf("%w: %s %s: %s has %s, not the certified %s",
					ErrNotListed, s.Repo, s.Tag, name, digest, f.Digest)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s does not certify %s", ErrNotListed, s.Repo, s.Tag, name)
}

// ValidRepo checks a repository is host/owner/name, lowercase.
func ValidRepo(repo string) error {
	segs := strings.Split(repo, "/")
	if len(segs) < 3 {
		return fmt.Errorf("repo %q: want host/owner/name", repo)
	}
	for _, seg := range segs {
		if !repoSegment.MatchString(seg) || seg == "." || seg == ".." {
			return fmt.Errorf("repo %q: want lowercase host/owner/name", repo)
		}
	}
	return nil
}

// ValidTag checks a tag is one the registry can hold as a single directory: letters,
// digits and ._+-, so no slashes.
func ValidTag(tag string) error {
	if !tagPattern.MatchString(tag) {
		return fmt.Errorf("tag %q: want letters, digits and ._+- only", tag)
	}
	return nil
}
