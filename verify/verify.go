package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DefaultRegistry is where shadybin publishes statements: the registry repository, served
// by GitHub Pages under shadybin's own domain, so where it is hosted can change without
// breaking the binaries that pinned this. The host need not be trusted: what it serves is
// signed.
const DefaultRegistry = "https://shadybin.dev/registry"

// Names of a release's files in the registry, under <registry>/<repo>/<tag>/.
const (
	StatementName = "statement.txt"
	SignatureName = "statement.txt.sig"
	ReportName    = "report.md"
	ManifestName  = "manifest.json"
	ReviewName    = "review.json"
)

// maxSignature bounds the signature file: a few lines of base64, one per signing key.
const maxSignature = 4096

var (
	// ErrNotCertified means shadybin has not certified the file: no valid signature, or a
	// statement that does not list the file with that digest.
	ErrNotCertified = errors.New("not certified by shadybin")
	// ErrRejected means shadybin reviewed the release and found it shady. It is final: the
	// release will not be certified, and an updater should not ask again.
	ErrRejected = fmt.Errorf("%w: rejected", ErrNotCertified)
	// ErrBadSignature means no line of the signature file is a signature, by a pinned key,
	// over the statement.
	ErrBadSignature = fmt.Errorf("%w: bad signature", ErrNotCertified)
	// ErrBadStatement means the statement is signed but not a statement this SDK reads:
	// another format, or not canonical.
	ErrBadStatement = fmt.Errorf("%w: bad statement", ErrNotCertified)
	// ErrWrongRelease means the statement is for another repository or tag than asked: one
	// release's statement served for another.
	ErrWrongRelease = fmt.Errorf("%w: statement for another release", ErrNotCertified)
	// ErrNotListed means the release is certified, but not with this file and digest.
	ErrNotListed = fmt.Errorf("%w: file not listed", ErrNotCertified)
	// ErrPending means the registry has no statement for the release yet. An updater
	// should wait and ask again, not install it and not fall back to another release.
	ErrPending = fmt.Errorf("%w yet", ErrNotCertified)
)

// ParseKey reads a public key as hex, 32 bytes.
func ParseKey(h string) (ed25519.PublicKey, error) {
	k, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %q: want %d hex bytes", h, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(k), nil
}

// Open checks a statement's signature file against the pinned keys and returns the
// statement. The signature file holds one base64 signature per line, so a statement signed
// while a key is rotated carries both; one valid signature by a pinned key is enough.
func Open(statement, signature []byte, keys []ed25519.PublicKey) (*Statement, error) {
	if len(keys) == 0 {
		return nil, errors.New("no shadybin keys pinned")
	}
	if len(signature) > maxSignature {
		return nil, fmt.Errorf("%w: signature file too large", ErrBadSignature)
	}
	for line := range strings.Lines(string(signature)) {
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		for _, k := range keys {
			if ed25519.Verify(k, statement, sig) {
				s, err := ParseStatement(statement)
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrBadStatement, err)
				}
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: no signature by a pinned key", ErrBadSignature)
}

// Verify does what a verifier does once it has a release's statement and signature file,
// fetched from the registry: it checks the signature against the pinned keys, the
// statement is for the repository and tag asked about, the verdict is certified, and the
// file is listed with its digest. It returns nil only when all four hold.
func Verify(statement, signature []byte, keys []ed25519.PublicKey, repo, tag, name string, digest Digest) error {
	s, err := Open(statement, signature, keys)
	if err != nil {
		return err
	}
	if s.Repo != strings.ToLower(repo) || s.Tag != tag {
		return fmt.Errorf("%w: the statement is for %s %s", ErrWrongRelease, s.Repo, s.Tag)
	}
	return s.Covers(name, digest)
}

// StatementURL and SignatureURL are where a release's files are in a registry.
func StatementURL(registry, repo, tag string) string {
	return strings.TrimSuffix(registry, "/") + "/" + strings.ToLower(repo) + "/" + tag + "/" + StatementName
}

// SignatureURL is the signature file beside StatementURL.
func SignatureURL(registry, repo, tag string) string {
	return strings.TrimSuffix(registry, "/") + "/" + strings.ToLower(repo) + "/" + tag + "/" + SignatureName
}

// KeyHex is shadybin's signing key, the public half, hex. During a rotation there are
// two; see DefaultKeys.
var KeyHex = []string{"d971638b671326b3831fb6962e0da516593a1af317b29521651bdf02bb2ed8fc"}

// DefaultKeys are shadybin's public keys, parsed: what a Checker with no Keys trusts. A
// binary that pins its own copy instead can still check against KeyHex.
func DefaultKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, h := range KeyHex {
		k, err := ParseKey(h)
		if err != nil {
			panic(err)
		}
		keys = append(keys, k)
	}
	return keys
}

// Checker asks the registry whether a release file is certified.
type Checker struct {
	// Keys are the shadybin public keys to trust; nil means DefaultKeys.
	Keys []ed25519.PublicKey
	// Registry is the registry's base URL; empty means DefaultRegistry.
	Registry string
	// Client fetches from the registry; nil means http.DefaultClient.
	Client *http.Client
}

// Check returns nil only if shadybin certified the file name with that digest for the
// repository's tag. It returns ErrPending when the release has no statement yet, and
// ErrRejected when shadybin reviewed it and refused it.
func (c *Checker) Check(ctx context.Context, repo, tag, name string, digest Digest) error {
	s, err := c.Statement(ctx, repo, tag)
	if err != nil {
		return err
	}
	return s.Covers(name, digest)
}

// Statement fetches and opens the release's statement, and checks it is the statement for
// that repository and tag, so one release's statement cannot stand in for another's.
func (c *Checker) Statement(ctx context.Context, repo, tag string) (*Statement, error) {
	dir, err := c.dir(repo, tag)
	if err != nil {
		return nil, err
	}
	statement, err := c.get(ctx, dir+StatementName, maxStatement)
	if err != nil {
		return nil, err
	}
	signature, err := c.get(ctx, dir+SignatureName, maxSignature)
	if err != nil {
		return nil, err
	}
	keys := c.Keys
	if keys == nil {
		keys = DefaultKeys()
	}
	s, err := Open(statement, signature, keys)
	if err != nil {
		return nil, err
	}
	if s.Repo != strings.ToLower(repo) || s.Tag != tag {
		return nil, fmt.Errorf("%w: registry served the statement for %s %s", ErrWrongRelease, s.Repo, s.Tag)
	}
	return s, nil
}

func (c *Checker) dir(repo, tag string) (string, error) {
	repo = strings.ToLower(repo)
	if err := ValidRepo(repo); err != nil {
		return "", err
	}
	if err := ValidTag(tag); err != nil {
		return "", err
	}
	base := c.Registry
	if base == "" {
		base = DefaultRegistry
	}
	return strings.TrimSuffix(base, "/") + "/" + repo + "/" + tag + "/", nil
}

func (c *Checker) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shadybin registry: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrPending
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("shadybin registry: %s: %s", url, resp.Status)
	}
	var b bytes.Buffer
	if _, err := io.Copy(&b, io.LimitReader(resp.Body, limit+1)); err != nil {
		return nil, fmt.Errorf("shadybin registry: %s: %w", url, err)
	}
	if int64(b.Len()) > limit {
		return nil, fmt.Errorf("shadybin registry: %s: too large", url)
	}
	return b.Bytes(), nil
}
