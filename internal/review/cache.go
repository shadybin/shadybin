package review

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/shadybin/shadybin/internal/keys"
	"github.com/shadybin/shadybin/verify"
)

// The dependency cache lives in the registry: deps/<module>@<version>/<digest>.json, the
// unit as reviewed, and .sig beside it. The digest is of the exact input, so an entry
// answers exactly one question. Every project that compiles in that module at that version
// and asks it gets the answer without a call.
//
// An entry decides other projects' verdicts, so it is signed, and the registry it is read
// from need not be trusted.

// cachePrefix separates the cache's signatures from statements'.
const cachePrefix = "shadybin review cache v1\n"

const maxEntry = 4 << 20

// CachePath is a unit's entry in the registry, relative to its root.
func CachePath(u *Unit) string {
	return "deps/" + u.Module + "@" + u.To + "/" + strings.TrimPrefix(u.Digest, "sha256:") + ".json"
}

// Cache reads entries from a registry.
type Cache struct {
	// Registry is the registry's base URL, or a local directory.
	Registry string
	// Keys are the shadybin keys an entry must be signed by.
	Keys   []ed25519.PublicKey
	Client *http.Client
}

// Lookup returns the cached result for a unit, nil if there is none. An entry that is
// there but not validly signed is an error: someone has tampered with the registry.
func (c *Cache) Lookup(ctx context.Context, u *Unit) (*Unit, error) {
	if c == nil || c.Registry == "" || !u.Cacheable() {
		return nil, nil
	}
	path := CachePath(u)
	data, err := c.get(ctx, path)
	if data == nil || err != nil {
		return nil, err
	}
	sig, err := c.get(ctx, path+".sig")
	if err != nil {
		return nil, err
	}
	if sig == nil || !signedBy(data, sig, c.Keys) {
		return nil, fmt.Errorf("cache entry %s is not signed by a shadybin key", path)
	}
	var e Unit
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("cache entry %s: %w", path, err)
	}
	if e.Digest != u.Digest || e.Module != u.Module || e.To != u.To || e.Result == nil {
		return nil, fmt.Errorf("cache entry %s answers another question", path)
	}
	return &e, nil
}

func (c *Cache) get(ctx context.Context, path string) ([]byte, error) {
	if !strings.HasPrefix(c.Registry, "https://") && !strings.HasPrefix(c.Registry, "http://") {
		data, err := os.ReadFile(filepath.Join(c.Registry, filepath.FromSlash(path)))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return data, err
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.Registry, "/")+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("cache %s: %s", path, resp.Status)
	}
	var b bytes.Buffer
	if _, err := io.Copy(&b, io.LimitReader(resp.Body, maxEntry+1)); err != nil {
		return nil, err
	}
	if b.Len() > maxEntry {
		return nil, fmt.Errorf("cache %s: too large", path)
	}
	return b.Bytes(), nil
}

func signedBy(data, sig []byte, pinned []ed25519.PublicKey) bool {
	msg := append([]byte(cachePrefix), data...)
	for line := range strings.Lines(string(sig)) {
		s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil || len(s) != ed25519.SignatureSize {
			continue
		}
		for _, k := range pinned {
			if ed25519.Verify(k, msg, s) {
				return true
			}
		}
	}
	return false
}

// WriteEntries signs and writes the cache entries for a review's dependency units that
// were reviewed afresh, into the registry at root, leaving any entry already there.
func WriteEntries(root string, r *Review, k ed25519.PrivateKey) (int, error) {
	n := 0
	for i := range r.Units {
		u := &r.Units[i]
		if !u.Cacheable() || u.Cached || u.Result == nil {
			continue
		}
		if verify.ValidTag(u.To) != nil || strings.Contains(u.Module, "..") {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(CachePath(u)))
		if _, err := os.Stat(path); err == nil {
			continue
		}
		data, err := json.MarshalIndent(u, "", "  ")
		if err != nil {
			return n, err
		}
		data = append(data, '\n')
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return n, err
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return n, err
		}
		sig := keys.Sign(k, append([]byte(cachePrefix), data...))
		if err := os.WriteFile(path+".sig", []byte(sig), 0o644); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
