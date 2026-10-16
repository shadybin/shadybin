// Package checksums reads the checksum files vendors publish with a release
// (sha256sum's format, which GoReleaser's checksums.txt uses) and hashes files.
package checksums

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/shadybin/shadybin/verify"
)

// Parse reads "<hex>  <name>" lines, sha256sum's text and binary ("<hex> *<name>") forms,
// into name → digest. Blank lines are skipped; anything else unreadable is an error.
func Parse(data []byte) (map[string]verify.Digest, error) {
	out := map[string]verify.Digest{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		h, name, ok := strings.Cut(line, " ")
		name = strings.TrimPrefix(strings.TrimLeft(name, " "), "*")
		if !ok || name == "" {
			return nil, fmt.Errorf("checksums line %d: want <sha256> <name>", n)
		}
		d, err := verify.ParseDigest("sha256:" + strings.ToLower(h))
		if err != nil {
			return nil, fmt.Errorf("checksums line %d: %w", n, err)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("checksums line %d: %s listed twice", n, name)
		}
		out[name] = d
	}
	return out, sc.Err()
}

// File returns the SHA-256 of a file.
func File(path string) (verify.Digest, error) {
	var d verify.Digest
	f, err := os.Open(path)
	if err != nil {
		return d, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return d, err
	}
	copy(d[:], h.Sum(nil))
	return d, nil
}

// Line is a file's line in sha256sum's format.
func Line(name string, d verify.Digest) string {
	return hex.EncodeToString(d[:]) + "  " + name + "\n"
}
