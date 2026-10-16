// Package keys makes and uses shadybin's signing keys. Only the signing side needs it;
// what verifies a signature is package verify.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Generate writes a new private key to path, which must not exist, readable by its owner
// only, and returns the public key as hex: what a verifier pins.
func Generate(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

// Parse reads a private key: its 32-byte seed, base64, as Generate writes it.
func Parse(s string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("private key: want a base64 ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Public returns a private key's public key as hex.
func Public(k ed25519.PrivateKey) string {
	return hex.EncodeToString(k.Public().(ed25519.PublicKey))
}

// Sign returns one line of a signature file: the signature over data, base64.
func Sign(k ed25519.PrivateKey, data []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k, data)) + "\n"
}
