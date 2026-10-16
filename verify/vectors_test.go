package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The vectors are the conformance tests every SDK runs: Go, Zig and Rust each verify every
// case and must give its result. They are written by this file, from fixed keys, with
//
//	SHADYBIN_WRITE_VECTORS=1 go test -run TestVectors
//
// and copied into each SDK by make vectors.
const vectorsPath = "../spec/vectors.json"

// Results, in the order a verifier checks: signature, statement, release, verdict, file.
const (
	resultOK           = "ok"
	resultBadSignature = "bad_signature"
	resultBadStatement = "bad_statement"
	resultWrongRelease = "wrong_release"
	resultRejected     = "rejected"
	resultNotListed    = "not_listed"
)

type vectors struct {
	Comment string   `json:"comment"`
	Keys    []string `json:"keys"`
	Cases   []vector `json:"cases"`
}

type vector struct {
	Name      string `json:"name"`
	Statement string `json:"statement"`
	Signature string `json:"signature"`
	Repo      string `json:"repo"`
	Tag       string `json:"tag"`
	File      string `json:"file"`
	Digest    string `json:"digest"`
	Result    string `json:"result"`
}

func vectorKey(n string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("shadybin test vector key " + n))
	return ed25519.NewKeyFromSeed(seed[:])
}

func sig(k ed25519.PrivateKey, data string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k, []byte(data))) + "\n"
}

func makeVectors() vectors {
	k1, k2 := vectorKey("1"), vectorKey("2")
	darwin, linux := sha256.Sum256([]byte("darwin archive")), sha256.Sum256([]byte("linux archive"))
	statement := func(verdict string) string {
		s := Statement{Repo: "github.com/acme/tool", Tag: "v1.2.0", Verdict: verdict,
			Report: sha256.Sum256([]byte("report")), Manifest: sha256.Sum256([]byte("manifest")), Review: sha256.Sum256([]byte("review")),
			Files: []File{{"tool_Linux_x86_64.tar.gz", linux}, {"tool_Darwin_arm64.tar.gz", darwin}}}
		b, err := s.Marshal()
		if err != nil {
			panic(err)
		}
		return string(b)
	}
	good, rejected := statement(Certified), statement(Rejected)
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	unsorted := strings.Join(append(append([]string{}, lines[:7]...), lines[8], lines[7]), "\n") + "\n"
	crlf := strings.ReplaceAll(good, "\n", "\r\n")
	upperHex := strings.Replace(good, "file sha256:"+hex.EncodeToString(darwin[:]), "file sha256:"+strings.ToUpper(hex.EncodeToString(darwin[:])), 1)
	tampered := strings.Replace(good, "tag v1.2.0", "tag v1.2.1", 1)
	unknown := strings.Replace(good, "shadybin statement v1", "shadybin statement v2", 1)
	d := Digest(darwin).String()

	c := func(name, statement, signature, repo, tag, file, digest, result string) vector {
		return vector{name, statement, signature, repo, tag, file, digest, result}
	}
	return vectors{
		Comment: "shadybin verifier conformance vectors. Keys are hex Ed25519 public keys to pin. For each case, verify statement and signature (the files as fetched) for repo and tag, and check file with digest; the result is the first check that fails, in the order signature, statement, release, verdict, file. See spec/SPEC.md.",
		Keys:    []string{hex.EncodeToString(k1.Public().(ed25519.PublicKey))},
		Cases: []vector{
			c("certified", good, sig(k1, good), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultOK),
			c("repository asked in another case", good, sig(k1, good), "github.com/Acme/Tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultOK),
			c("key rotation: an unpinned key's line first", good, sig(k2, good)+sig(k1, good), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultOK),
			c("signed by an unpinned key", good, sig(k2, good), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultBadSignature),
			c("statement edited after signing", tampered, sig(k1, good), "github.com/acme/tool", "v1.2.1", "tool_Darwin_arm64.tar.gz", d, resultBadSignature),
			c("signature file empty", good, "", "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultBadSignature),
			c("signature file not base64", good, "not a signature\n", "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultBadSignature),
			c("files not sorted", unsorted, sig(k1, unsorted), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultBadStatement),
			c("CRLF line endings", crlf, sig(k1, crlf), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultBadStatement),
			c("uppercase hex", upperHex, sig(k1, upperHex), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultBadStatement),
			c("unknown statement version", unknown, sig(k1, unknown), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultBadStatement),
			c("statement for another tag", good, sig(k1, good), "github.com/acme/tool", "v1.3.0", "tool_Darwin_arm64.tar.gz", d, resultWrongRelease),
			c("statement for another repository", good, sig(k1, good), "github.com/acme/other", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultWrongRelease),
			c("rejected on review", rejected, sig(k1, rejected), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", d, resultRejected),
			c("file with another digest", good, sig(k1, good), "github.com/acme/tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", Digest(linux).String(), resultNotListed),
			c("file not in the release", good, sig(k1, good), "github.com/acme/tool", "v1.2.0", "tool_Windows_x86_64.zip", d, resultNotListed),
		},
	}
}

func result(err error) string {
	switch {
	case err == nil:
		return resultOK
	case errors.Is(err, ErrBadSignature):
		return resultBadSignature
	case errors.Is(err, ErrBadStatement):
		return resultBadStatement
	case errors.Is(err, ErrWrongRelease):
		return resultWrongRelease
	case errors.Is(err, ErrRejected):
		return resultRejected
	case errors.Is(err, ErrNotListed):
		return resultNotListed
	}
	return "error: " + err.Error()
}

func TestVectors(t *testing.T) {
	want := makeVectors()
	data, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if os.Getenv("SHADYBIN_WRITE_VECTORS") != "" {
		if err := os.WriteFile(vectorsPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	onDisk, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, data) {
		t.Fatalf("%s is stale: run SHADYBIN_WRITE_VECTORS=1 go test -run TestVectors", vectorsPath)
	}
	var v vectors
	if err := json.Unmarshal(onDisk, &v); err != nil {
		t.Fatal(err)
	}
	var keys []ed25519.PublicKey
	for _, h := range v.Keys {
		k, err := ParseKey(h)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	for _, c := range v.Cases {
		d, err := ParseDigest(c.Digest)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got := result(Verify([]byte(c.Statement), []byte(c.Signature), keys, c.Repo, c.Tag, c.File, d))
		if got != c.Result {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Result)
		}
	}
}
