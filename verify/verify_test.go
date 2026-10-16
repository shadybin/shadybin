package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testStatement(t *testing.T) (*Statement, []byte) {
	t.Helper()
	s := &Statement{
		Repo:     "github.com/acme/tool",
		Tag:      "v1.2.0",
		Verdict:  Certified,
		Report:   sha256.Sum256([]byte("report")),
		Manifest: sha256.Sum256([]byte("manifest")),
		Review:   sha256.Sum256([]byte("review")),
		Files: []File{
			{Name: "tool_Linux_x86_64.tar.gz", Digest: sha256.Sum256([]byte("linux"))},
			{Name: "tool_Darwin_arm64.tar.gz", Digest: sha256.Sum256([]byte("darwin"))},
		},
	}
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return s, data
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(priv ed25519.PrivateKey, data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
}

func TestStatementRoundTrip(t *testing.T) {
	_, data := testStatement(t)
	if !strings.HasPrefix(string(data), header+"\nrepo github.com/acme/tool\ntag v1.2.0\nverdict certified\nreport sha256:") {
		t.Fatalf("unexpected encoding:\n%s", data)
	}
	if i, j := strings.Index(string(data), "Darwin"), strings.Index(string(data), "Linux"); i > j {
		t.Fatalf("files not sorted:\n%s", data)
	}
	s, err := ParseStatement(data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := s.Marshal()
	if string(again) != string(data) {
		t.Fatalf("round trip changed the statement:\n%s\n%s", data, again)
	}
}

func TestParseStatementRejectsNonCanonical(t *testing.T) {
	_, data := testStatement(t)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	swapped := append(append([]string{}, lines[:7]...), lines[8], lines[7])
	for name, bad := range map[string]string{
		"unsorted":      strings.Join(swapped, "\n") + "\n",
		"no newline":    strings.TrimSuffix(string(data), "\n"),
		"crlf":          strings.ReplaceAll(string(data), "\n", "\r\n"),
		"extra space":   strings.Replace(string(data), "tag v1.2.0", "tag  v1.2.0", 1),
		"uppercase hex": strings.Replace(string(data), "sha256:", "sha256:A", 1),
		"trailing line": string(data) + "extra\n",
		"duplicate":     string(data) + lines[8] + "\n",
		"no manifest":   strings.Replace(string(data), "manifest ", "manifesto ", 1),
		"no review":     strings.Replace(string(data), "review ", "reviews ", 1),
		"other verdict": strings.Replace(string(data), "verdict certified", "verdict fine", 1),
		"no verdict":    strings.Replace(string(data), "verdict certified\n", "", 1),
		"other header":  strings.Replace(string(data), "v1", "v2", 1),
		"uppercase":     strings.Replace(string(data), "acme", "Acme", 1),
	} {
		if _, err := ParseStatement([]byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestMarshalRejects(t *testing.T) {
	for name, s := range map[string]Statement{
		"no files":       {Repo: "github.com/a/b", Tag: "v1"},
		"bad repo":       {Repo: "acme/tool", Tag: "v1", Files: []File{{Name: "x"}}},
		"slash in tag":   {Repo: "github.com/a/b", Tag: "sdk/v1", Files: []File{{Name: "x"}}},
		"space in name":  {Repo: "github.com/a/b", Tag: "v1", Files: []File{{Name: "a b"}}},
		"path in name":   {Repo: "github.com/a/b", Tag: "v1", Files: []File{{Name: "../x"}}},
		"duplicate name": {Repo: "github.com/a/b", Tag: "v1", Files: []File{{Name: "x"}, {Name: "x"}}},
	} {
		if _, err := s.Marshal(); err == nil {
			t.Errorf("%s: marshalled", name)
		}
	}
}

func TestOpen(t *testing.T) {
	_, data := testStatement(t)
	pub, priv := testKey(t)
	other, otherPriv := testKey(t)

	if _, err := Open(data, sign(priv, data), []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	// Rotation: two lines, either key pinned.
	both := append(sign(otherPriv, data), sign(priv, data)...)
	for _, k := range []ed25519.PublicKey{pub, other} {
		if _, err := Open(data, both, []ed25519.PublicKey{k}); err != nil {
			t.Fatalf("rotation signature: %v", err)
		}
	}
	tampered := []byte(strings.Replace(string(data), "v1.2.0", "v1.2.1", 1))
	for name, c := range map[string]struct {
		data, sig []byte
		keys      []ed25519.PublicKey
	}{
		"wrong key":      {data, sign(otherPriv, data), []ed25519.PublicKey{pub}},
		"tampered":       {tampered, sign(priv, data), []ed25519.PublicKey{pub}},
		"empty":          {data, nil, []ed25519.PublicKey{pub}},
		"garbage":        {data, []byte("not base64\n"), []ed25519.PublicKey{pub}},
		"no pinned keys": {data, sign(priv, data), nil},
	} {
		if _, err := Open(c.data, c.sig, c.keys); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestCovers(t *testing.T) {
	s, _ := testStatement(t)
	if err := s.Covers("tool_Darwin_arm64.tar.gz", sha256.Sum256([]byte("darwin"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Covers("tool_Darwin_arm64.tar.gz", sha256.Sum256([]byte("evil"))); !errors.Is(err, ErrNotCertified) {
		t.Fatalf("other digest: %v", err)
	}
	if err := s.Covers("tool_Windows_x86_64.zip", sha256.Sum256([]byte("windows"))); !errors.Is(err, ErrNotCertified) {
		t.Fatalf("unlisted file: %v", err)
	}
	s.Verdict = Rejected
	if err := s.Covers("tool_Darwin_arm64.tar.gz", sha256.Sum256([]byte("darwin"))); !errors.Is(err, ErrRejected) || !errors.Is(err, ErrNotCertified) {
		t.Fatalf("rejected release: %v", err)
	}
}

func TestChecker(t *testing.T) {
	_, data := testStatement(t)
	pub, priv := testKey(t)
	files := map[string][]byte{
		"/github.com/acme/tool/v1.2.0/statement.txt":     data,
		"/github.com/acme/tool/v1.2.0/statement.txt.sig": sign(priv, data),
		// v1.3.0's directory serves v1.2.0's statement: a replay.
		"/github.com/acme/tool/v1.3.0/statement.txt":     data,
		"/github.com/acme/tool/v1.3.0/statement.txt.sig": sign(priv, data),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()
	c := Checker{Keys: []ed25519.PublicKey{pub}, Registry: srv.URL + "/", Client: srv.Client()}
	ctx := context.Background()
	darwin := sha256.Sum256([]byte("darwin"))

	if err := c.Check(ctx, "github.com/Acme/Tool", "v1.2.0", "tool_Darwin_arm64.tar.gz", darwin); err != nil {
		t.Fatalf("certified file: %v", err)
	}
	if err := c.Check(ctx, "github.com/acme/tool", "v1.4.0", "tool_Darwin_arm64.tar.gz", darwin); !errors.Is(err, ErrPending) {
		t.Fatalf("missing release: %v", err)
	}
	if err := c.Check(ctx, "github.com/acme/tool", "v1.3.0", "tool_Darwin_arm64.tar.gz", darwin); !errors.Is(err, ErrNotCertified) || errors.Is(err, ErrPending) {
		t.Fatalf("replayed statement: %v", err)
	}
}

func TestDefaultKeys(t *testing.T) {
	if len(DefaultKeys()) != len(KeyHex) || len(KeyHex) == 0 {
		t.Fatal("shadybin's own keys do not parse")
	}
}
