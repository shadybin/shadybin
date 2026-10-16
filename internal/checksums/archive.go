package checksums

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
)

// maxArchive bounds an archive read whole for comparison.
const maxArchive = 1 << 30

// entry is what an archive entry installs: its type, permissions (setuid, setgid and
// sticky included), link target, device numbers, extended attributes and contents. Its
// time, owner and group, and the archive's compression header, are not: they record where
// and when the archive was made, not what it holds.
type entry struct {
	kind   byte
	mode   int64
	link   string
	device string
	xattrs string
	digest [sha256.Size]byte
}

// IsArchive reports whether a file name is an archive SameContents can compare.
func IsArchive(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".zip")
}

// SameContents reports whether two archives install the same thing: the same entries,
// each with the same name, type, permissions, link target and bytes. They may differ in
// entries' times, owners and groups, in entry order, and in the gzip header, which say
// where and when an archive was made. It returns why they differ when they do.
func SameContents(a, b string) (bool, string, error) {
	ea, err := entries(a)
	if err != nil {
		return false, "", err
	}
	eb, err := entries(b)
	if err != nil {
		return false, "", err
	}
	for _, name := range slices.Sorted(maps.Keys(ea)) {
		other, ok := eb[name]
		switch {
		case !ok:
			return false, name + " is only in the published archive", nil
		case other.kind != ea[name].kind || other.link != ea[name].link || other.device != ea[name].device:
			return false, name + " is a different kind of entry", nil
		case other.xattrs != ea[name].xattrs:
			return false, name + " has different extended attributes", nil
		case other.mode != ea[name].mode:
			return false, fmt.Sprintf("%s has mode %o, not %o", name, other.mode, ea[name].mode), nil
		case other.digest != ea[name].digest:
			return false, name + " has different contents", nil
		}
	}
	for name := range eb {
		if _, ok := ea[name]; !ok {
			return false, name + " is only in the rebuilt archive", nil
		}
	}
	return true, "", nil
}

func entries(path string) (map[string]entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxArchive {
		return nil, fmt.Errorf("%s: too large to compare", path)
	}
	out := map[string]entry{}
	add := func(name string, e entry) error {
		if _, dup := out[name]; dup {
			return fmt.Errorf("%s: %s is in it twice", path, name)
		}
		out[name] = e
		return nil
	}
	if strings.HasSuffix(path, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := zipConsistent(data, zr); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			h := sha256.New()
			_, err = io.Copy(h, io.LimitReader(rc, maxArchive))
			rc.Close()
			if err != nil {
				return nil, err
			}
			e := entry{kind: zipKind(f.Mode()), mode: unixMode(f.Mode())}
			copy(e.digest[:], h.Sum(nil))
			if e.kind == 'l' {
				// A zip stores a symlink's target as its contents.
				e.link = fmt.Sprintf("sha256:%x", e.digest)
			}
			if err := add(f.Name, e); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// Past the end-of-archive marker there must be nothing but padding: an
			// extractor told to read on (tar --ignore-zeros) would find more entries.
			rest, err := io.ReadAll(io.LimitReader(gz, maxArchive))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			if bytes.ContainsFunc(rest, func(r rune) bool { return r != 0 }) {
				return nil, fmt.Errorf("%s: data after the end of the archive", path)
			}
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.LimitReader(tr, maxArchive)); err != nil {
			return nil, err
		}
		kind := hdr.Typeflag
		if kind == tar.TypeRegA { // the old name for a regular file
			kind = tar.TypeReg
		}
		e := entry{kind: kind, mode: hdr.Mode & 0o7777, link: hdr.Linkname, xattrs: xattrs(hdr)}
		if kind == tar.TypeChar || kind == tar.TypeBlock {
			e.device = fmt.Sprintf("%d,%d", hdr.Devmajor, hdr.Devminor)
		}
		copy(e.digest[:], h.Sum(nil))
		if err := add(hdr.Name, e); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// zipKind is a zip entry's type, from the Unix mode its external attributes carry: a
// symlink whose target is its contents must not pass for a file holding the same bytes.
func zipKind(m fs.FileMode) byte {
	switch {
	case m.IsDir():
		return 'd'
	case m&fs.ModeSymlink != 0:
		return 'l'
	case m.IsRegular():
		return 'f'
	}
	return 'o'
}

// unixMode is a zip entry's permissions with the setuid, setgid and sticky bits, as a tar
// header has them.
func unixMode(m fs.FileMode) int64 {
	mode := int64(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	return mode
}

// xattrs are a tar entry's extended attributes, which install with the file (a
// capability such as cap_setuid is one), sorted into one string to compare.
func xattrs(hdr *tar.Header) string {
	var out []string
	for k, v := range hdr.PAXRecords {
		if strings.HasPrefix(k, "SCHILY.xattr.") || strings.HasPrefix(k, "LIBARCHIVE.xattr.") {
			out = append(out, k+"="+v)
		}
	}
	slices.Sort(out)
	return strings.Join(out, "\x00")
}

// zipConsistent checks a zip says the same thing to every extractor. Go reads the central
// directory at the end; a streaming extractor reads the local header before each entry's
// data. So the local headers must run from the first byte, one per central entry, in its
// order, with the same name, method and sizes, each entry's data following its header and
// the next header following the data, up to the central directory, and the archive must
// end where its end record says. Anything else, a crafted zip could hide.
func zipConsistent(data []byte, zr *zip.Reader) error {
	le := func(off, n int) (uint64, bool) {
		if off < 0 || off+n > len(data) {
			return 0, false
		}
		var v uint64
		for i := n - 1; i >= 0; i-- {
			v = v<<8 | uint64(data[off+i])
		}
		return v, true
	}
	off := 0
	for _, f := range zr.File {
		if sig, ok := le(off, 4); !ok || sig != 0x04034b50 {
			return fmt.Errorf("%s: no local header where one should start", f.Name)
		}
		flags, _ := le(off+6, 2)
		method, _ := le(off+8, 2)
		csize, _ := le(off+18, 4)
		usize, _ := le(off+22, 4)
		nameLen, _ := le(off+26, 2)
		extraLen, ok := le(off+28, 2)
		if !ok {
			return fmt.Errorf("%s: truncated local header", f.Name)
		}
		nameEnd := off + 30 + int(nameLen)
		if nameEnd > len(data) || string(data[off+30:nameEnd]) != f.Name {
			return fmt.Errorf("%s: its local header names another file", f.Name)
		}
		if uint16(method) != f.Method {
			return fmt.Errorf("%s: its local header has another compression method", f.Name)
		}
		start := nameEnd + int(extraLen)
		if got, err := f.DataOffset(); err != nil || got != int64(start) {
			return fmt.Errorf("%s: its data is not where its local header says", f.Name)
		}
		zip64 := csize == 0xffffffff || usize == 0xffffffff
		if flags&0x8 == 0 && !zip64 && (csize != f.CompressedSize64 || usize != f.UncompressedSize64) {
			return fmt.Errorf("%s: its local header has other sizes", f.Name)
		}
		off = start + int(f.CompressedSize64)
		if flags&0x8 != 0 { // a data descriptor follows the data
			if sig, ok := le(off, 4); ok && sig == 0x08074b50 {
				off += 4
			}
			if zip64 || f.CompressedSize64 >= 0xffffffff || f.UncompressedSize64 >= 0xffffffff {
				off += 20
			} else {
				off += 12
			}
		}
	}
	if sig, ok := le(off, 4); !ok || sig != 0x02014b50 {
		return errors.New("data between the last entry and the central directory")
	}
	// The end record is the last thing in the file, its comment included.
	for p := len(data) - 22; p >= 0 && p >= len(data)-22-0xffff; p-- {
		if sig, _ := le(p, 4); sig == 0x06054b50 {
			if n, _ := le(p+20, 2); p+22+int(n) == len(data) {
				return nil
			}
		}
	}
	return errors.New("data after the end of the archive")
}
