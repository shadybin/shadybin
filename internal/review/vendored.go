package review

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Vendored is a third-party copy kept in the repository, as project.json declares it.
type Vendored struct {
	// Path is the copy's directory in the repository.
	Path string
	// Name and Version name the upstream release; URL is its archive and SHA256 the
	// archive's digest.
	Name, Version, URL, SHA256 string
}

const maxArchive = 256 << 20

// carveVendored checks each vendored copy against its upstream archive. Its files that are
// byte for byte upstream's become a third-party module; anything else in the copy, edited
// or added, stays the vendor's and is reviewed with the project. It returns the modules,
// and pathspecs that keep the upstream files out of the project's diff.
func carveVendored(ctx context.Context, src string, decl []Vendored, mods []*Module) ([]*Module, []string, error) {
	var excludes []string
	for _, v := range decl {
		upstream, err := fetchArchive(ctx, v.URL, v.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("vendored %s: %w", v.Path, err)
		}
		dir := filepath.Join(src, filepath.FromSlash(v.Path))
		third := &Module{Path: v.Name, Version: v.Version, Dir: dir, Upstream: v.URL,
			Provenance: "matches its upstream release " + v.URL, Files: map[string][]string{}, repoPath: v.Path}
		for _, m := range mods {
			if !m.InRepo && !m.Main {
				continue
			}
			for pkg, files := range m.Files {
				var keep []string
				for _, f := range files {
					abs := filepath.Join(m.Dir, filepath.FromSlash(f))
					rel, err := filepath.Rel(realPath(dir), realPath(abs))
					if err != nil || strings.HasPrefix(rel, "..") {
						keep = append(keep, f)
						continue
					}
					rel = filepath.ToSlash(rel)
					data, err := os.ReadFile(abs)
					if err != nil {
						return nil, nil, err
					}
					if !upstream.has(rel, data) {
						keep = append(keep, f)
						continue
					}
					p := v.Name
					if d := path.Dir(rel); d != "." {
						p += "/" + d
					}
					third.Files[p] = append(third.Files[p], rel)
					excludes = append(excludes, ":(exclude)"+path.Join(v.Path, rel))
				}
				if len(keep) == 0 {
					delete(m.Files, pkg)
				} else {
					m.Files[pkg] = keep
				}
			}
		}
		if len(third.Files) == 0 {
			return nil, nil, fmt.Errorf("vendored %s: none of its files is in %s", v.Path, v.URL)
		}
		mods = append(mods, third)
	}
	return mods, excludes, nil
}

// archive is an upstream release's files, by path.
type archive map[string][]byte

// has reports whether the archive holds a file at rel, or at one path ending in /rel,
// with exactly these bytes. Archives put their files under a top directory, and vendored
// copies often take a subset of them, flattened, so a unique suffix match counts.
func (a archive) has(rel string, data []byte) bool {
	if b, ok := a[rel]; ok {
		return bytes.Equal(b, data)
	}
	var found []byte
	n := 0
	for p, b := range a {
		if strings.HasSuffix(p, "/"+rel) || (path.Base(p) == path.Base(rel) && !strings.Contains(rel, "/")) {
			found, n = b, n+1
		}
	}
	return n == 1 && bytes.Equal(found, data)
}

// fetchArchive downloads an archive, checks its digest, and reads its files.
func fetchArchive(ctx context.Context, url, want string) (archive, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxArchive {
		return nil, fmt.Errorf("%s: too large", url)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != strings.ToLower(want) {
		return nil, fmt.Errorf("%s has sha256 %s, not the %s project.json names", url, got, want)
	}
	return readArchive(url, data)
}

func readArchive(name string, data []byte) (archive, error) {
	files := archive{}
	switch {
	case strings.HasSuffix(name, ".zip"):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxArchive))
			rc.Close()
			if err != nil {
				return nil, err
			}
			files[f.Name] = b
		}
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"), strings.HasSuffix(name, ".crate"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, maxArchive))
			if err != nil {
				return nil, err
			}
			files[h.Name] = b
		}
	default:
		return nil, fmt.Errorf("%s: want a .zip, .tar.gz or .tgz archive", name)
	}
	return files, nil
}

// writeArchive writes an archive's files under dir, stripping one top directory if every
// file has it, and returns dir. Paths that would leave dir are refused.
func writeArchive(a archive, dir string) (string, error) {
	top := ""
	for p := range a {
		first, _, ok := strings.Cut(p, "/")
		if !ok || (top != "" && first != top) {
			top = ""
			break
		}
		top = first
	}
	for p, b := range a {
		rel := p
		if top != "" {
			rel = strings.TrimPrefix(p, top+"/")
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(filepath.Separator)) {
			return "", fmt.Errorf("archive path %q leaves its directory", p)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// fromGit writes the repository's path at a tag into a temporary directory: an older copy
// of something kept in the repository, to diff against.
func fromGit(ctx context.Context, src, tag, repoPath string, log io.Writer) (string, error) {
	var out bytes.Buffer
	cmd := execGit(ctx, src, &out, log, "archive", "--format=tar", tag, "--", repoPath)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git archive %s %s: %w", tag, repoPath, err)
	}
	dir, err := os.MkdirTemp("", "shadybin-old-")
	if err != nil {
		return "", err
	}
	tr := tar.NewReader(&out)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(h.Name, repoPath), "/")
		target := filepath.Join(dir, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, dir+string(filepath.Separator)) {
			return "", fmt.Errorf("git archive path %q leaves its directory", h.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			return "", err
		}
	}
	return dir, nil
}
