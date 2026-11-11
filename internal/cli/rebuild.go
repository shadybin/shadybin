package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/shadybin/shadybin/internal/checksums"
	cleanenv "github.com/shadybin/shadybin/internal/env"
	"github.com/shadybin/shadybin/internal/registry"
	"github.com/shadybin/shadybin/verify"
)

// rebuild runs the project's builds at tag (all of them, or only the one at index which,
// as the certify workflow does on each build's runner), in src if given (which must be a
// clean checkout of the tag) or in a fresh clone, and copies the artifacts into out.
//
// phase is "fetch" (each build's fetch commands only), "run" (its run commands, then the
// artifacts), or "" for both. sealed is the seal record of a checkout seal has sealed,
// which has no .git to check the tag against: the record names the tag and its time.
func rebuild(ctx context.Context, p *registry.Project, which int, tag, src, out, phase, sealed string, log io.Writer) ([]verify.File, error) {
	if phase != "" && phase != "fetch" && phase != "run" {
		return nil, fmt.Errorf("phase %q: want fetch, run or empty for both", phase)
	}
	if which >= len(p.Builds) {
		return nil, fmt.Errorf("the project has %d builds; there is no build %d", len(p.Builds), which)
	}
	var epoch string
	if sealed != "" {
		data, err := os.ReadFile(sealed)
		if err != nil {
			return nil, err
		}
		r, err := parseSealRecord(data)
		if err != nil {
			return nil, err
		}
		if r.Repo != p.Repo || r.Tag != tag {
			return nil, fmt.Errorf("the seal record is for %s %s, not %s %s", r.Repo, r.Tag, p.Repo, tag)
		}
		if src == "" {
			return nil, errors.New("a sealed rebuild runs in the sealed checkout: give -src")
		}
		if _, err := os.Stat(filepath.Join(src, ".git")); err == nil {
			return nil, fmt.Errorf("%s still has .git: it is not sealed", src)
		}
		epoch = strconv.FormatInt(r.Epoch, 10)
	} else if src == "" {
		tmp, err := os.MkdirTemp("", "shadybin-rebuild-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		src = filepath.Join(tmp, "src")
		if _, err := git(ctx, "", log, "clone", "--quiet", "--branch", tag, "--", p.CloneURL(), src); err != nil {
			return nil, err
		}
	}
	if sealed == "" {
		// Tools that honour SOURCE_DATE_EPOCH stamp the commit's time, not the build's.
		_, t, err := checkCheckout(ctx, src, tag, log)
		if err != nil {
			return nil, err
		}
		epoch = strconv.FormatInt(t, 10)
	}
	var files []verify.File
	for i, b := range p.Builds {
		if which >= 0 && i != which {
			continue
		}
		// TAG is the tag being rebuilt, for builds that stamp the version, as a release
		// workflow's own would from its ref. The build runs the vendor's code, so it gets
		// none of the credentials of whoever runs the rebuild.
		env, dropped := cleanenv.Clean(os.Environ())
		if len(dropped) > 0 {
			fmt.Fprintf(log, "rebuild: not passing %s to the build\n", strings.Join(dropped, ", "))
		}
		env = append(env, "SOURCE_DATE_EPOCH="+epoch, "TAG="+tag)
		for k, v := range b.Env {
			env = append(env, k+"="+v)
		}
		var steps []string
		if phase != "run" {
			steps = append(steps, b.Fetch...)
		}
		if phase != "fetch" {
			steps = append(steps, b.Run...)
		}
		for _, step := range steps {
			fmt.Fprintf(log, "+ %s\n", step)
			cmd := exec.CommandContext(ctx, "sh", "-c", step)
			cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = src, env, log, log
			if err := cmd.Run(); err != nil {
				return nil, fmt.Errorf("build %d, step %q: %w", i, step, err)
			}
		}
		if phase == "fetch" {
			continue
		}
		built, err := collect(src, b.Artifacts, out)
		if err != nil {
			return nil, fmt.Errorf("build %d: %w", i, err)
		}
		files = append(files, built...)
	}
	return files, nil
}

// collect copies the files the globs match in src into out, flat, and hashes them.
func collect(src string, globs []string, out string) ([]verify.File, error) {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	var files []verify.File
	for _, g := range globs {
		matches, err := filepath.Glob(filepath.Join(src, filepath.FromSlash(g)))
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("the build made nothing matching %s", g)
		}
		for _, m := range matches {
			name := filepath.Base(m)
			if slices.ContainsFunc(files, func(f verify.File) bool { return f.Name == name }) {
				return nil, fmt.Errorf("two artifacts are named %s", name)
			}
			if err := copyFile(m, filepath.Join(out, name)); err != nil {
				return nil, err
			}
			d, err := checksums.File(m)
			if err != nil {
				return nil, err
			}
			files = append(files, verify.File{Name: name, Digest: d})
		}
	}
	slices.SortFunc(files, func(a, b verify.File) int { return strings.Compare(a.Name, b.Name) })
	return files, nil
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// git runs git in dir and returns its trimmed output; its errors go to log.
func git(ctx context.Context, dir string, log io.Writer, args ...string) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &stdout, log
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}
