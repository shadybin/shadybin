package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/shadybin/shadybin/internal/checksums"
	"github.com/shadybin/shadybin/internal/registry"
	"github.com/shadybin/shadybin/verify"
)

// rebuild runs the project's builds at tag (all of them, or only the one at index which,
// as the certify workflow does on each build's runner), in src if given (which must be a
// clean checkout of the tag) or in a fresh clone, and copies the artifacts into out.
func rebuild(ctx context.Context, p *registry.Project, which int, tag, src, out string, log io.Writer) ([]verify.File, error) {
	if which >= len(p.Builds) {
		return nil, fmt.Errorf("the project has %d builds; there is no build %d", len(p.Builds), which)
	}
	if src == "" {
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
	head, err := git(ctx, src, log, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	tagged, err := git(ctx, src, log, "rev-parse", "refs/tags/"+tag+"^{commit}")
	if err != nil {
		return nil, err
	}
	if head != tagged {
		return nil, fmt.Errorf("%s is at %s, not at %s (%s)", src, head, tag, tagged)
	}
	if dirty, err := git(ctx, src, log, "status", "--porcelain"); err != nil {
		return nil, err
	} else if dirty != "" {
		return nil, fmt.Errorf("%s has changes the tag does not:\n%s", src, dirty)
	}
	// Tools that honour SOURCE_DATE_EPOCH stamp the commit's time, not the build's.
	epoch, err := git(ctx, src, log, "log", "-1", "--format=%ct")
	if err != nil {
		return nil, err
	}
	var files []verify.File
	for i, b := range p.Builds {
		if which >= 0 && i != which {
			continue
		}
		// TAG is the tag being rebuilt, for builds that stamp the version, as a release
		// workflow's own would from its ref. The build runs the vendor's code, so it gets
		// none of the credentials of whoever runs the rebuild.
		env, dropped := buildEnv(os.Environ())
		if len(dropped) > 0 {
			fmt.Fprintf(log, "rebuild: not passing %s to the build\n", strings.Join(dropped, ", "))
		}
		env = append(env, "SOURCE_DATE_EPOCH="+epoch, "TAG="+tag)
		for k, v := range b.Env {
			env = append(env, k+"="+v)
		}
		for _, step := range b.Run {
			fmt.Fprintf(log, "+ %s\n", step)
			cmd := exec.CommandContext(ctx, "sh", "-c", step)
			cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = src, env, log, log
			if err := cmd.Run(); err != nil {
				return nil, fmt.Errorf("build %d, step %q: %w", i, step, err)
			}
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

// buildEnv is the environment a build runs in: the caller's, less anything that looks like
// a credential, since the build runs the vendor's code (build.zig, build.rs, a Makefile).
// The certify workflow gives its rebuild jobs no secrets; this covers anyone else running
// rebuild, and secrets added later. It returns the names it dropped.
func buildEnv(environ []string) (env, dropped []string) {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if credential(name) {
			dropped = append(dropped, name)
			continue
		}
		env = append(env, kv)
	}
	slices.Sort(dropped)
	return env, dropped
}

// credential reports whether an environment variable's name says it holds a credential,
// or a way to reach one: an API key, a token, a password, an agent's socket, or the
// GitHub Actions runtime's own tokens, with which a build could mint an identity or
// upload artifacts.
func credential(name string) bool {
	n := strings.ToUpper(name)
	for _, prefix := range []string{"ANTHROPIC_", "SHADYBIN_", "ACTIONS_", "OP_", "AWS_", "AZURE_", "GOOGLE_", "GCP_", "NPM_", "CARGO_REGISTRY_", "TWINE_"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	switch n {
	case "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "NETRC":
		return true
	}
	for _, part := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL"} {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}
