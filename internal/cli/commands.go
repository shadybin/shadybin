package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/shadybin/shadybin/internal/checksums"
	"github.com/shadybin/shadybin/internal/keys"
	"github.com/shadybin/shadybin/internal/manifest"
	"github.com/shadybin/shadybin/internal/registry"
	"github.com/shadybin/shadybin/internal/review"
	"github.com/shadybin/shadybin/verify"
)

// signingKeyEnv holds the private key when -key is not given, as a CI secret would.
const signingKeyEnv = "SHADYBIN_SIGNING_KEY"

func runKeygen(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("keygen", "", stderr)
	out := fs.String("o", "", "file to write the private key to; must not exist")
	if err := parse(fs, args, "o"); err != nil {
		return err
	}
	pub, err := keys.Generate(*out)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "wrote the private key to %s; the public key, to pin, is:\n", *out)
	fmt.Fprintln(stdout, pub)
	return nil
}

func runRebuild(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("rebuild", "", stderr)
	project := fs.String("project", "", "the project's project.json")
	tag := fs.String("tag", "", "the tag to rebuild")
	src := fs.String("src", "", "a clean checkout of the tag; empty clones it")
	out := fs.String("out", "", "directory to collect the built files in")
	which := fs.Int("build", -1, "run only the project's build at this index, from 0; -1 runs them all")
	if err := parse(fs, args, "project", "tag", "out"); err != nil {
		return err
	}
	p, err := registry.LoadProject(*project)
	if err != nil {
		return err
	}
	if err := verify.ValidTag(*tag); err != nil {
		return err
	}
	built, err := rebuild(ctx, p, *which, *tag, *src, *out, stderr)
	if err != nil {
		return err
	}
	for _, f := range built {
		fmt.Fprint(stdout, checksums.Line(f.Name, f.Digest))
	}
	return nil
}

func runCompare(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("compare", "<rebuilt-dir>", stderr)
	published := fs.String("published", "", "the vendor's published checksums file")
	if err := parse(fs, args, "published"); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errUsage
	}
	pub, err := readChecksums(*published)
	if err != nil {
		return err
	}
	rebuilt, err := hashDir(fs.Arg(0))
	if err != nil {
		return err
	}
	rows := compare(pub, rebuilt)
	fmt.Fprintln(stdout, "| File | Published | Rebuilt | Result |")
	fmt.Fprintln(stdout, "|---|---|---|---|")
	matched, differs := 0, 0
	for _, r := range rows {
		fmt.Fprintf(stdout, "| `%s` | %s | %s | %s |\n", r.name, short(r.published), short(r.rebuilt), r.result)
		switch r.result {
		case resultMatch:
			matched++
		case resultDiffers:
			differs++
		}
	}
	if differs > 0 || matched == 0 {
		fmt.Fprintf(stderr, "shadybin compare: %d identical, %d different\n", matched, differs)
		return errFailed
	}
	return nil
}

func runStatement(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("statement", "<rebuilt-dir>", stderr)
	root := fs.String("registry", "", "registry directory to write the release into")
	repo := fs.String("repo", "", "the source repository, host/owner/name")
	tag := fs.String("tag", "", "the tag the files were rebuilt from")
	published := fs.String("published", "", "the vendor's published checksums file")
	report := fs.String("report", "", "the review's report.md")
	manifestFile := fs.String("manifest", "", "the release's manifest.json")
	reviewFile := fs.String("review", "", "the release's review.json, whose verdict the statement carries")
	if err := parse(fs, args, "registry", "repo", "tag", "published", "report", "manifest", "review"); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errUsage
	}
	pub, err := readChecksums(*published)
	if err != nil {
		return err
	}
	rebuilt, err := hashDir(fs.Arg(0))
	if err != nil {
		return err
	}
	s := verify.Statement{Repo: repoFlag(*repo), Tag: *tag}
	for _, r := range compare(pub, rebuilt) {
		switch r.result {
		case resultDiffers:
			return fmt.Errorf("%s: the rebuilt file is not the published one (%s, published %s)", r.name, r.rebuilt, r.published)
		case resultMatch:
			s.Files = append(s.Files, verify.File{Name: r.name, Digest: r.rebuilt})
		case resultUnpublished:
			fmt.Fprintf(stderr, "shadybin statement: %s was rebuilt but not published; leaving it out\n", r.name)
		case resultNotRebuilt:
			fmt.Fprintf(stderr, "shadybin statement: %s was published but not rebuilt; it is not certified\n", r.name)
		}
	}
	reportData, err := os.ReadFile(*report)
	if err != nil {
		return err
	}
	s.Report, err = checksums.File(*report)
	if err != nil {
		return err
	}
	if _, err := manifest.Load(*manifestFile); err != nil {
		return err
	}
	manifestData, err := os.ReadFile(*manifestFile)
	if err != nil {
		return err
	}
	s.Manifest, err = checksums.File(*manifestFile)
	if err != nil {
		return err
	}
	rv, err := review.Load(*reviewFile)
	if err != nil {
		return err
	}
	s.Verdict = rv.Verdict
	reviewData, err := os.ReadFile(*reviewFile)
	if err != nil {
		return err
	}
	if s.Review, err = checksums.File(*reviewFile); err != nil {
		return err
	}
	data, err := s.Marshal()
	if err != nil {
		return err
	}
	dir, err := registry.ReleaseDir(*root, s.Repo, s.Tag)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, verify.StatementName)); err == nil {
		return registry.ErrExists
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, verify.ReportName), reportData, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, verify.ManifestName), manifestData, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, verify.ReviewName), reviewData, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, verify.StatementName), data, 0o644); err != nil {
		return err
	}
	fmt.Fprintln(stdout, filepath.Join(dir, verify.StatementName))
	return nil
}

func runSign(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("sign", "", stderr)
	root := fs.String("registry", "", "the registry directory")
	repo := fs.String("repo", "", "the source repository, host/owner/name")
	tag := fs.String("tag", "", "the release's tag")
	keyFile := fs.String("key", "", "the private key file; empty reads $"+signingKeyEnv)
	if err := parse(fs, args, "registry", "repo", "tag"); err != nil {
		return err
	}
	keyText := os.Getenv(signingKeyEnv)
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		keyText = string(b)
	}
	if keyText == "" {
		return fmt.Errorf("no key: give -key or set $%s", signingKeyEnv)
	}
	k, err := keys.Parse(keyText)
	if err != nil {
		return err
	}
	dir, err := registry.ReleaseDir(*root, repoFlag(*repo), *tag)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, verify.StatementName))
	if err != nil {
		return err
	}
	s, err := verify.ParseStatement(data)
	if err != nil {
		return err
	}
	if s.Repo != repoFlag(*repo) || s.Tag != *tag {
		return fmt.Errorf("the statement in %s is for %s %s", dir, s.Repo, s.Tag)
	}
	// What is signed for is what is published: check the report and manifest beside the
	// statement are the ones it names before vouching for them.
	for name, want := range map[string]verify.Digest{verify.ReportName: s.Report, verify.ManifestName: s.Manifest, verify.ReviewName: s.Review} {
		got, err := checksums.File(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s is not the one the statement names", name)
		}
	}
	// Nobody approves a verdict, so the rule that reached it runs again here, on what is
	// published, before anything is signed.
	rv, err := review.Load(filepath.Join(dir, verify.ReviewName))
	if err != nil {
		return err
	}
	m, err := manifest.Load(filepath.Join(dir, verify.ManifestName))
	if err != nil {
		return err
	}
	var prev *manifest.Manifest
	if rv.Previous != "" {
		if err := certifiedIn(*root, s.Repo, rv.Previous); err != nil {
			return fmt.Errorf("the review is against %s: %w", rv.Previous, err)
		}
		prevDir, _ := registry.ReleaseDir(*root, s.Repo, rv.Previous)
		if prev, err = manifest.Load(filepath.Join(prevDir, verify.ManifestName)); err != nil {
			return err
		}
	}
	verdict, reasons := review.Decide(rv, m, prev)
	if verdict != s.Verdict || verdict != rv.Verdict {
		return fmt.Errorf("the statement says %s, but the review's answers give %s %v", s.Verdict, verdict, reasons)
	}
	sigPath := filepath.Join(dir, verify.SignatureName)
	existing, err := os.ReadFile(sigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := verify.Open(data, existing, []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}); err == nil {
		fmt.Fprintln(stderr, "shadybin sign: already signed with this key")
		return nil
	}
	f, err := os.OpenFile(sigPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, keys.Sign(k, data)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := registry.Published(*root, s.Repo, s.Tag, s.Verdict); err != nil {
		return err
	}
	n, err := review.WriteEntries(*root, rv, k)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s %s, %s, with %s; %d new dependency reviews cached\n", s.Repo, s.Tag, s.Verdict, keys.Public(k), n)
	return nil
}

func runManifest(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("manifest", "", stderr)
	project := fs.String("project", "", "the project's project.json")
	src := fs.String("src", "", "the checkout to analyse")
	out := fs.String("o", "", "file to write manifest.json to")
	if err := parse(fs, args, "project", "src", "o"); err != nil {
		return err
	}
	p, err := registry.LoadProject(*project)
	if err != nil {
		return err
	}
	m, err := buildManifest(ctx, p, *src, stderr)
	if err != nil {
		return err
	}
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

func runCapabilities(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("capabilities", "<manifest.json>", stderr)
	previous := fs.String("previous", "", "the last certified release's manifest.json, to list what changed")
	previousTag := fs.String("previous-tag", "", "the last certified release's tag")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 || (*previous == "") != (*previousTag == "") {
		fs.Usage()
		return errUsage
	}
	m, err := manifest.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	var prev *manifest.Manifest
	if *previous != "" {
		if prev, err = manifest.Load(*previous); err != nil {
			return err
		}
	}
	m.Markdown(stdout, prev, *previousTag)
	return nil
}

func runReview(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("review", "", stderr)
	project := fs.String("project", "", "the project's project.json")
	src := fs.String("src", "", "a clean checkout of the release's tag, with tags fetched")
	manifestFile := fs.String("manifest", "", "the release's manifest.json")
	previous := fs.String("previous", "", "the last certified release's manifest.json; empty reviews everything whole")
	previousTag := fs.String("previous-tag", "", "the last certified release's tag")
	cacheFrom := fs.String("cache", "", "registry URL or directory to read cached dependency reviews from")
	cacheKeys := fs.String("cache-key", "", "shadybin public keys, hex, comma-separated, that cache entries must be signed by")
	out := fs.String("o", "", "file to write review.json to")
	dryRun := fs.Bool("dry-run", false, "list the units and their size, and call no model")
	if err := parse(fs, args, "project", "src", "manifest"); err != nil {
		return err
	}
	if (*previous == "") != (*previousTag == "") || (*out == "" && !*dryRun) {
		fs.Usage()
		return errUsage
	}
	p, err := registry.LoadProject(*project)
	if err != nil {
		return err
	}
	in := review.Inputs{Src: *src, Source: sourceFor(p, *previousTag), Owned: p.Owned, Extra: p.Analyze.Files,
		Vendored: vendoredFor(p), PreviousTag: *previousTag}
	if len(in.Owned) == 0 {
		in.Owned = review.OwnedPrefixes(p.Repo)
	}
	if in.Manifest, err = manifest.Load(*manifestFile); err != nil {
		return err
	}
	if *previous != "" {
		if in.Previous, err = manifest.Load(*previous); err != nil {
			return err
		}
	}
	plan, err := review.Gather(ctx, in, stderr)
	if err != nil {
		return err
	}
	var cache *review.Cache
	if *cacheFrom != "" {
		cache = &review.Cache{Registry: *cacheFrom}
		for h := range strings.SplitSeq(*cacheKeys, ",") {
			k, err := verify.ParseKey(h)
			if err != nil {
				return fmt.Errorf("-cache-key: %w", err)
			}
			cache.Keys = append(cache.Keys, k)
		}
	}
	if *dryRun {
		total := 0
		for _, u := range plan.Units {
			hit, err := cache.Lookup(ctx, &u)
			if err != nil {
				return err
			}
			state := ""
			if hit != nil {
				state = "cached"
			}
			fmt.Fprintf(stdout, "%-10s %-60s %-24s %d/%d %8dk tokens %s\n", u.Kind, u.Module, u.From+".."+u.To, u.Part, u.Parts, review.Tokens(&u)/1000, state)
			if hit == nil {
				total += review.Tokens(&u)
			}
		}
		byScope := map[string]int{}
		for _, m := range plan.Modules {
			who := "third-party"
			if m.Owned {
				who = "owned"
			}
			byScope[who+" "+m.Scope]++
		}
		for _, k := range slices.Sorted(maps.Keys(byScope)) {
			fmt.Fprintf(stdout, "modules: %d %s\n", byScope[k], k)
		}
		for _, m := range plan.Modules {
			if m.Provenance != "" && m.Provenance != "from its repository" {
				fmt.Fprintf(stdout, "provenance: %s@%s %s %v\n", m.Path, m.Version, m.Provenance, m.Foreign)
			}
		}
		fmt.Fprintf(stdout, "%d units, about %dk input tokens to review\n", len(plan.Units), total/1000)
		return nil
	}
	rv, err := review.Run(ctx, in, plan, review.NewClaude(), cache, stderr)
	if err != nil {
		return err
	}
	data, err := rv.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	rv.Markdown(stdout)
	return nil
}

// certifiedIn checks the registry at root holds a signed, certified statement for the tag.
// The registry's main branch is shadybin's own record, so a signature there is its own.
func certifiedIn(root, repo, tag string) error {
	dir, err := registry.ReleaseDir(root, repo, tag)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, verify.StatementName))
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, verify.SignatureName)); err != nil {
		return errors.New("not signed")
	}
	s, err := verify.ParseStatement(data)
	if err != nil {
		return err
	}
	if s.Verdict != verify.Certified {
		return errors.New("it was not certified")
	}
	return nil
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("verify", "<file>...", stderr)
	reg := fs.String("registry", verify.DefaultRegistry, "registry URL, or a local registry directory")
	keyList := fs.String("key", "", "trusted public keys, hex, comma-separated")
	repo := fs.String("repo", "", "the source repository, host/owner/name")
	tag := fs.String("tag", "", "the release's tag")
	if err := parse(fs, args, "key", "repo", "tag"); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errUsage
	}
	c := verify.Checker{Registry: *reg}
	for h := range strings.SplitSeq(*keyList, ",") {
		k, err := verify.ParseKey(h)
		if err != nil {
			return err
		}
		c.Keys = append(c.Keys, k)
	}
	if !strings.HasPrefix(*reg, "https://") && !strings.HasPrefix(*reg, "http://") {
		abs, err := filepath.Abs(*reg)
		if err != nil {
			return err
		}
		t := &http.Transport{}
		t.RegisterProtocol("file", http.NewFileTransport(http.Dir(abs)))
		c.Registry, c.Client = "file:///", &http.Client{Transport: t}
	}
	s, err := c.Statement(ctx, *repo, *tag)
	if err != nil {
		return err
	}
	failed := false
	for _, path := range fs.Args() {
		d, err := checksums.File(path)
		if err == nil {
			err = s.Covers(filepath.Base(path), d)
		}
		if err != nil {
			fmt.Fprintf(stderr, "FAIL %s: %v\n", path, err)
			failed = true
			continue
		}
		fmt.Fprintf(stdout, "ok   %s\n", path)
	}
	if failed {
		return errFailed
	}
	return nil
}

const (
	resultMatch       = "identical"
	resultDiffers     = "**DIFFERENT**"
	resultNotRebuilt  = "not rebuilt"
	resultUnpublished = "not published"
)

type row struct {
	name               string
	published, rebuilt verify.Digest
	result             string
}

// compare lines up the published files with the rebuilt ones, sorted by name.
func compare(published, rebuilt map[string]verify.Digest) []row {
	var rows []row
	for name, p := range published {
		r, ok := rebuilt[name]
		switch {
		case !ok:
			rows = append(rows, row{name: name, published: p, result: resultNotRebuilt})
		case r == p:
			rows = append(rows, row{name: name, published: p, rebuilt: r, result: resultMatch})
		default:
			rows = append(rows, row{name: name, published: p, rebuilt: r, result: resultDiffers})
		}
	}
	for name, r := range rebuilt {
		if _, ok := published[name]; !ok {
			rows = append(rows, row{name: name, rebuilt: r, result: resultUnpublished})
		}
	}
	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.name, b.name) })
	return rows
}

func short(d verify.Digest) string {
	if d == (verify.Digest{}) {
		return "—"
	}
	return "`" + d.String()[:len("sha256:")+12] + "…`"
}

func readChecksums(path string) (map[string]verify.Digest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return checksums.Parse(data)
}

// hashDir hashes the regular files directly in dir.
func hashDir(dir string) (map[string]verify.Digest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]verify.Digest{}
	for _, e := range entries {
		if e.Type()&os.ModeType != 0 {
			continue
		}
		d, err := checksums.File(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = d
	}
	return out, nil
}
