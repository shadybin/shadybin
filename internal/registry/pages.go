package registry

import (
	"bytes"
	"cmp"
	"encoding/json"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/shadybin/shadybin/verify"
)

// SiteURL is where the registry is served; RepoURL is the repository it is served from,
// where GitHub renders its markdown reports.
const (
	SiteURL = "https://shadybin.dev/registry"
	RepoURL = "https://github.com/shadybin/registry/blob/main"
)

// release is one release on a project's page.
type release struct {
	Tag     string
	State   string // certified, rejected, or the badge's pending or not certified
	Signed  bool
	Message string // the badge's text
	Color   string
}

type project struct {
	Repo     string
	Badge    string
	Releases []release
}

// WritePages writes the registry's HTML: an index of every project, and a page per
// project listing its releases and their verdicts. GitHub Pages serves the registry as
// files, so without these a project's address, the one its badge links to, is a 404.
func WritePages(root string) error {
	var projects []project
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".github" || d.Name() == "deps") {
			return filepath.SkipDir
		}
		if d.IsDir() || d.Name() != "project.json" {
			return nil
		}
		dir := filepath.Dir(path)
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return err
		}
		p := project{Repo: filepath.ToSlash(rel), Badge: badgeImage(filepath.ToSlash(rel))}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() || verify.ValidTag(e.Name()) != nil {
				continue
			}
			r := release{Tag: e.Name()}
			if data, err := os.ReadFile(filepath.Join(dir, e.Name(), verify.StatementName)); err == nil {
				if _, err := os.Stat(filepath.Join(dir, e.Name(), verify.SignatureName)); err == nil {
					if s, err := verify.ParseStatement(data); err == nil {
						r.State, r.Signed = s.Verdict, true
					}
				}
			}
			b := loadBadge(filepath.Join(dir, e.Name(), BadgeName))
			if r.State == "" {
				r.State = strings.TrimSpace(strings.TrimPrefix(b.Message, e.Name()))
			}
			r.Message, r.Color = b.Message, b.Color
			if r.Message == "" {
				r.Message = e.Name() + " " + r.State
			}
			p.Releases = append(p.Releases, r)
		}
		slices.SortFunc(p.Releases, func(a, b release) int { return compareVersions(b.Tag, a.Tag) })
		projects = append(projects, p)
		var page bytes.Buffer
		if err := projectPage.Execute(&page, p); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "index.html"), page.Bytes(), 0o644)
	})
	if err != nil {
		return err
	}
	slices.SortFunc(projects, func(a, b project) int { return strings.Compare(a.Repo, b.Repo) })
	var page bytes.Buffer
	if err := indexPage.Execute(&page, projects); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "index.html"), page.Bytes(), 0o644)
}

func loadBadge(path string) Badge {
	var b Badge
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &b)
	}
	return b
}

func badgeImage(repo string) string {
	return "https://img.shields.io/endpoint?url=" + SiteURL + "/" + repo + "/" + BadgeName
}

// compareVersions orders tags by their numbers, so v0.10.0 comes after v0.9.0.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea == nil && eb == nil {
			if c := cmp.Compare(na, nb); c != 0 {
				return c
			}
		} else if c := strings.Compare(pa[i], pb[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(pa), len(pb))
}

func versionParts(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsDigit(r) && !unicode.IsLetter(r) })
}

const pageStyle = `
:root { --ink:#1c1f1a; --muted:#5c6157; --paper:#fbfaf6; --card:#fff; --line:#e6e3da; --green:#14532d;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace; }
* { box-sizing: border-box; }
html { background: var(--paper); }
body { margin: 0; color: var(--ink); font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }
a { color: var(--green); text-underline-offset: 3px; }
.wrap { max-width: 56rem; margin: 0 auto; padding: 0 1.5rem; }
header { padding: 1.5rem 0; }
header .wrap { display: flex; align-items: center; justify-content: space-between; }
.wordmark { font: 600 1.15rem/1 var(--mono); color: var(--ink); text-decoration: none; }
.wordmark span { color: var(--green); }
nav a { color: var(--muted); text-decoration: none; margin-left: 1.5rem; font-size: 0.95rem; }
main { padding: 2.5rem 0 4rem; }
h1 { font-size: 2rem; letter-spacing: -0.03em; margin: 0 0 0.5rem; word-break: break-word; }
.sub { color: var(--muted); margin: 0 0 1.5rem; }
.badge { height: 20px; vertical-align: middle; }
table { border-collapse: collapse; width: 100%; background: var(--card); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; font-size: 0.95rem; }
th, td { text-align: left; padding: 0.75rem 1rem; border-top: 1px solid var(--line); vertical-align: middle; }
th { border-top: 0; color: var(--muted); font-weight: 600; font-size: 0.85rem; background: #f6f4ee; }
.tag { font: 600 0.95rem var(--mono); }
.pill { display: inline-block; font: 600 0.8rem/1 var(--mono); padding: 0.35rem 0.55rem; border-radius: 6px; white-space: nowrap; }
.green { background: #dcfce7; color: #14532d; } .red { background: #fee2e2; color: #991b1b; }
.grey { background: #ececeb; color: #4b4b48; } .orange { background: #ffedd5; color: #9a3412; }
.files a { margin-right: 0.8rem; white-space: nowrap; }
.muted { color: var(--muted); }
footer { border-top: 1px solid var(--line); padding: 2rem 0 3rem; color: var(--muted); font-size: 0.9rem; }
`

var funcs = template.FuncMap{
	"pill": func(color string) string {
		switch color {
		case "brightgreen":
			return "green"
		case "red":
			return "red"
		case "orange":
			return "orange"
		}
		return "grey"
	},
	"repoURL":  func() string { return RepoURL },
	"siteURL":  func() string { return SiteURL },
	"upstream": func(repo string) string { return "https://" + repo },
}

const pageHead = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%2314532d'/%3E%3Cpath d='M18 33l9 9 19-20' fill='none' stroke='%23fff' stroke-width='7' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>` + pageStyle + `</style>`

const pageHeader = `<header><div class="wrap"><a class="wordmark" href="https://shadybin.dev/">shady<span>bin</span></a>
<nav><a href="{{siteURL}}/">Registry</a><a href="https://github.com/shadybin/registry#readme">About</a><a href="https://github.com/shadybin/shadybin">GitHub</a></nav></div></header>`

const pageFooter = `<footer><div class="wrap">Every signature here is a commit in <a href="https://github.com/shadybin/registry">shadybin/registry</a>. Verify any of them with shadybin's public key, <code>d971638b…2ed8fc</code>; see <a href="https://github.com/shadybin/registry#checking-a-release">how</a>.</div></footer>`

var projectPage = template.Must(template.New("project").Funcs(funcs).Parse(pageHead + `
<title>{{.Repo}}: shadybin</title></head><body>` + pageHeader + `
<main><div class="wrap">
<h1>{{.Repo}}</h1>
<p class="sub"><img class="badge" src="{{.Badge}}" alt="badge"> · <a href="{{upstream .Repo}}">source</a> · <a href="{{repoURL}}/{{.Repo}}/project.json">how it is rebuilt</a></p>
{{if .Releases}}<table>
<tr><th>Release</th><th>Verdict</th><th>Files</th></tr>
{{range .Releases}}<tr>
<td class="tag">{{.Tag}}</td>
<td><span class="pill {{pill .Color}}">{{.Message}}</span></td>
<td class="files">{{if .Signed}}<a href="{{repoURL}}/{{$.Repo}}/{{.Tag}}/report.md">report</a><a href="{{siteURL}}/{{$.Repo}}/{{.Tag}}/statement.txt">statement</a><a href="{{siteURL}}/{{$.Repo}}/{{.Tag}}/statement.txt.sig">signature</a><a href="{{siteURL}}/{{$.Repo}}/{{.Tag}}/manifest.json">manifest</a><a href="{{siteURL}}/{{$.Repo}}/{{.Tag}}/review.json">review</a>{{else}}<span class="muted">no statement</span>{{end}}</td>
</tr>{{end}}
</table>{{else}}<p class="muted">No releases yet.</p>{{end}}
</div></main>` + pageFooter + `</body></html>
`))

var indexPage = template.Must(template.New("index").Funcs(funcs).Parse(pageHead + `
<title>The shadybin registry</title></head><body>` + pageHeader + `
<main><div class="wrap">
<h1>The registry</h1>
<p class="sub">Every project shadybin certifies, and each one's latest release. <a href="https://github.com/shadybin/registry#adding-a-project">Add yours.</a></p>
<table>
<tr><th>Project</th><th>Latest release</th></tr>
{{range .}}<tr><td><a href="{{siteURL}}/{{.Repo}}/">{{.Repo}}</a></td><td><img class="badge" src="{{.Badge}}" alt="badge"></td></tr>{{end}}
</table>
</div></main>` + pageFooter + `</body></html>
`))
