package manifest

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// quiet are capabilities nearly every package has, through formatting, encoding or the
// runtime; listing them says nothing about a release.
var quiet = map[string]bool{"UNANALYZED": true, "REFLECT": true, "RUNTIME": true}

// Notable returns a package's capabilities without the quiet ones.
func (m *Manifest) Notable(pkg string) []string {
	return slices.DeleteFunc(slices.Clone(m.Capabilities[pkg]), func(c string) bool { return quiet[c] })
}

// Change is what a release newly does, or no longer does, compared with an earlier one.
type Change struct {
	// Added and Removed map a package to capabilities it gained or lost.
	Added, Removed map[string][]string
	// NewPackages and GonePackages are packages compiled in, or no longer.
	NewPackages, GonePackages []string
	// Modules map a dependency module whose version changed to its old and new versions;
	// an empty version means it was not compiled in.
	Modules map[string][2]string
}

// Empty reports whether nothing changed.
func (c *Change) Empty() bool {
	return len(c.Added) == 0 && len(c.Removed) == 0 && len(c.NewPackages) == 0 && len(c.GonePackages) == 0 && len(c.Modules) == 0
}

// Diff compares the notable capabilities of m with an earlier release's.
func Diff(prev, m *Manifest) *Change {
	c := &Change{Added: map[string][]string{}, Removed: map[string][]string{}, Modules: map[string][2]string{}}
	for _, mod := range union(slices.Collect(maps.Keys(m.Modules)), slices.Collect(maps.Keys(prev.Modules))) {
		if prev.Modules[mod] != m.Modules[mod] {
			c.Modules[mod] = [2]string{prev.Modules[mod], m.Modules[mod]}
		}
	}
	c.NewPackages = minus(m.Packages, prev.Packages)
	c.GonePackages = minus(prev.Packages, m.Packages)
	for _, p := range union(slices.Collect(maps.Keys(m.Capabilities)), slices.Collect(maps.Keys(prev.Capabilities))) {
		if a := minus(m.Notable(p), prev.Notable(p)); len(a) > 0 {
			c.Added[p] = a
		}
		if r := minus(prev.Notable(p), m.Notable(p)); len(r) > 0 {
			c.Removed[p] = r
		}
	}
	return c
}

// Markdown writes the report's capabilities section. prev, the last certified release's
// manifest, and prevTag may be nil and empty for a project's first release.
func (m *Manifest) Markdown(w io.Writer, prev *Manifest, prevTag string) {
	fmt.Fprintln(w, "## Capabilities")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "What each package compiled into the binary uses directly from the standard library, for %s, found by `%s`. Reflection, runtime and unanalyzed calls are left out: nearly every package has them.\n\n",
		strings.Join(m.GOOS, ", "), m.Tool)
	byCap := map[string][]string{}
	for p := range m.Capabilities {
		for _, c := range m.Notable(p) {
			byCap[c] = append(byCap[c], p)
		}
	}
	fmt.Fprintln(w, "| Capability | Packages |")
	fmt.Fprintln(w, "|---|---|")
	for _, c := range slices.Sorted(maps.Keys(byCap)) {
		fmt.Fprintf(w, "| %s | <details><summary>%d</summary>%s</details> |\n", c, len(byCap[c]), m.list(byCap[c]))
	}
	fmt.Fprintf(w, "\n%d packages outside the standard library are compiled in.\n\n", len(m.Packages))

	if prev == nil {
		fmt.Fprintln(w, "### Changes")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This is the project's first certified release: there is nothing to compare it with.")
		return
	}
	fmt.Fprintf(w, "### Changes since %s\n\n", prevTag)
	c := Diff(prev, m)
	if c.Empty() {
		fmt.Fprintln(w, "None: the same packages, with the same capabilities.")
		return
	}
	for _, p := range slices.Sorted(maps.Keys(c.Added)) {
		fmt.Fprintf(w, "- `%s` now uses %s\n", m.short(p), strings.Join(c.Added[p], ", "))
	}
	for _, p := range slices.Sorted(maps.Keys(c.Removed)) {
		fmt.Fprintf(w, "- `%s` no longer uses %s\n", m.short(p), strings.Join(c.Removed[p], ", "))
	}
	if len(c.NewPackages) > 0 {
		fmt.Fprintf(w, "- New packages: %s\n", m.list(c.NewPackages))
	}
	if len(c.GonePackages) > 0 {
		fmt.Fprintf(w, "- Packages removed: %s\n", m.list(c.GonePackages))
	}
	for _, mod := range slices.Sorted(maps.Keys(c.Modules)) {
		switch v := c.Modules[mod]; {
		case v[0] == "":
			fmt.Fprintf(w, "- New dependency `%s@%s`\n", mod, v[1])
		case v[1] == "":
			fmt.Fprintf(w, "- Dependency `%s` removed (was %s)\n", mod, v[0])
		default:
			fmt.Fprintf(w, "- Dependency `%s` %s → %s\n", mod, v[0], v[1])
		}
	}
}

func (m *Manifest) short(p string) string {
	if rest, ok := strings.CutPrefix(p, m.Module); ok && (rest == "" || rest[0] == '/') {
		return "." + rest
	}
	return p
}

// list formats packages for the report, sorted as shortened, so the project's own
// (./...) come before its dependencies.
func (m *Manifest) list(pkgs []string) string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = m.short(p)
	}
	slices.Sort(out)
	for i, p := range out {
		out[i] = "`" + p + "`"
	}
	return strings.Join(out, ", ")
}

// minus returns the sorted elements of a not in b.
func minus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

func union(a, b []string) []string {
	out := slices.Concat(a, b)
	slices.Sort(out)
	return slices.Compact(out)
}
