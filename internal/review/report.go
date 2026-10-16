package review

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// Markdown writes the report's review section.
func (r *Review) Markdown(w io.Writer) {
	fmt.Fprintln(w, "## Review")
	fmt.Fprintln(w)
	cached := 0
	for _, u := range r.Units {
		if u.Cached {
			cached++
		}
	}
	if r.Verdict == Certified {
		fmt.Fprintln(w, "**Certified.**")
	} else {
		fmt.Fprintln(w, "**Rejected:**")
		fmt.Fprintln(w)
		for _, reason := range r.Reasons {
			fmt.Fprintf(w, "- %s\n", oneLine(reason))
		}
	}
	fmt.Fprintln(w)
	since := "whole, as the project's first reviewed release"
	if r.Previous != "" {
		since = "as what changed since " + r.Previous + ", the last certified release"
	}
	fmt.Fprintf(w, "`%s` reviewed the code compiled into the binary %s: %d units, %d of them answered from the shared cache. The verdict follows from its answers by a fixed rule, with no person involved.\n",
		r.Model, since, len(r.Units), cached)
	r.modules(w)
	for _, u := range r.Units {
		fmt.Fprintln(w)
		title := "`" + u.Module + "`"
		switch {
		case u.Kind == KindProject && u.From != "":
			title += " changes since " + u.From
		case u.Kind == KindProject:
			title += " (the project)"
		case u.From != "":
			title += " " + u.From + " → " + u.To
		case u.Scope == ScopeSurface:
			title += " " + u.To + ", surface"
		case u.To != "":
			title += " " + u.To
		default:
			title += " (local replacement)"
		}
		title += partName(u)
		if u.Cached {
			title += ", cached"
		}
		fmt.Fprintf(w, "### %s\n\n", title)
		if u.Result == nil {
			fmt.Fprintln(w, "Not reviewed.")
			continue
		}
		fmt.Fprintf(w, "%s: %s\n", strings.ToUpper(u.Result.Verdict), oneLine(u.Result.Summary))
		if len(u.Result.Findings) > 0 {
			fmt.Fprintln(w)
			for _, f := range u.Result.Findings {
				fmt.Fprintf(w, "- **%s** `%s:%d` %s: %s\n", f.Severity, f.File, f.Line, oneLine(f.Title), oneLine(f.Detail))
			}
		}
		if len(u.Result.DataFlows) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Data leaving the process:")
			fmt.Fprintln(w)
			for _, d := range u.Result.DataFlows {
				fmt.Fprintf(w, "- %s → %s (`%s`)\n", oneLine(d.What), oneLine(d.To), d.File)
			}
		}
	}
}

// modules says how each module compiled in was treated, so what the verdict covers is plain.
func (r *Review) modules(w io.Writer) {
	if len(r.Modules) == 0 {
		return
	}
	groups := map[string][]string{}
	for _, m := range r.Modules {
		name := "`" + m.Path + "`"
		if m.Version != "" {
			name = "`" + m.Path + "@" + m.Version + "`"
		}
		var key string
		switch {
		case m.Scope == "project":
			key = "Reviewed with the project's code, since it is in the vendor's repository"
		case m.Owned:
			key = "The vendor's own, reviewed " + m.Scope
		case m.Scope == ScopeSurface:
			key = "Third-party, new to the project: reviewed at its surface (build-time and load-time code, binaries, assembly and C, and packages that can act on the world)"
		case m.Scope == ScopeDiff:
			key = "Third-party, version changed: the change reviewed"
		case m.Scope == ScopeTooLarge:
			key = "Third-party, new to the project, too large to review at its surface: pinned to its exact release, and reviewed as a diff when its version changes"
		case m.Scope == "unchanged":
			key = "Third-party, unchanged since the last certified release, when it was reviewed"
		default:
			key = "Third-party, with nothing at its surface to review"
		}
		groups[key] = append(groups[key], name)
	}
	fmt.Fprintln(w)
	for _, k := range slices.Sorted(maps.Keys(groups)) {
		fmt.Fprintf(w, "- %s: %s\n", k, strings.Join(groups[k], ", "))
	}
	var notes []string
	for _, m := range r.Modules {
		switch {
		case len(m.Foreign) > 0:
			notes = append(notes, fmt.Sprintf("- **`%s@%s` has files its repository does not:** %s (%s). They were shown to the reviewer.", m.Path, m.Version, strings.Join(m.Foreign, ", "), m.Provenance))
		case strings.HasPrefix(m.Provenance, "not checkable"):
			notes = append(notes, fmt.Sprintf("- `%s@%s`: %s.", m.Path, m.Version, m.Provenance))
		}
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Published packages checked against their source repositories:")
		fmt.Fprintln(w)
		for _, n := range notes {
			fmt.Fprintln(w, n)
		}
	}
}

// oneLine keeps model text from breaking the report's markdown.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
