// Package review has a model read the code compiled into a release and decides, by a
// fixed rule over what it reports, whether the release is certified. Nobody approves a
// verdict: the rule (Decide) runs on the published review.json, so anyone can rerun it.
package review

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/shadybin/shadybin/internal/manifest"
)

// Model reviews every unit. A change of model, like a change of prompt, gives new cache keys.
const Model = "claude-opus-5-5"

// PromptVersion names the system prompt and the input format; bump it with either.
const PromptVersion = "3"

// Verdicts.
const (
	Certified = "certified"
	Rejected  = "rejected"
)

// Unit kinds.
const (
	// KindProject is the code in the vendor's repository.
	KindProject = "project"
	// KindOwned is a module the vendor controls from outside its repository.
	KindOwned = "owned"
	// KindThirdParty is a module someone else publishes.
	KindThirdParty = "third-party"
)

// Result is what the model returns for one unit, in the shape of resultSchema.
type Result struct {
	Summary      string        `json:"summary"`
	Verdict      string        `json:"verdict"` // pass or fail
	Findings     []Finding     `json:"findings"`
	Capabilities []Explanation `json:"capabilities"`
	DataFlows    []DataFlow    `json:"data_flows"`
}

// Finding is something the reviewer noticed. Severity is info, concern or malicious.
type Finding struct {
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// Explanation accounts for one capability the manifest found in a package.
type Explanation struct {
	Package     string `json:"package"`
	Capability  string `json:"capability"`
	Explanation string `json:"explanation"`
	File        string `json:"file"`
}

// DataFlow is data leaving the process: what, and where to.
type DataFlow struct {
	What string `json:"what"`
	To   string `json:"to"`
	File string `json:"file"`
}

// Unit is one call to the model: a module's code, whole or as a diff, or a part of it.
type Unit struct {
	Kind   string `json:"kind"`
	Module string `json:"module"`
	// From is the version (or, for the project, the tag) the code was last reviewed at;
	// empty means the unit holds the code whole.
	From string `json:"from"`
	// To is the version reviewed; empty for the project and for a local replacement.
	To string `json:"to"`
	// Scope is how much of the code the unit holds: whole, diff or surface.
	Scope string `json:"scope"`
	// Part and Parts number the pieces a unit too large for one call is split into.
	Part  int `json:"part"`
	Parts int `json:"parts"`
	// Packages are the packages whose code the unit holds.
	Packages []string `json:"packages"`
	// Digest is the SHA-256 of the exact input, the dependency cache's key.
	Digest string `json:"digest"`
	// Cached means the result came from the registry's cache, not a new call.
	Cached bool `json:"cached"`
	// ServedBy is the model that answered, which a refusal fallback can change.
	ServedBy string  `json:"served_by"`
	Result   *Result `json:"result"`

	input string
}

// Cacheable reports whether the unit's result can be shared: a module at a version, which
// its checksum fixes for everyone who compiles it in.
func (u *Unit) Cacheable() bool { return u.Kind != KindProject && u.To != "" }

// Review is a release's review.json.
type Review struct {
	Model    string `json:"model"`
	Prompt   string `json:"prompt"`
	Previous string `json:"previous"`
	// Modules record how each module compiled in was treated.
	Modules []ModuleInfo `json:"modules"`
	Units   []Unit       `json:"units"`
	Verdict string       `json:"verdict"`
	// Reasons say why a release was rejected; empty when certified.
	Reasons []string `json:"reasons"`
}

// Marshal returns review.json's bytes.
func (r *Review) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Load reads a review.json.
func Load(path string) (*Review, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Review
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

// sensitive are the capabilities a first review must account for package by package:
// the ones that act on the world. A later review accounts for every capability a package
// gains.
func sensitive(c string) bool {
	switch c {
	case "EXEC", "NETWORK", "OPERATING_SYSTEM", "ARBITRARY_EXECUTION", "CGO":
		return true
	}
	return strings.HasPrefix(c, "MODIFY_SYSTEM_STATE")
}

// Pair is a package and a capability.
type Pair struct{ Package, Capability string }

// Required returns the capabilities the review must explain, in the given packages: what
// each gained since prev, or with no prev, its sensitive capabilities.
func Required(m, prev *manifest.Manifest, packages []string) []Pair {
	var out []Pair
	var added map[string][]string
	if prev != nil {
		added = manifest.Diff(prev, m).Added
	}
	for _, p := range slices.Sorted(slices.Values(packages)) {
		caps := added[p]
		if prev == nil {
			caps = slices.DeleteFunc(m.Notable(p), func(c string) bool { return !sensitive(c) })
		}
		for _, c := range caps {
			out = append(out, Pair{p, c})
		}
	}
	return out
}

// Decide is the rule that certifies or rejects a release, over the review's units and the
// manifests of the release and of the previous certified release (nil for the first). It
// is deterministic: intake reruns it before signing, and anyone can rerun it after.
func Decide(r *Review, m, prev *manifest.Manifest) (string, []string) {
	var reasons []string
	covered := map[string]bool{}
	for _, u := range r.Units {
		name := u.Module + partName(u)
		if u.Result == nil {
			reasons = append(reasons, name+": not reviewed")
			continue
		}
		for _, p := range u.Packages {
			covered[p] = true
		}
		if u.Result.Verdict != "pass" {
			reasons = append(reasons, fmt.Sprintf("%s: the reviewer failed it: %s", name, u.Result.Summary))
		}
		for _, f := range u.Result.Findings {
			if f.Severity == "malicious" {
				reasons = append(reasons, fmt.Sprintf("%s: %s (%s:%d)", name, f.Title, f.File, f.Line))
			}
		}
		explained := map[Pair]bool{}
		for _, e := range u.Result.Capabilities {
			if strings.TrimSpace(e.Explanation) != "" {
				explained[Pair{e.Package, e.Capability}] = true
			}
		}
		for _, need := range Required(m, prev, u.Packages) {
			if !explained[need] {
				reasons = append(reasons, fmt.Sprintf("%s: %s uses %s, and the review does not say why", name, need.Package, need.Capability))
			}
		}
	}
	// Every capability that must be explained sits in a package some unit reviewed.
	var all []string
	for p := range m.Capabilities {
		all = append(all, p)
	}
	for _, need := range Required(m, prev, all) {
		if !covered[need.Package] {
			reasons = append(reasons, fmt.Sprintf("%s uses %s, and no review covered the package", need.Package, need.Capability))
		}
	}
	slices.Sort(reasons)
	reasons = slices.Compact(reasons)
	if len(reasons) > 0 {
		return Rejected, reasons
	}
	return Certified, nil
}

func partName(u Unit) string {
	if u.Parts > 1 {
		return fmt.Sprintf(" (part %d of %d)", u.Part, u.Parts)
	}
	return ""
}
