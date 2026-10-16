package manifest

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestMerge(t *testing.T) {
	out := []byte(`{"capabilityInfo": [
		{"packageDir": "example.com/tool/net", "capability": "CAPABILITY_NETWORK", "capabilityType": "CAPABILITY_TYPE_DIRECT"},
		{"packageDir": "example.com/tool/net", "capability": "CAPABILITY_EXEC", "capabilityType": "CAPABILITY_TYPE_TRANSITIVE"},
		{"packageDir": "example.com/tool/net", "capability": "CAPABILITY_NETWORK", "capabilityType": "CAPABILITY_TYPE_DIRECT"}
	]}`)
	caps := map[string]map[string]bool{}
	if err := merge(out, caps); err != nil {
		t.Fatal(err)
	}
	if len(caps) != 1 || len(caps["example.com/tool/net"]) != 1 || !caps["example.com/tool/net"]["NETWORK"] {
		t.Fatalf("want only the direct NETWORK, got %v", caps)
	}
}

func TestDiff(t *testing.T) {
	prev := &Manifest{
		Module:   "example.com/tool",
		Packages: []string{"example.com/tool", "example.com/tool/gone", "github.com/dep/a"},
		Modules:  map[string]string{"github.com/dep/a": "v1.0.0", "github.com/dep/gone": "v0.1.0"},
		Capabilities: map[string][]string{
			"example.com/tool":      {"FILES", "REFLECT"},
			"example.com/tool/gone": {"NETWORK"},
		},
	}
	m := &Manifest{
		Module:   "example.com/tool",
		Packages: []string{"example.com/tool", "github.com/dep/a", "github.com/dep/b"},
		Modules:  map[string]string{"github.com/dep/a": "v1.1.0", "github.com/dep/b": "v2.0.0"},
		Capabilities: map[string][]string{
			// RUNTIME is quiet: gaining it is no change.
			"example.com/tool": {"EXEC", "FILES", "REFLECT", "RUNTIME"},
			"github.com/dep/b": {"NETWORK"},
		},
	}
	c := Diff(prev, m)
	if !slices.Equal(c.Added["example.com/tool"], []string{"EXEC"}) || !slices.Equal(c.Added["github.com/dep/b"], []string{"NETWORK"}) || len(c.Added) != 2 {
		t.Errorf("added: %v", c.Added)
	}
	if !slices.Equal(c.Removed["example.com/tool/gone"], []string{"NETWORK"}) || len(c.Removed) != 1 {
		t.Errorf("removed: %v", c.Removed)
	}
	if !slices.Equal(c.NewPackages, []string{"github.com/dep/b"}) || !slices.Equal(c.GonePackages, []string{"example.com/tool/gone"}) {
		t.Errorf("packages: new %v, gone %v", c.NewPackages, c.GonePackages)
	}
	want := map[string][2]string{
		"github.com/dep/a":    {"v1.0.0", "v1.1.0"},
		"github.com/dep/b":    {"", "v2.0.0"},
		"github.com/dep/gone": {"v0.1.0", ""},
	}
	if len(c.Modules) != len(want) {
		t.Errorf("modules: %v", c.Modules)
	}
	for k, v := range want {
		if c.Modules[k] != v {
			t.Errorf("module %s: %v, want %v", k, c.Modules[k], v)
		}
	}
	if Diff(m, m).Empty() != true {
		t.Error("a manifest differs from itself")
	}

	var b bytes.Buffer
	m.GOOS, m.Tool = []string{"linux"}, Capslock
	m.Markdown(&b, prev, "v1.0.0")
	for _, s := range []string{
		"### Changes since v1.0.0",
		"- `.` now uses EXEC",
		"- `github.com/dep/b` now uses NETWORK",
		"- `./gone` no longer uses NETWORK",
		"- Dependency `github.com/dep/a` v1.0.0 → v1.1.0",
		"- New dependency `github.com/dep/b@v2.0.0`",
		"- Dependency `github.com/dep/gone` removed (was v0.1.0)",
	} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("report lacks %q:\n%s", s, b.String())
		}
	}
	if strings.Contains(b.String(), "| RUNTIME |") {
		t.Errorf("report lists a quiet capability:\n%s", b.String())
	}
}

func TestMarshalIsStable(t *testing.T) {
	m := &Manifest{Capabilities: map[string][]string{"b": {"X"}, "a": {"Y"}, "c": {"Z"}}}
	first, _ := m.Marshal()
	for range 20 {
		if again, _ := m.Marshal(); !bytes.Equal(first, again) {
			t.Fatal("manifest bytes vary between runs")
		}
	}
}
