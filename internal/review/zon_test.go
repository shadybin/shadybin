package review

import "testing"

func TestParseZon(t *testing.T) {
	v, err := parseZon(`.{
    .name = .marlin,
    .version = "0.1.5",
    // a comment
    .fingerprint = 0x3f342538c61cb51b, // trailing
    .dependencies = .{
        .vaxis = .{
            .url = "git+https://github.com/rockorager/libvaxis#c060d31",
            .hash = "vaxis-0.6.0-BWNV",
            .lazy = true,
        },
        .@"odd name" = .{ .path = "../x" },
    },
    .paths = .{ "build.zig", "src", "" },
    .empty = .{},
}`)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	deps := m["dependencies"].(map[string]any)
	vaxis := deps["vaxis"].(map[string]any)
	if m["name"] != ".marlin" || m["version"] != "0.1.5" || vaxis["hash"] != "vaxis-0.6.0-BWNV" || vaxis["lazy"] != "true" ||
		deps["odd name"].(map[string]any)["path"] != "../x" {
		t.Fatalf("parsed %#v", m)
	}
	if p := zonPaths(m); len(p) != 3 || p[2] != "." {
		t.Fatalf("paths %v", p)
	}
	for _, bad := range []string{`.{ .a = "x" `, `.{ .a = "unterminated }`, `.{ .a = 1 } extra`} {
		if _, err := parseZon(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

func TestZigOrigin(t *testing.T) {
	for raw, want := range map[string][2]string{
		"git+https://github.com/rockorager/libvaxis#c060d31":                     {"github.com/rockorager/libvaxis", "from its repository"},
		"https://github.com/zig-utils/zig-regex/archive/refs/tags/v0.2.0.tar.gz": {"github.com/zig-utils/zig-regex", "from its repository (an archive GitHub makes from it)"},
		"https://example.com/releases/lib-1.0.tar.gz":                            {"example.com/releases/lib-1.0.tar.gz", "not checkable: an archive from example.com, not a repository"},
	} {
		if name, prov := zigOrigin(raw); name != want[0] || prov != want[1] {
			t.Errorf("%s: %s, %s", raw, name, prov)
		}
	}
}
