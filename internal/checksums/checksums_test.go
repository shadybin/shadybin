package checksums

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("CD", 32)
	got, err := Parse([]byte(a + "  terma_Linux_x86_64.tar.gz\n\n" + b + " *terma_Windows_x86_64.zip\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["terma_Linux_x86_64.tar.gz"].String() != "sha256:"+a ||
		got["terma_Windows_x86_64.zip"].String() != "sha256:"+strings.ToLower(b) {
		t.Fatalf("got %v", got)
	}
	for name, bad := range map[string]string{
		"no name":   a + "\n",
		"short":     "abcd  x\n",
		"duplicate": a + "  x\n" + a + "  x\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
