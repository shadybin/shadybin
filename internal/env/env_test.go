package env

import (
	"slices"
	"strings"
	"testing"
)

// TestClean: a build runs the vendor's code, so it gets no credentials.
func TestClean(t *testing.T) {
	env, dropped := Clean([]string{
		"PATH=/usr/bin", "HOME=/home/runner", "GOFLAGS=-mod=readonly", "RUNNER_TEMP=/tmp", "GITHUB_REF=refs/tags/v1",
		"ANTHROPIC_API_KEY=sk-ant", "GITHUB_TOKEN=ghs", "GH_TOKEN=gho", "SHADYBIN_SIGNING_KEY=seed",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=jwt", "ACTIONS_RUNTIME_TOKEN=rt", "AWS_SECRET_ACCESS_KEY=x",
		"NPM_TOKEN=n", "MY_SERVICE_PASSWORD=p", "SSH_AUTH_SOCK=/tmp/agent", "OP_SESSION_my=s",
	})
	want := []string{"PATH=/usr/bin", "HOME=/home/runner", "GOFLAGS=-mod=readonly", "RUNNER_TEMP=/tmp", "GITHUB_REF=refs/tags/v1"}
	if !slices.Equal(env, want) {
		t.Errorf("env = %v, want %v", env, want)
	}
	if len(dropped) != 11 || slices.ContainsFunc(dropped, func(n string) bool { return strings.Contains(n, "=") }) {
		t.Errorf("dropped should be the 11 names, without values: %v", dropped)
	}
}
