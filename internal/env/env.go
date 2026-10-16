// Package env keeps credentials away from the programs shadybin runs on a vendor's code.
package env

import (
	"slices"
	"strings"
)

// Clean is the environment for a program that may run the vendor's code or read its
// configuration (a build, zig fetch, cargo, go list): the caller's, less anything that looks
// like a credential. The certify workflow gives such steps no secrets; this covers anyone
// else running them, and secrets added later. It returns the names it dropped.
func Clean(environ []string) (env, dropped []string) {
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
