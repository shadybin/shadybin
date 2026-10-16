// Package cli is the shadybin command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

var commands = []command{
	{"keygen", "make a signing key", runKeygen},
	{"rebuild", "rebuild a release from its tag", runRebuild},
	{"compare", "compare rebuilt files with the published checksums", runCompare},
	{"manifest", "record what the code can do", runManifest},
	{"capabilities", "write the report's capabilities section from a manifest", runCapabilities},
	{"review", "have the model review the code compiled in, and decide the verdict", runReview},
	{"statement", "write the statement for rebuilt files that match", runStatement},
	{"sign", "sign a release's statement", runSign},
	{"badge", "point a project's badge at its latest release", runBadge},
	{"verify", "check files against the registry", runVerify},
}

// errUsage means the arguments were wrong; the flag package has already said how.
var errUsage = errors.New("usage")

// errFailed means the command reported its failure itself; exit non-zero, say no more.
var errFailed = errors.New("failed")

// Run runs the command line and returns the exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		return 2
	}
	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		err := c.run(ctx, args[1:], stdout, stderr)
		switch {
		case err == nil:
			return 0
		case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
			return 2
		case errors.Is(err, errFailed):
			return 1
		}
		fmt.Fprintf(stderr, "shadybin %s: %v\n", c.name, err)
		return 1
	}
	fmt.Fprintf(stderr, "shadybin: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "shadybin certifies that a release was built from its tagged source.")
	fmt.Fprintln(w, "\nUsage: shadybin <command> [flags]")
	fmt.Fprintln(w, "\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-13s %s\n", c.name, c.summary)
	}
}

// flags makes a command's flag set; args describes its positional arguments for usage.
func flags(name, args string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("shadybin "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: shadybin %s [flags] %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses args and checks the required flags were set.
func parse(fs *flag.FlagSet, args []string, required ...string) error {
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	for _, name := range required {
		if fs.Lookup(name).Value.String() == "" {
			fmt.Fprintf(fs.Output(), "-%s is required\n", name)
			fs.Usage()
			return errUsage
		}
	}
	return nil
}

// repoFlag lowercases a repository given on the command line; the registry and statements
// hold it lowercase.
func repoFlag(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
