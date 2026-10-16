// Command shadybin rebuilds releases from their tagged source, certifies the ones that come
// out byte for byte the same, and checks files against what it certified.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/shadybin/shadybin/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
