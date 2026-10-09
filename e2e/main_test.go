package e2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

var acceptanceContext = context.Background()
var acceptanceCompleted bool

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	flag.Parse()
	cfg, err := readLiveConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cfg != nil && flag.Lookup("test.run").Value.String() != "^TestAcceptanceStorage$" {
		fmt.Fprintln(os.Stderr, "live tests require the complete TestAcceptanceStorage suite")
		return 1
	}
	if cfg != nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		acceptanceContext = ctx
	}

	cleanup := goBuildS5cmd()
	defer cleanup()
	code := m.Run()
	if cfg != nil && code == 0 && !acceptanceCompleted {
		fmt.Fprintln(os.Stderr, "live acceptance suite did not complete")
		return 1
	}
	return code
}
