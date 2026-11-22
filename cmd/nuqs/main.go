// Command nuqs is the Nuqs vulnerability assessment tool.
//
// All the real work lives in internal/cli. This file only wires up the real
// Nmap runner, the built-in checks and Ctrl-C handling.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nuqs-org/nuqs/checks"
	"github.com/nuqs-org/nuqs/internal/cli"
	"github.com/nuqs-org/nuqs/internal/nmap"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := &cli.App{
		Version:      version,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		NewRunner:    func(path string) nmap.Runner { return nmap.ExecRunner{Path: path} },
		Checks:       checks.All,
		LiveProgress: isTerminal(os.Stderr) && os.Getenv("TERM") != "dumb",
	}
	code := app.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// isTerminal reports whether f is a terminal, not a file or a pipe.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
