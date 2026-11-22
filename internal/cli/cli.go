// Package cli is the "nuqs" command line. main.go only calls Run.
//
// Everything the CLI needs from outside (Nmap, the list of checks) comes in
// through App, so tests can run the whole CLI without Nmap installed.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/nuqs-org/nuqs/internal/api"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/output"
	"github.com/nuqs-org/nuqs/internal/target"
	"github.com/nuqs-org/nuqs/internal/tools"
	"github.com/nuqs-org/nuqs/internal/web"
)

// Exit codes returned by Run.
const (
	ExitOK    = 0 // everything worked (findings or not)
	ExitError = 1 // the scan couldn't run
	ExitUsage = 2 // the command was typed wrong
)

// App holds what the CLI depends on.
type App struct {
	Version string
	Stdout  io.Writer
	Stderr  io.Writer
	// NewRunner returns the Nmap runner to use. The path comes from --nmap.
	NewRunner func(path string) nmap.Runner
	// Checks returns the checks to run.
	Checks func() []check.Check
	// LookPath resolves the nmap binary for "nuqs serve". Nil defaults to exec.LookPath.
	LookPath func(file string) (string, error)
	// ListenAndServe starts the HTTP server for "nuqs serve". Nil defaults to net/http.
	ListenAndServe func(ctx context.Context, addr string, h http.Handler) error
}

const usage = `Nuqs is a non-overengineered vulnerability assessment tool.

Usage:
  nuqs scan [flags] <target>...   scan targets (IP, CIDR, range like 10.0.0.1-20, or hostname)
  nuqs serve [flags]              start the local web UI and JSON API server
  nuqs checks                     list the built-in checks
  nuqs version                    print the version

Run "nuqs scan -h" or "nuqs serve -h" to see the flags.
`

// Run runs the command in args (without the program name) and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "scan":
		return a.scan(ctx, args[1:])
	case "serve":
		return a.serve(ctx, args[1:])
	case "checks":
		return a.listChecks()
	case "version", "--version", "-v":
		fmt.Fprintf(a.Stdout, "nuqs %s\n", a.Version)
		return ExitOK
	case "help", "--help", "-h":
		fmt.Fprint(a.Stdout, usage)
		return ExitOK
	default:
		fmt.Fprintf(a.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return ExitUsage
	}
}

func (a *App) listChecks() int {
	svc := &tools.Service{Checks: a.Checks}
	for _, in := range svc.ListChecks() {
		fmt.Fprintf(a.Stdout, "%-24s %-8s %s\n", in.ID, in.Severity, in.Title)
	}
	return ExitOK
}

func (a *App) scan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	ports := fs.String("p", "", `ports to scan, like "22,80,443" or "1-1000" (default: Nmap's top 1000)`)
	skipPing := fs.Bool("Pn", false, "scan hosts even if they don't answer ping")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	workers := fs.Int("workers", engine.DefaultWorkers, "how many checks run at the same time")
	timeout := fs.Duration("timeout", engine.DefaultCheckTimeout, "max time for one check")
	force := fs.Bool("force", false, fmt.Sprintf("allow scanning more than %d addresses", target.DefaultLimit))
	nmapPath := fs.String("nmap", "", "path to the nmap binary (default: nmap from PATH)")
	fs.Usage = func() {
		fmt.Fprintln(a.Stderr, "Usage: nuqs scan [flags] <target>...")
		fs.PrintDefaults()
	}

	// Let people put flags before or after targets: "nuqs scan 10.0.0.1 -p 22".
	var specs []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return ExitOK
			}
			return ExitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		specs = append(specs, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	if *workers < 1 || *timeout <= 0 {
		fmt.Fprintln(a.Stderr, "--workers must be at least 1 and --timeout must be positive")
		return ExitUsage
	}
	if len(specs) == 0 {
		fmt.Fprintln(a.Stderr, "no targets given")
		fs.Usage()
		return ExitUsage
	}
	limit := int64(target.DefaultLimit)
	if *force {
		limit = 0
	}
	targets, _, err := target.Parse(specs, limit)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitUsage
	}

	svc := &tools.Service{
		Version:   a.Version,
		NewRunner: func() nmap.Runner { return a.NewRunner(*nmapPath) },
		Checks:    a.Checks,
	}
	rep, err := svc.RunValidated(ctx, tools.ValidatedScan{
		Targets:  targets,
		Ports:    *ports,
		SkipPing: *skipPing,
		Workers:  *workers,
		Timeout:  *timeout,
	}, a.progress)
	if rep == nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "scan stopped early:", err)
	}

	if *asJSON {
		err = output.JSON(a.Stdout, rep)
	} else {
		err = output.Text(a.Stdout, rep)
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "error writing report:", err)
		return ExitError
	}
	if ctx.Err() != nil {
		return ExitError
	}
	return ExitOK
}

func (a *App) serve(ctx context.Context, args []string) int {
	defaultAddr := "127.0.0.1:9002"
	if envPort := os.Getenv("PORT"); envPort != "" {
		defaultAddr = "127.0.0.1:" + envPort
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	addr := fs.String("addr", defaultAddr, "local address to listen on")
	nmapPath := fs.String("nmap", os.Getenv("NUQS_NMAP_PATH"), "path to the nmap binary (default: NUQS_NMAP_PATH or nmap from PATH)")
	allowRaw := fs.String("allow", os.Getenv("NUQS_ALLOWED_TARGETS"), "comma-separated allowed IPs or CIDRs (default: 127.0.0.0/8 loopback only)")
	fs.Usage = func() {
		fmt.Fprintln(a.Stderr, "Usage: nuqs serve [flags]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(a.Stderr, "unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return ExitUsage
	}

	if err := checkLoopback(*addr); err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitUsage
	}
	allowed, err := tools.ParseAllowedScope(*allowRaw)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitUsage
	}

	bin := *nmapPath
	if bin == "" {
		bin = "nmap"
	}
	lookPath := a.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	resolvedNmap, err := lookPath(bin)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: Nmap isn't installed or wasn't found (%v). %s, or pass --nmap /path/to/nmap.\n", err, tools.NmapInstallHint())
		return ExitError
	}

	svc := &tools.Service{
		Version:      a.Version,
		RunnerName:   "nmap",
		NewRunner:    func() nmap.Runner { return a.NewRunner(resolvedNmap) },
		Checks:       a.Checks,
		AllowedScope: allowed,
		EnforceScope: true,
		MaxWorkers:   128,
		StartedAt:    time.Now(),
	}
	scans := &tools.Scans{Service: svc}
	// On Ctrl+C stop running scans first. Their live pages then get a last
	// update and close, so the server can shut down right away.
	stop := context.AfterFunc(ctx, scans.StopAll)
	defer stop()
	defer scans.StopAll()
	webHandler, err := web.New(svc, scans, *addr)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitError
	}
	apiHandler := api.New(svc, *addr)
	apiHandler.Scans = scans

	mux := http.NewServeMux()
	apiHandler.Register(mux)
	webHandler.Register(mux)

	fmt.Fprintf(a.Stdout, "Nuqs web UI at http://%s\n", *addr)
	listen := a.ListenAndServe
	if listen == nil {
		listen = defaultListenAndServe
	}
	if err := listen(ctx, *addr, api.LocalOnly(*addr, mux)); err != nil {
		fmt.Fprintf(a.Stderr, "error: server terminated: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// checkLoopback makes sure the web UI only listens on this computer. There's
// no login yet, so anyone who could reach it could run scans.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		_, err = strconv.ParseUint(port, 10, 16)
	}
	if err != nil {
		return fmt.Errorf("--addr %q should look like 127.0.0.1:9002", addr)
	}
	if ip, perr := netip.ParseAddr(host); host != "localhost" && (perr != nil || !ip.IsLoopback()) {
		return fmt.Errorf("--addr %q: the web UI only listens on this computer for now (127.0.0.1 or localhost), because it has no login yet", addr)
	}
	return nil
}

func defaultListenAndServe(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	}
}

// progress prints short status lines to stderr, so stdout stays clean for the report.
func (a *App) progress(ev engine.Event) {
	switch ev.Kind {
	case engine.DiscoveryStarted:
		fmt.Fprintln(a.Stderr, "Finding hosts and open ports with Nmap...")
	case engine.DiscoveryDone:
		fmt.Fprintf(a.Stderr, "Found %d %s.\n", ev.Count, plural(ev.Count, "host", "hosts"))
	case engine.ChecksStarted:
		fmt.Fprintf(a.Stderr, "Running %d %s...\n", ev.Count, plural(ev.Count, "check", "checks"))
	case engine.ScanDone:
		fmt.Fprintf(a.Stderr, "Done at %s.\n\n", time.Now().Format("15:04:05"))
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
