// Package cli is the "nuqs" command line. main.go only calls Run.
//
// Everything the CLI needs from outside (Nmap, the list of checks) comes in
// through App, so tests can run the whole CLI without Nmap installed.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nuqs-org/nuqs/internal/api"
	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/output"
	"github.com/nuqs-org/nuqs/internal/store"
	"github.com/nuqs-org/nuqs/internal/target"
	"github.com/nuqs-org/nuqs/internal/tools"
	"github.com/nuqs-org/nuqs/internal/web"
)

// Exit codes returned by Run.
const (
	ExitOK    = 0 // everything worked (findings or not)
	ExitError = 1 // the scan couldn't run
	ExitUsage = 2 // the command was typed wrong

	// ExitFindings is for --fail-on: the scan found something at or above
	// that severity, so a CI job can fail on it.
	ExitFindings = 3
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
	// ListenAndServeTLS starts the HTTPS server for "nuqs serve". Nil defaults to net/http with TLS 1.2+.
	ListenAndServeTLS func(ctx context.Context, addr, certFile, keyFile string, h http.Handler) error
	// PBKDF2Iterations overrides the default password hashing cost (0 uses auth.DefaultPBKDF2Iterations).
	PBKDF2Iterations int
	// DataDir is where scans and accounts are saved. Empty means store.DefaultDir().
	DataDir string
	// LiveProgress shows scan progress as one line that updates in place.
	// Set it when Stderr is a terminal. Otherwise progress is a few plain
	// lines, which read fine in logs and CI.
	LiveProgress bool
}

const usage = `Nuqs is a non-overengineered vulnerability assessment tool.

Usage:
  nuqs scan [flags] <target>...        scan targets (IP, CIDR, range like 10.0.0.1-20, or hostname)
  nuqs history [-n 20]                 list saved scans, newest first
  nuqs show [--json] <id>              print a saved scan again
  nuqs show --finding <id> [scan-id]   timeline of one finding across scans
  nuqs diff [--json] <old> [new]       what changed between two saved scans
  nuqs serve [flags]                   start the web UI and JSON API server
  nuqs user reset-password <username>  issue a one-time password reset code
  nuqs checks                          list the built-in checks
  nuqs version                         print the version

Scans and accounts are saved in NUQS_DATA_DIR, or a "nuqs" folder in your config folder.
Run "nuqs scan -h", "nuqs serve -h" or "nuqs user -h" to see the flags.
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
	case "history":
		return a.history(args[1:])
	case "show":
		return a.show(args[1:])
	case "diff":
		return a.diff(args[1:])
	case "serve":
		return a.serve(ctx, args[1:])
	case "user":
		return a.user(args[1:])
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
	noSave := fs.Bool("no-save", false, "don't save this scan to the history")
	failOn := fs.String("fail-on", "", "exit with code 3 if there's a finding at or above this severity: critical, high, medium, low or info")
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
	var failAt model.Severity
	if *failOn != "" {
		var err error
		if failAt, err = model.ParseSeverity(*failOn); err != nil {
			fmt.Fprintln(a.Stderr, "--fail-on should be critical, high, medium, low or info")
			return ExitUsage
		}
	}
	if len(specs) == 0 {
		fmt.Fprintln(a.Stderr, "no targets given")
		fs.Usage()
		return ExitUsage
	}
	portSpec := strings.TrimSpace(*ports)
	if portSpec != "" {
		normalized, ok := tools.NormalizePorts(portSpec)
		if !ok {
			if strings.Contains(strings.ToUpper(portSpec), "U:") {
				fmt.Fprintln(a.Stderr, "UDP ports aren't supported yet, use TCP ports like 22,80,443 or 1-1000.")
			} else {
				fmt.Fprintln(a.Stderr, "Enter valid ports such as 22,80,443 or 1-1000.")
			}
			return ExitUsage
		}
		portSpec = normalized
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
	onEvent := a.progress
	var live *liveStatus
	started := time.Now()
	if a.LiveProgress {
		live = newLiveStatus(a.Stderr, time.Now)
		go live.tick(time.Second)
		onEvent = live.event
	}
	rep, err := svc.RunValidated(ctx, tools.ValidatedScan{
		Targets:  targets,
		Ports:    portSpec,
		SkipPing: *skipPing,
		Workers:  *workers,
		Timeout:  *timeout,
	}, onEvent)
	if live != nil {
		live.finish()
		if rep != nil {
			fmt.Fprintf(a.Stderr, "Scanned in %s.\n\n", time.Since(started).Round(100*time.Millisecond))
		}
	}
	if rep == nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "scan stopped early:", err)
	}

	if err := a.printReport(rep, *asJSON); err != nil {
		return ExitError
	}
	if !*noSave {
		a.saveScan(ctx, targets, rep, err, scanSettings{Target: strings.Join(specs, ", "), Ports: portSpec, SkipPing: *skipPing, Workers: *workers, Timeout: timeout.String()})
	}
	if ctx.Err() != nil {
		return ExitError
	}
	if *failOn != "" {
		if n := countAtLeast(rep, failAt); n > 0 {
			fmt.Fprintf(a.Stderr, "Failing because of --fail-on %s: %d finding(s) at %s or above.\n", failAt, n, failAt)
			return ExitFindings
		}
	}
	return ExitOK
}

// countAtLeast counts the findings at or above a severity.
func countAtLeast(rep *engine.Report, min model.Severity) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Severity >= min {
			n++
		}
	}
	return n
}

func (a *App) printReport(rep *engine.Report, asJSON bool) error {
	var err error
	if asJSON {
		err = output.JSON(a.Stdout, rep)
	} else {
		err = output.Text(a.Stdout, rep)
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "error writing report:", err)
	}
	return err
}

// scanSettings is what "nuqs scan" was run with, saved so the web UI can
// show it. The names match tools.ScanRequest.
type scanSettings struct {
	Target   string `json:"target"`
	Ports    string `json:"ports"`
	SkipPing bool   `json:"skip_ping"`
	Workers  int    `json:"workers"`
	Timeout  string `json:"timeout"`
}

// saveScan saves the scan to the history and says what changed since the
// last scan of the same targets. A scan that ran is worth more than its
// history entry, so if saving fails we only say so.
func (a *App) saveScan(ctx context.Context, targets []string, rep *engine.Report, scanErr error, settings scanSettings) {
	st, err := store.Open(a.dataDir())
	if err != nil {
		fmt.Fprintln(a.Stderr, "warning: couldn't save this scan:", err)
		return
	}
	defer func() { _ = st.Close() }()
	status, msg := store.Completed, ""
	if ctx.Err() != nil {
		status = store.Stopped
	}
	if scanErr != nil {
		msg = tools.FriendlyError(scanErr)
	}
	raw, _ := json.Marshal(settings) // plain strings and numbers, can't fail
	r := store.Run{Name: strings.Join(targets, ", "), Kind: "cli", Settings: string(raw), Targets: targets,
		Status: status, Error: msg, Started: rep.Started, Finished: rep.Finished, Report: rep}
	if len(r.Name) > 100 {
		r.Name = r.Name[:97] + "..."
	}
	if err := st.Save(&r); err != nil {
		fmt.Fprintln(a.Stderr, "warning: couldn't save this scan:", err)
		return
	}
	fmt.Fprintf(a.Stderr, "Saved as scan %d. See it again with: nuqs show %d\n", r.ID, r.ID)
	if r.Status == store.Completed && r.Error == "" {
		a.sinceLastScan(st, r.ID, rep)
	}
}

// sinceLastScan prints the one line summary of what changed since the last
// scan of the same targets and ports, if there is one.
func (a *App) sinceLastScan(st *store.Store, id int64, rep *engine.Report) {
	prev, err := st.Previous(id)
	if err != nil {
		return // no earlier scan to compare with, or it couldn't be read
	}
	d := diff.Compare(prev.Report, rep)
	fmt.Fprintf(a.Stderr, "Since scan %d (%s): %s. See what changed with: nuqs diff %d\n",
		prev.ID, prev.Started.Local().Format("2006-01-02 15:04"), d.Summary(), id)
}

func (a *App) dataDir() string {
	if a.DataDir != "" {
		return a.DataDir
	}
	return store.DefaultDir()
}

// history lists the saved scans, newest first.
func (a *App) history(args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	limit := fs.Int("n", 20, "how many scans to list, 0 for all")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 || *limit < 0 {
		fmt.Fprintln(a.Stderr, "Usage: nuqs history [-n 20]")
		return ExitUsage
	}
	st, err := store.Open(a.dataDir())
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	defer func() { _ = st.Close() }()
	runs, err := st.Runs(*limit)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	if len(runs) == 0 {
		fmt.Fprintln(a.Stdout, "No saved scans yet. Run one with: nuqs scan <target>")
		return ExitOK
	}
	tw := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTARTED\tSTATUS\tHOSTS\tCRIT\tHIGH\tMED\tLOW\tINFO\tNAME")
	for _, r := range runs {
		c := r.Findings
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", r.ID, r.Started.Local().Format("2006-01-02 15:04"), r.Status, r.Hosts,
			c[model.Critical], c[model.High], c[model.Medium], c[model.Low], c[model.Info], r.Name)
	}
	if err := tw.Flush(); err != nil {
		return ExitError
	}
	return ExitOK
}

// show prints a saved scan the same way "nuqs scan" did, or one finding's
// timeline across scans when --finding is given.
func (a *App) show(args []string) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	asJSON := fs.Bool("json", false, "print the report or timeline as JSON")
	finding := fs.String("finding", "", "show one finding's timeline across scans of the same targets and ports (finding ID or check ID)")
	fs.Usage = func() {
		fmt.Fprintln(a.Stderr, "Usage: nuqs show [--json] [--finding <id>] [scan-id]")
		fs.PrintDefaults()
	}

	// Accept flags before or after an optional scan ID, just like "nuqs scan".
	var positional []string
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
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if strings.TrimSpace(*finding) != "" {
		return a.showFinding(strings.TrimSpace(*finding), positional, *asJSON)
	}
	findingSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "finding" {
			findingSet = true
		}
	})
	if findingSet {
		fmt.Fprintln(a.Stderr, "Usage: nuqs show [--json] --finding <id> [scan-id]")
		return ExitUsage
	}
	if len(positional) != 1 {
		fmt.Fprintln(a.Stderr, "Usage: nuqs show [--json] <id>, the IDs are in nuqs history")
		return ExitUsage
	}
	id, err := strconv.ParseInt(positional[0], 10, 64)
	if err != nil {
		fmt.Fprintln(a.Stderr, "Usage: nuqs show [--json] <id>, the IDs are in nuqs history")
		return ExitUsage
	}
	st, err := store.Open(a.dataDir())
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	defer func() { _ = st.Close() }()
	r, err := st.Run(id)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	if r.Report == nil {
		fmt.Fprintf(a.Stderr, "Scan %d %s without a report: %s\n", id, r.Status, r.Error)
		return ExitError
	}
	if r.Error != "" && !*asJSON {
		fmt.Fprintf(a.Stderr, "Note: %s\n", r.Error)
	}
	if err := a.printReport(r.Report, *asJSON); err != nil {
		return ExitError
	}
	return ExitOK
}

func (a *App) showFinding(query string, positional []string, asJSON bool) int {
	var scanID int64
	hasScanID := len(positional) == 1
	if len(positional) > 1 {
		fmt.Fprintln(a.Stderr, "Usage: nuqs show [--json] --finding <id> [scan-id]")
		return ExitUsage
	}
	if hasScanID {
		var err error
		scanID, err = strconv.ParseInt(positional[0], 10, 64)
		if err != nil {
			fmt.Fprintln(a.Stderr, "Usage: nuqs show [--json] --finding <id> [scan-id]")
			return ExitUsage
		}
	}

	st, err := store.Open(a.dataDir())
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	defer func() { _ = st.Close() }()

	var runs []store.Run
	var findingID string
	if hasScanID {
		runs, err = st.SameScopeRuns(scanID)
		if err != nil {
			fmt.Fprintln(a.Stderr, "error:", err)
			return ExitError
		}
		var matches []string
		findingID, matches = resolveFindingInRuns(query, runs)
		if findingID == "" {
			a.reportFindingLookupError(query, matches)
			return ExitError
		}
	} else {
		found, err := st.FindFindingRuns(query)
		if err != nil {
			fmt.Fprintln(a.Stderr, "error:", err)
			return ExitError
		}
		var anchorID int64
		var matches []string
		for _, m := range found {
			if m.FindingID == query {
				findingID, anchorID = m.FindingID, m.LatestRunID
				break
			}
			matches = append(matches, m.FindingID)
		}
		if findingID == "" && len(found) == 1 {
			findingID, anchorID = found[0].FindingID, found[0].LatestRunID
		}
		if findingID == "" {
			a.reportFindingLookupError(query, matches)
			return ExitError
		}
		runs, err = st.SameScopeRuns(anchorID)
		if err != nil {
			fmt.Fprintln(a.Stderr, "error:", err)
			return ExitError
		}
	}

	reports := make([]diff.ScanReport, 0, len(runs))
	for _, r := range runs {
		reports = append(reports, diff.ScanReport{
			ID:      r.ID,
			Name:    r.Name,
			Started: r.Started,
			Targets: r.Targets,
			Report:  r.Report,
		})
	}
	tl, ok := diff.BuildTimeline(findingID, reports)
	if !ok {
		fmt.Fprintf(a.Stderr, "error: no saved finding matching %q\n", query)
		return ExitError
	}
	if asJSON {
		err = output.TimelineJSON(a.Stdout, tl)
	} else {
		err = output.TimelineText(a.Stdout, tl)
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "error writing timeline:", err)
		return ExitError
	}
	return ExitOK
}

func resolveFindingInRuns(query string, runs []store.Run) (string, []string) {
	seen := map[string]bool{}
	var matches []string
	for _, r := range runs {
		if r.Report == nil {
			continue
		}
		for _, f := range r.Report.Findings {
			if f.ID == query {
				return f.ID, nil
			}
			if f.CheckID == query && !seen[f.ID] {
				seen[f.ID] = true
				matches = append(matches, f.ID)
			}
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", matches
}

func (a *App) reportFindingLookupError(query string, matches []string) {
	if len(matches) == 0 {
		fmt.Fprintf(a.Stderr, "error: no saved finding matching %q\n", query)
		return
	}
	fmt.Fprintf(a.Stderr, "error: more than one finding matches %q, pass the full finding ID:\n", query)
	for _, id := range matches {
		fmt.Fprintf(a.Stderr, "  nuqs show --finding '%s'\n", id)
	}
}

// diff prints what changed between two saved scans. With one ID it compares
// that scan with the last finished scan of the same targets and ports.
func (a *App) diff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	asJSON := fs.Bool("json", false, "print the comparison as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	ids := make([]int64, fs.NArg())
	bad := fs.NArg() < 1 || fs.NArg() > 2
	for i, arg := range fs.Args() {
		var err error
		ids[i], err = strconv.ParseInt(arg, 10, 64)
		bad = bad || err != nil || ids[i] < 1
	}
	if bad {
		fmt.Fprintln(a.Stderr, "Usage: nuqs diff [--json] <old> [new], the IDs are in nuqs history")
		return ExitUsage
	}
	st, err := store.Open(a.dataDir())
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	defer func() { _ = st.Close() }()

	cur, old := ids[len(ids)-1], int64(0)
	if len(ids) == 2 {
		old = ids[0]
	}
	d, err := tools.Compare(st, old, cur)
	if errors.Is(err, tools.ErrNotOlder) {
		fmt.Fprintf(a.Stderr, "The first ID should be the older scan, like: nuqs diff %d %d\n", cur, old)
		return ExitUsage
	}
	if errors.Is(err, tools.ErrNoEarlierScan) {
		fmt.Fprintf(a.Stderr, "Scan %d has no earlier finished scan of the same targets and ports. Pick one with: nuqs diff <old> %d\n", cur, cur)
		return ExitError
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
	for _, note := range d.Notes {
		fmt.Fprintf(a.Stderr, "Note: %s.\n", note)
	}
	if *asJSON {
		err = output.DiffJSON(a.Stdout, d)
	} else {
		err = output.DiffText(a.Stdout, d)
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "error writing comparison:", err)
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
	addr := fs.String("addr", defaultAddr, "address to listen on (non-loopback requires HTTPS)")
	nmapPath := fs.String("nmap", os.Getenv("NUQS_NMAP_PATH"), "path to the nmap binary (default: NUQS_NMAP_PATH or nmap from PATH)")
	allowRaw := fs.String("allow", os.Getenv("NUQS_ALLOWED_TARGETS"), "comma-separated allowed IPs or CIDRs (default: 127.0.0.0/8 loopback only)")
	tlsCert := fs.String("tls-cert", os.Getenv("NUQS_TLS_CERT"), "path to PEM TLS certificate for HTTPS")
	tlsKey := fs.String("tls-key", os.Getenv("NUQS_TLS_KEY"), "path to PEM TLS private key for HTTPS")
	tlsSelfSigned := fs.Bool("tls-self-signed", false, "generate and reuse a local self-signed HTTPS certificate in the data folder")
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

	certPath := strings.TrimSpace(*tlsCert)
	keyPath := strings.TrimSpace(*tlsKey)
	if (certPath == "") != (keyPath == "") {
		fmt.Fprintln(a.Stderr, "error: --tls-cert and --tls-key must both be provided")
		return ExitUsage
	}
	if *tlsSelfSigned && certPath != "" {
		fmt.Fprintln(a.Stderr, "error: use either --tls-self-signed or --tls-cert/--tls-key, not both")
		return ExitUsage
	}
	useTLS := *tlsSelfSigned || certPath != ""

	isLoopback, err := CheckServeAddr(*addr)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitUsage
	}
	if !isLoopback && !useTLS {
		fmt.Fprintf(a.Stderr, "error: --addr %q listens on the network, which requires HTTPS. Pass --tls-self-signed or --tls-cert and --tls-key.\n", *addr)
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

	dataDir := a.dataDir()
	st, err := store.Open(dataDir)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitError
	}
	defer func() { _ = st.Close() }()
	if *tlsSelfSigned {
		certPath, keyPath, err = EnsureSelfSignedCert(dataDir, *addr)
		if err != nil {
			fmt.Fprintf(a.Stderr, "error: %v\n", err)
			return ExitError
		}
	}

	authSvc := auth.NewService(st)
	authSvc.HTTPS = useTLS
	if a.PBKDF2Iterations > 0 {
		authSvc.Iterations = a.PBKDF2Iterations
	}
	setupCode, needsSetup, err := authSvc.EnsureSetupCode()
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
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
	scans := &tools.Scans{Service: svc, Store: st}
	if err := scans.Load(); err != nil {
		fmt.Fprintln(a.Stderr, "error: loading saved scans:", err)
		return ExitError
	}
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
	webHandler.Auth = authSvc
	webHandler.HTTPS = useTLS

	apiHandler := api.New(svc, *addr)
	apiHandler.Scans = scans
	apiHandler.Auth = authSvc
	apiHandler.HTTPS = useTLS

	mux := http.NewServeMux()
	apiHandler.Register(mux)
	webHandler.Register(mux)

	handler := authSvc.Gate(mux)
	if isLoopback {
		handler = api.LocalOnly(*addr, handler)
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	localURL := LocalAccessURL(*addr, scheme)
	fmt.Fprintf(a.Stdout, "Nuqs web UI at %s (listening on %s)\n", localURL, *addr)
	if lanURL := NetworkHintURL(*addr, scheme); lanURL != "" {
		fmt.Fprintf(a.Stdout, "Team LAN URL:  %s\n", lanURL)
	}
	if needsSetup {
		fmt.Fprintf(a.Stdout, "\nFirst-time setup required (no accounts exist yet).\nOpen %s/setup and enter this one-time setup code:\n  %s\n\n", localURL, setupCode)
	}

	if useTLS {
		listenTLS := a.ListenAndServeTLS
		if listenTLS == nil {
			listenTLS = defaultListenAndServeTLS
		}
		if err := listenTLS(ctx, *addr, certPath, keyPath, handler); err != nil {
			fmt.Fprintf(a.Stderr, "error: server terminated: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	listen := a.ListenAndServe
	if listen == nil {
		listen = defaultListenAndServe
	}
	if err := listen(ctx, *addr, handler); err != nil {
		fmt.Fprintf(a.Stderr, "error: server terminated: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// checkLoopback makes sure an address only listens on this computer.
func checkLoopback(addr string) error {
	loopback, err := CheckServeAddr(addr)
	if err != nil {
		return err
	}
	if !loopback {
		return fmt.Errorf("--addr %q: plain HTTP only listens on this computer (127.0.0.1 or localhost); pass HTTPS flags to listen on the network", addr)
	}
	return nil
}

func defaultListenAndServe(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return runHTTPServer(ctx, srv, func() error { return srv.ListenAndServe() })
}

func defaultListenAndServeTLS(ctx context.Context, addr, certFile, keyFile string, h http.Handler) error {
	tlsCfg, err := BuildTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return runHTTPServer(ctx, srv, func() error { return srv.ListenAndServeTLS("", "") })
}

func runHTTPServer(ctx context.Context, srv *http.Server, start func() error) error {
	errCh := make(chan error, 1)
	go func() {
		if err := start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	case engine.HostFound:
		fmt.Fprintf(a.Stderr, "Found %s with %d open %s.\n", ev.Discovered.Address, len(ev.Discovered.Services), plural(len(ev.Discovered.Services), "service", "services"))
	case engine.DiscoveryDone:
		fmt.Fprintf(a.Stderr, "Found %d %s.\n", ev.Count, plural(ev.Count, "host", "hosts"))
	case engine.ChecksStarted:
		if ev.Count > 0 {
			fmt.Fprintf(a.Stderr, "Running %d %s...\n", ev.Count, plural(ev.Count, "check", "checks"))
		}
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
