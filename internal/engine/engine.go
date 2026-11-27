// Package engine runs a scan from start to end.
//
// The flow is simple:
//
//  1. ask the HostScanner (Nmap) which hosts and services are up
//  2. for every service, pick the checks that apply to it
//  3. run those checks in parallel, each with its own timeout
//  4. collect findings and errors into a Report
//
// One bad check can never break the scan. Errors, timeouts and even panics
// are caught and reported, and the other checks keep going.
package engine

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// Defaults used when the Engine fields are left at zero.
const (
	DefaultWorkers      = 10
	DefaultCheckTimeout = 30 * time.Second
)

// HostScanner finds live hosts and their services. In real scans this is
// nmap.Scanner, in tests it's a fake.
type HostScanner interface {
	Scan(ctx context.Context, targets []string) ([]model.Host, error)
}

// ProgressScanner is a HostScanner that can also say how far along it is.
// Nmap reports its own steps, like "Service scan, 40% done, about 12s left".
// When the Scanner has this, the engine passes those updates on as
// ScanProgress events.
type ProgressScanner interface {
	HostScanner
	ScanWithProgress(ctx context.Context, targets []string, progress func(ScannerProgress)) ([]model.Host, error)
}

// StreamingScanner discovers hosts incrementally while Nmap is running.
type StreamingScanner interface {
	HostScanner
	StreamScan(ctx context.Context, targets []string, host func(model.Host), progress func(ScannerProgress)) error
}

// ScannerProgress is one progress update from the HostScanner.
type ScannerProgress struct {
	Task      string        // what it's doing, like "Connect Scan" or "Service scan"
	Percent   float64       // how much of that task is done, 0 to 100
	Remaining time.Duration // its own guess for the rest of the task, 0 if none
}

// EventKind says what happened during a scan.
type EventKind string

// Event kinds, in the order they happen.
const (
	DiscoveryStarted EventKind = "discovery_started"
	ScanProgress     EventKind = "scan_progress"  // Progress = where Nmap is, comes many times
	DiscoveryDone    EventKind = "discovery_done" // Count = hosts found
	HostFound        EventKind = "host_found"     // Discovered is the newly discovered host
	ChecksStarted    EventKind = "checks_started" // Count = total checks scheduled so far
	CheckDone        EventKind = "check_done"     // one check finished on one service
	ScanDone         EventKind = "scan_done"
)

// Event is sent to OnEvent so the CLI and the web UI can show progress.
type Event struct {
	Kind       EventKind
	Host       string
	Discovered model.Host
	Port       int
	CheckID    string
	Count      int
	Err        error           // set on CheckDone when the check failed
	Progress   ScannerProgress // set on ScanProgress
}

// CheckError records a check that couldn't finish. It is not a finding.
type CheckError struct {
	CheckID string `json:"check_id"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Error   string `json:"error"`
}

// Report is everything a scan produced.
type Report struct {
	Targets  []string        `json:"targets"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished"`
	Hosts    []model.Host    `json:"hosts"`
	Findings []model.Finding `json:"findings"`
	Errors   []CheckError    `json:"errors"`
}

// Engine holds the scan setup. The zero value is not usable, Scanner must be set.
type Engine struct {
	Scanner      HostScanner
	Checks       []check.Check
	Workers      int           // how many checks run at once, 0 means DefaultWorkers
	CheckTimeout time.Duration // max time for one check, 0 means DefaultCheckTimeout
	OnEvent      func(Event)   // optional, called one event at a time
}

type job struct {
	c check.Check
	t check.Target
}

// Run scans the targets. Targets must already be validated (see package target).
//
// If ctx is cancelled the scan stops early and Run returns what it has so far
// together with ctx's error.
func (e *Engine) Run(ctx context.Context, targets []string) (*Report, error) {
	if e.Scanner == nil {
		return nil, fmt.Errorf("engine: no scanner set")
	}
	if err := check.Validate(e.Checks); err != nil {
		return nil, fmt.Errorf("engine: bad checks: %w", err)
	}

	rep := &Report{Targets: targets, Started: time.Now(), Hosts: []model.Host{}, Findings: []model.Finding{}, Errors: []CheckError{}}
	var emitMu sync.Mutex
	emit := func(ev Event) {
		if e.OnEvent != nil {
			emitMu.Lock()
			defer emitMu.Unlock()
			e.OnEvent(ev)
		}
	}

	emit(Event{Kind: DiscoveryStarted})
	var hosts []model.Host
	var err error
	if ss, ok := e.Scanner.(StreamingScanner); ok {
		return e.runStreaming(ctx, targets, ss, rep, emit)
	}
	if ps, ok := e.Scanner.(ProgressScanner); ok && e.OnEvent != nil {
		hosts, err = ps.ScanWithProgress(ctx, targets, func(p ScannerProgress) {
			emit(Event{Kind: ScanProgress, Progress: p})
		})
	} else {
		hosts, err = e.Scanner.Scan(ctx, targets)
	}
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}
	rep.Hosts = slices.Clone(hosts) // we sort it later, so never touch the scanner's slice
	emit(Event{Kind: DiscoveryDone, Count: len(hosts)})

	var jobs []job
	for _, h := range hosts {
		for _, svc := range h.Services {
			for _, c := range e.Checks {
				if check.Applies(c.Info(), svc) {
					jobs = append(jobs, job{c: c, t: check.Target{Host: h.Address, Service: svc}})
				}
			}
		}
	}
	emit(Event{Kind: ChecksStarted, Count: len(jobs)})

	var mu sync.Mutex
	e.runJobs(ctx, jobs, func(j job, res *check.Result, err error) {
		mu.Lock()
		err = e.recordCheck(rep, j, res, err)
		mu.Unlock()
		emit(Event{Kind: CheckDone, Host: j.t.Host, Port: j.t.Service.Port, CheckID: j.c.Info().ID, Err: err})
	})

	sortReport(rep)
	rep.Finished = time.Now()
	emit(Event{Kind: ScanDone, Count: len(rep.Findings)})
	return rep, ctx.Err()
}

func (e *Engine) runStreaming(ctx context.Context, targets []string, scanner StreamingScanner, rep *Report, emit func(Event)) (*Report, error) {
	var mu sync.Mutex
	var hosts []model.Host
	checksStarted := 0
	var wg sync.WaitGroup
	queue := make(chan job)
	e.startWorkers(ctx, queue, &wg, func(j job, res *check.Result, err error) {
		mu.Lock()
		err = e.recordCheck(rep, j, res, err)
		mu.Unlock()
		emit(Event{Kind: CheckDone, Host: j.t.Host, Port: j.t.Service.Port, CheckID: j.c.Info().ID, Err: err})
	})
	err := scanner.StreamScan(ctx, targets, func(h model.Host) {
		mu.Lock()
		hosts = append(hosts, h)
		rep.Hosts = append(rep.Hosts, h)
		mu.Unlock()
		emit(Event{Kind: HostFound, Discovered: h})
		var hostJobs []job
		for _, svc := range h.Services {
			for _, c := range e.Checks {
				if check.Applies(c.Info(), svc) {
					hostJobs = append(hostJobs, job{c: c, t: check.Target{Host: h.Address, Service: svc}})
				}
			}
		}
		if len(hostJobs) > 0 {
			checksStarted += len(hostJobs)
			emit(Event{Kind: ChecksStarted, Host: h.Address, Count: checksStarted})
		}
		for _, j := range hostJobs {
			select {
			case queue <- j:
			case <-ctx.Done():
				return
			}
		}
	}, func(p ScannerProgress) { emit(Event{Kind: ScanProgress, Progress: p}) })
	close(queue)
	emit(Event{Kind: DiscoveryDone, Count: len(hosts)})
	wg.Wait()
	if err != nil {
		sortReport(rep)
		rep.Finished = time.Now()
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		return nil, fmt.Errorf("discovery failed: %w", err)
	}
	sortReport(rep)
	rep.Finished = time.Now()
	emit(Event{Kind: ScanDone, Count: len(rep.Findings)})
	return rep, ctx.Err()
}

// recordCheck applies one check result to the report. The caller serializes access
// when checks run concurrently.
func (e *Engine) recordCheck(rep *Report, j job, res *check.Result, err error) error {
	in := j.c.Info()
	conf := model.Confirmed
	if err == nil && res != nil && res.Confidence != "" {
		conf = res.Confidence
		if !conf.Valid() {
			res, err = nil, fmt.Errorf("check returned an unknown confidence %q", conf)
		}
	}
	if err != nil {
		rep.Errors = append(rep.Errors, CheckError{CheckID: in.ID, Host: j.t.Host, Port: j.t.Service.Port, Error: err.Error()})
	} else if res != nil {
		rep.Findings = append(rep.Findings, model.Finding{ID: model.FindingID(j.t.Host, in.ID, j.t.Service.Port, j.t.Service.Protocol), CheckID: in.ID, Title: in.Title, Severity: in.Severity, Confidence: conf, Host: j.t.Host, Port: j.t.Service.Port, Protocol: j.t.Service.Protocol, Evidence: res.Evidence, Fix: in.Fix})
	}
	return err
}

// runJobs runs every job on a fixed pool of workers and calls done for each.
func (e *Engine) runJobs(ctx context.Context, jobs []job, done func(job, *check.Result, error)) {
	queue := make(chan job)
	var wg sync.WaitGroup
	e.startWorkers(ctx, queue, &wg, done)
	for _, j := range jobs {
		select {
		case queue <- j:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(queue)
	wg.Wait()
}

// startWorkers starts the shared check worker pool used by buffered and
// streaming scans. The caller owns closing queue and waiting on wg.
func (e *Engine) startWorkers(ctx context.Context, queue <-chan job, wg *sync.WaitGroup, done func(job, *check.Result, error)) {
	workers := e.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				res, err := e.runOne(ctx, j)
				done(j, res, err)
			}
		}()
	}
}

// runOne runs a single check with a timeout and turns panics into errors.
func (e *Engine) runOne(ctx context.Context, j job) (res *check.Result, err error) {
	timeout := e.CheckTimeout
	if timeout <= 0 {
		timeout = DefaultCheckTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type out struct {
		res *check.Result
		err error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- out{err: fmt.Errorf("check panicked: %v\n%s", r, debug.Stack())}
			}
		}()
		r, err := j.c.Run(ctx, j.t)
		ch <- out{r, err}
	}()

	// A well behaved check returns on ctx.Done by itself. If it doesn't,
	// we stop waiting so one stuck check can't hang the whole scan.
	select {
	case o := <-ch:
		if o.res == nil && ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timed out after %s", timeout)
		}
		return o.res, o.err
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timed out after %s", timeout)
		}
		return nil, ctx.Err()
	}
}

// sortReport puts findings worst first, then by host, port and check, so
// output is the same every time for the same scan.
func sortReport(r *Report) {
	slices.SortFunc(r.Findings, func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.Host, b.Host),
			cmp.Compare(a.Port, b.Port),
			cmp.Compare(a.CheckID, b.CheckID),
		)
	})
	slices.SortFunc(r.Errors, func(a, b CheckError) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Port, b.Port), cmp.Compare(a.CheckID, b.CheckID))
	})
	slices.SortFunc(r.Hosts, func(a, b model.Host) int { return compareAddr(a.Address, b.Address) })
}

// compareAddr sorts IPs numerically (10.0.0.2 before 10.0.0.10) and falls
// back to plain text for anything that isn't an IP.
func compareAddr(a, b string) int {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return x.Compare(y)
	}
	return cmp.Compare(a, b)
}
