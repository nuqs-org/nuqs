// Tests the engine: timeouts, panics, cancelling, the worker limit and sorting.

package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// fakeScanner returns fixed hosts instead of running Nmap.
type fakeScanner struct {
	hosts []model.Host
	err   error
}

func (f fakeScanner) Scan(context.Context, []string) ([]model.Host, error) { return f.hosts, f.err }

// fakeCheck runs a function you give it and counts calls.
type fakeCheck struct {
	info  check.Info
	run   func(ctx context.Context, t check.Target) (*check.Result, error)
	calls atomic.Int32
}

func (f *fakeCheck) Info() check.Info { return f.info }
func (f *fakeCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	f.calls.Add(1)
	return f.run(ctx, t)
}

func newCheck(id string, sev model.Severity, services []string, run func(context.Context, check.Target) (*check.Result, error)) *fakeCheck {
	return &fakeCheck{info: check.Info{ID: id, Title: id + " title", Fix: id + " fix", Severity: sev, Services: services}, run: run}
}

func found(evidence string) func(context.Context, check.Target) (*check.Result, error) {
	return func(context.Context, check.Target) (*check.Result, error) {
		return &check.Result{Evidence: evidence}, nil
	}
}

func clean(context.Context, check.Target) (*check.Result, error) { return nil, nil }

var twoHosts = []model.Host{
	{Address: "10.0.0.10", Services: []model.Service{{Port: 80, Protocol: "tcp", Name: "http"}, {Port: 22, Protocol: "tcp", Name: "ssh"}}},
	{Address: "10.0.0.2", Services: []model.Service{{Port: 23, Protocol: "tcp", Name: "telnet"}}},
}

func TestFindingsAndApplicability(t *testing.T) {
	web := newCheck("web", model.Low, []string{"http"}, found("no headers"))
	tel := newCheck("tel", model.Medium, []string{"telnet"}, found("telnet open"))
	ok := newCheck("ok", model.High, []string{"ssh"}, clean)
	unused := newCheck("unused", model.High, []string{"ftp"}, found("x"))

	e := &Engine{Scanner: fakeScanner{hosts: twoHosts}, Checks: []check.Check{web, tel, ok, unused}}
	rep, err := e.Run(context.Background(), []string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	if unused.calls.Load() != 0 {
		t.Error("a check must not run on services it doesn't apply to")
	}
	if web.calls.Load() != 1 || tel.calls.Load() != 1 || ok.calls.Load() != 1 {
		t.Errorf("each applicable check should run once: web=%d tel=%d ok=%d", web.calls.Load(), tel.calls.Load(), ok.calls.Load())
	}
	if len(rep.Findings) != 2 || len(rep.Errors) != 0 {
		t.Fatalf("expected 2 findings and 0 errors, got %+v / %+v", rep.Findings, rep.Errors)
	}

	// Worst first: the medium telnet finding comes before the low web one.
	f := rep.Findings[0]
	want := model.Finding{
		ID: "tel|10.0.0.2|23/tcp", CheckID: "tel", Title: "tel title", Severity: model.Medium, Confidence: model.Confirmed,
		Host: "10.0.0.2", Port: 23, Protocol: "tcp", Evidence: "telnet open", Fix: "tel fix",
	}
	if f != want {
		t.Errorf("finding = %+v\nwant      %+v", f, want)
	}
	if rep.Findings[1].CheckID != "web" {
		t.Errorf("second finding should be web, got %s", rep.Findings[1].CheckID)
	}

	// Hosts are sorted by IP, so 10.0.0.2 comes before 10.0.0.10.
	if rep.Hosts[0].Address != "10.0.0.2" {
		t.Errorf("hosts not sorted numerically: %s first", rep.Hosts[0].Address)
	}
	if rep.Started.IsZero() || rep.Finished.Before(rep.Started) {
		t.Error("start and finish times not set properly")
	}
	if len(rep.Targets) != 1 || rep.Targets[0] != "10.0.0.0/24" {
		t.Errorf("targets not recorded: %v", rep.Targets)
	}
}

func TestCheckErrorIsNotAFinding(t *testing.T) {
	bad := newCheck("bad", model.High, nil, func(context.Context, check.Target) (*check.Result, error) {
		return nil, errors.New("connection refused")
	})
	rep, err := (&Engine{Scanner: fakeScanner{hosts: twoHosts[1:]}, Checks: []check.Check{bad}}).Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 || len(rep.Errors) != 1 {
		t.Fatalf("expected 1 error and no findings, got %+v / %+v", rep.Findings, rep.Errors)
	}
	want := CheckError{CheckID: "bad", Host: "10.0.0.2", Port: 23, Error: "connection refused"}
	if rep.Errors[0] != want {
		t.Errorf("error = %+v, want %+v", rep.Errors[0], want)
	}
}

func TestPanicIsCaught(t *testing.T) {
	boom := newCheck("boom", model.High, nil, func(context.Context, check.Target) (*check.Result, error) { panic("oops") })
	fine := newCheck("fine", model.Low, nil, found("still ran"))
	rep, err := (&Engine{Scanner: fakeScanner{hosts: twoHosts}, Checks: []check.Check{boom, fine}}).Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 3 || len(rep.Findings) != 3 {
		t.Fatalf("panics must become errors and other checks must keep running: %d errors, %d findings", len(rep.Errors), len(rep.Findings))
	}
	if !strings.Contains(rep.Errors[0].Error, "check panicked: oops") {
		t.Errorf("unexpected panic error: %s", rep.Errors[0].Error)
	}
}

func TestStuckCheckTimesOut(t *testing.T) {
	// This check ignores ctx completely, the worst case.
	stuck := newCheck("stuck", model.High, nil, func(context.Context, check.Target) (*check.Result, error) {
		time.Sleep(3 * time.Second)
		return &check.Result{Evidence: "too late"}, nil
	})
	start := time.Now()
	rep, err := (&Engine{Scanner: fakeScanner{hosts: twoHosts[1:]}, Checks: []check.Check{stuck}, CheckTimeout: 50 * time.Millisecond}).Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the engine waited for a stuck check instead of timing out")
	}
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Error, "timed out after 50ms") {
		t.Errorf("expected a timeout error, got %+v", rep.Errors)
	}
	if len(rep.Findings) != 0 {
		t.Error("a timed out check must not produce a finding")
	}
}

func TestPoliteCheckTimesOut(t *testing.T) {
	// This check respects ctx and returns its error, the normal case.
	polite := newCheck("polite", model.High, nil, func(ctx context.Context, _ check.Target) (*check.Result, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	rep, err := (&Engine{Scanner: fakeScanner{hosts: twoHosts[1:]}, Checks: []check.Check{polite}, CheckTimeout: 20 * time.Millisecond}).Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Error, "timed out") {
		t.Errorf("expected a timeout error, got %+v", rep.Errors)
	}
}

func TestCancelStopsScan(t *testing.T) {
	var hosts []model.Host
	for i := range 50 {
		hosts = append(hosts, model.Host{Address: "10.0.1." + string(rune('a'+i%26)), Services: []model.Service{{Port: 80, Protocol: "tcp", Name: "http"}}})
	}
	ctx, cancel := context.WithCancel(context.Background())
	var started atomic.Int32
	slow := newCheck("slow", model.Low, nil, func(ctx context.Context, _ check.Target) (*check.Result, error) {
		if started.Add(1) == 2 {
			cancel()
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	rep, err := (&Engine{Scanner: fakeScanner{hosts: hosts}, Checks: []check.Check{slow}, Workers: 2}).Run(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if rep == nil {
		t.Fatal("a cancelled scan should still return what it has")
	}
	if n := started.Load(); n > 4 {
		t.Errorf("cancel should stop new checks quickly, but %d started", n)
	}
}

func TestWorkerLimit(t *testing.T) {
	var hosts []model.Host
	for i := range 20 {
		hosts = append(hosts, model.Host{Address: "10.0.2." + string(rune('a'+i)), Services: []model.Service{{Port: 80, Protocol: "tcp", Name: "http"}}})
	}
	var now, peak atomic.Int32
	c := newCheck("count", model.Low, nil, func(context.Context, check.Target) (*check.Result, error) {
		n := now.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		now.Add(-1)
		return nil, nil
	})
	if _, err := (&Engine{Scanner: fakeScanner{hosts: hosts}, Checks: []check.Check{c}, Workers: 3}).Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if p := peak.Load(); p > 3 || p < 2 {
		t.Errorf("expected at most 3 (and more than 1) checks at once, saw %d", p)
	}
	if c.calls.Load() != 20 {
		t.Errorf("all 20 checks should run, %d did", c.calls.Load())
	}
}

func TestEvents(t *testing.T) {
	var mu sync.Mutex
	var kinds []EventKind
	var doneCount int
	e := &Engine{
		Scanner: fakeScanner{hosts: twoHosts},
		Checks:  []check.Check{newCheck("all", model.Low, nil, clean)},
		OnEvent: func(ev Event) {
			mu.Lock()
			defer mu.Unlock()
			kinds = append(kinds, ev.Kind)
			if ev.Kind == CheckDone {
				doneCount++
			}
			if ev.Kind == ChecksStarted && ev.Count != 3 {
				t.Errorf("ChecksStarted count = %d, want 3", ev.Count)
			}
			if ev.Kind == DiscoveryDone && ev.Count != 2 {
				t.Errorf("DiscoveryDone count = %d, want 2", ev.Count)
			}
		},
	}
	if _, err := e.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if kinds[0] != DiscoveryStarted || kinds[1] != DiscoveryDone || kinds[2] != ChecksStarted || kinds[len(kinds)-1] != ScanDone {
		t.Errorf("events out of order: %v", kinds)
	}
	if doneCount != 3 {
		t.Errorf("expected 3 CheckDone events, got %d", doneCount)
	}
}

func TestSetupErrors(t *testing.T) {
	if _, err := (&Engine{}).Run(context.Background(), nil); err == nil {
		t.Error("missing scanner should fail")
	}
	bad := newCheck("Bad ID", model.Low, nil, clean)
	if _, err := (&Engine{Scanner: fakeScanner{}, Checks: []check.Check{bad}}).Run(context.Background(), nil); err == nil {
		t.Error("invalid checks should fail before scanning")
	}
	boom := errors.New("nmap broke")
	rep, err := (&Engine{Scanner: fakeScanner{err: boom}}).Run(context.Background(), nil)
	if !errors.Is(err, boom) || rep != nil {
		t.Errorf("discovery errors should stop the scan, got %v, %v", rep, err)
	}
}

func TestNoHostsIsFine(t *testing.T) {
	rep, err := (&Engine{Scanner: fakeScanner{}}).Run(context.Background(), []string{"10.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Findings == nil || rep.Errors == nil {
		t.Error("empty lists should be [] not null, so JSON stays simple for tools")
	}
}

func TestScannerSliceNotChanged(t *testing.T) {
	hosts := []model.Host{{Address: "10.0.0.10"}, {Address: "10.0.0.2"}}
	if _, err := (&Engine{Scanner: fakeScanner{hosts: hosts}}).Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if hosts[0].Address != "10.0.0.10" {
		t.Error("the engine sorted the scanner's own slice, it must sort a copy")
	}
}

func TestCompareAddr(t *testing.T) {
	if compareAddr("10.0.0.2", "10.0.0.10") >= 0 {
		t.Error("IPs should sort numerically")
	}
	if compareAddr("a.example", "b.example") >= 0 {
		t.Error("names should sort as text")
	}
	if compareAddr("10.0.0.1", "10.0.0.1") != 0 {
		t.Error("equal addresses should compare equal")
	}
}

func TestConfidence(t *testing.T) {
	result := func(c model.Confidence) func(context.Context, check.Target) (*check.Result, error) {
		return func(context.Context, check.Target) (*check.Result, error) {
			return &check.Result{Evidence: "e", Confidence: c}, nil
		}
	}
	cases := []struct {
		name string
		in   model.Confidence
		want model.Confidence // empty means the result must become an error
	}{
		{"empty means confirmed", "", model.Confirmed},
		{"confirmed", model.Confirmed, model.Confirmed},
		{"inferred", model.Inferred, model.Inferred},
		{"unknown", "maybe", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tel := newCheck("tel", model.Medium, []string{"telnet"}, result(c.in))
			e := &Engine{Scanner: fakeScanner{hosts: twoHosts}, Checks: []check.Check{tel}}
			rep, err := e.Run(context.Background(), []string{"10.0.0.2"})
			if err != nil {
				t.Fatal(err)
			}
			if c.want == "" {
				if len(rep.Findings) != 0 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Error, "unknown confidence") {
					t.Fatalf("an unknown confidence must be an error, not a finding: %+v / %+v", rep.Findings, rep.Errors)
				}
				return
			}
			if len(rep.Findings) != 1 || rep.Findings[0].Confidence != c.want {
				t.Fatalf("want one %s finding, got %+v", c.want, rep.Findings)
			}
		})
	}
}
