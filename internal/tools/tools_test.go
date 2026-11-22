// Tests shared scan validation, scope checks, port normalization and check filtering.

package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/checks/telnet"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/nmap"
)

type portCheck struct{}

func (portCheck) Info() check.Info {
	return check.Info{
		ID:       "redis-no-auth",
		Title:    "Redis has no password",
		Severity: model.High,
		Fix:      "Set requirepass.",
		Ports:    []int{6379},
		Services: []string{"redis"},
	}
}

func (portCheck) Run(context.Context, check.Target) (*check.Result, error) { return nil, nil }

type fakeRunner struct {
	xml  []byte
	err  error
	args []string
}

func (f *fakeRunner) Run(_ context.Context, args []string) ([]byte, error) {
	f.args = slices.Clone(args)
	return f.xml, f.err
}

func newTestService(r nmap.Runner) *Service {
	return &Service{
		Version:      "v0.1.0-test",
		RunnerName:   "nmap",
		NewRunner:    func() nmap.Runner { return r },
		Checks:       func() []check.Check { return []check.Check{telnet.Check{}} },
		EnforceScope: true,
		MaxWorkers:   128,
		StartedAt:    time.Now().Add(-5 * time.Second),
	}
}

func TestListFilterAndStatus(t *testing.T) {
	svc := newTestService(&fakeRunner{})
	svc.Checks = func() []check.Check { return []check.Check{telnet.Check{}, portCheck{}} }

	all := svc.ListChecks()
	if len(all) != 2 || all[0].ID != "telnet-open" {
		t.Fatalf("unexpected checks: %+v", all)
	}
	if len(svc.FilterChecks("")) != 2 {
		t.Fatal("empty filter should return all checks")
	}
	if len(svc.FilterChecks("6379")) != 1 {
		t.Fatal("filter by port should match portCheck")
	}
	if len(svc.FilterChecks("telnet")) != 1 {
		t.Fatal("filter by service/id should match telnet")
	}
	if len(svc.FilterChecks("medium")) != 1 {
		t.Fatal("filter by severity should match telnet")
	}
	if len(svc.FilterChecks("nonexistent")) != 0 {
		t.Fatal("filter should return zero matches for unknown query")
	}

	st := svc.Status("127.0.0.1:9002")
	if st.Engine != "nuqs" || st.Version != "v0.1.0-test" || st.Modules != 2 || st.Addr != "127.0.0.1:9002" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestValidateScan(t *testing.T) {
	svc := newTestService(&fakeRunner{})

	t.Run("normalizes localhost and ports", func(t *testing.T) {
		scan, err := svc.ValidateScan(ScanRequest{
			Target:  "localhost",
			Ports:   "23, 80, T:443, 1000-1010",
			Timeout: "5s",
			Workers: 4,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Equal(scan.Targets, []string{"127.0.0.1"}) {
			t.Fatalf("targets = %v, want [127.0.0.1]", scan.Targets)
		}
		if scan.Ports != "23,80,T:443,1000-1010" {
			t.Fatalf("ports = %q", scan.Ports)
		}
		if scan.Workers != 4 || scan.Timeout != 5*time.Second {
			t.Fatalf("workers=%d timeout=%v", scan.Workers, scan.Timeout)
		}
	})

	t.Run("applies defaults when optional fields omitted", func(t *testing.T) {
		scan, err := svc.ValidateScan(ScanRequest{Target: "127.0.0.1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scan.Workers != engine.DefaultWorkers || scan.Timeout != engine.DefaultCheckTimeout || scan.Ports != "" {
			t.Fatalf("unexpected defaults: %+v", scan)
		}
	})

	cases := map[string]ScanRequest{
		"blank target":       {Target: "   "},
		"flag target":        {Target: "-oN"},
		"outside loopback":   {Target: "192.0.2.1", Force: true},
		"overlapping /7":     {Target: "127.0.0.1/7", Force: true},
		"too many targets":   {Target: "127.0.0.0/16"},
		"bad timeout text":   {Target: "127.0.0.1", Timeout: "later"},
		"negative timeout":   {Target: "127.0.0.1", Timeout: "-5s"},
		"zero timeout":       {Target: "127.0.0.1", Timeout: "0s"},
		"workers too low":    {Target: "127.0.0.1", Workers: -1},
		"workers too high":   {Target: "127.0.0.1", Workers: 200},
		"ports text":         {Target: "127.0.0.1", Ports: "abc"},
		"ports flag":         {Target: "127.0.0.1", Ports: "-oN"},
		"ports bad range":    {Target: "127.0.0.1", Ports: "100-50"},
		"ports out of max":   {Target: "127.0.0.1", Ports: "70000"},
		"ports empty entry":  {Target: "127.0.0.1", Ports: "80,,443"},
		"negative top ports": {Target: "127.0.0.1", TopPorts: -5},
		"huge top ports":     {Target: "127.0.0.1", TopPorts: 70000},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.ValidateScan(req)
			var valErr *ValidationError
			if !errors.As(err, &valErr) {
				t.Fatalf("expected ValidationError, got %T: %v", err, err)
			}
		})
	}

	t.Run("accepts quick scan top_ports and light_version", func(t *testing.T) {
		scan, err := svc.ValidateScan(ScanRequest{
			Target:       "127.0.0.1",
			TopPorts:     100,
			LightVersion: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scan.TopPorts != 100 || !scan.LightVersion || scan.Ports != "" {
			t.Fatalf("unexpected scan: %+v", scan)
		}

		// Explicit ports clears top_ports so Nmap never receives both.
		scan2, err := svc.ValidateScan(ScanRequest{
			Target:   "127.0.0.1",
			Ports:    "80,443",
			TopPorts: 100,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scan2.Ports != "80,443" || scan2.TopPorts != 0 {
			t.Fatalf("explicit ports should clear TopPorts: %+v", scan2)
		}
	})
}

func TestFriendlyErrorAndInstallHint(t *testing.T) {
	if !strings.Contains(nmapInstallHintFor("darwin"), "brew install nmap") {
		t.Fatalf("darwin hint = %q", nmapInstallHintFor("darwin"))
	}
	if !strings.Contains(nmapInstallHintFor("windows"), "winget install Insecure.Nmap") {
		t.Fatalf("windows hint = %q", nmapInstallHintFor("windows"))
	}
	if !strings.Contains(nmapInstallHintFor("linux"), "apt install nmap") {
		t.Fatalf("linux hint = %q", nmapInstallHintFor("linux"))
	}
	if NmapInstallHint() == "" {
		t.Fatal("NmapInstallHint should not be empty")
	}

	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{&ValidationError{Message: "bad input"}, "bad input"},
		{context.Canceled, "Scan stopped before finishing."},
		{context.DeadlineExceeded, "Scan timed out before finishing."},
		{fmt.Errorf("discovery failed: %w", exec.ErrNotFound), "Nmap isn't installed"},
		{os.ErrNotExist, "Nmap isn't installed"},
		{os.ErrPermission, "Permission denied while running Nmap"},
		{errors.New("nmap failed: Failed to resolve given hostname/IP"), "Couldn't resolve that target hostname"},
		{errors.New("discovery failed: reading nmap XML: EOF"), "Nmap stopped unexpectedly"},
		{errors.New("discovery failed: something custom"), "something custom"},
	}
	for _, tc := range cases {
		got := FriendlyError(tc.err)
		if tc.want == "" && got != "" {
			t.Errorf("FriendlyError(%v) = %q, want empty", tc.err, got)
		} else if tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("FriendlyError(%v) = %q, want substring %q", tc.err, got, tc.want)
		}
	}
}

func TestAllowedScope(t *testing.T) {
	allowed, err := ParseAllowedScope("192.168.56.0/24, 10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := FormatAllowedScope(allowed); got != "192.168.56.0/24, 10.0.0.5/32" {
		t.Fatalf("FormatAllowedScope = %q", got)
	}
	if !TargetAllowed("192.168.56.10", allowed) || !TargetAllowed("192.168.56.1-20", allowed) || !TargetAllowed("10.0.0.5", allowed) {
		t.Fatal("expected in-scope targets to be allowed")
	}
	if !TargetAllowed("192.168.56.0/25", allowed) {
		t.Fatal("expected subnet inside allowed prefix to be allowed")
	}
	if TargetAllowed("10.0.0.6", allowed) || TargetAllowed("192.168.0.0/16", allowed) || TargetAllowed("example.com", allowed) {
		t.Fatal("expected out-of-scope targets to be rejected")
	}

	if _, err := ParseAllowedScope("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid allowed target")
	}
	if empty, err := ParseAllowedScope("  "); err != nil || len(empty) != 0 {
		t.Fatalf("empty scope: got %v, %v", empty, err)
	}

	svc := newTestService(&fakeRunner{})
	svc.AllowedScope = allowed
	if _, err := svc.ValidateScan(ScanRequest{Target: "10.0.0.6"}); err == nil || !strings.Contains(err.Error(), "outside the allowed scope") {
		t.Fatalf("expected custom scope error, got %v", err)
	}
}

func TestRunScan(t *testing.T) {
	const telnetXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	runner := &fakeRunner{xml: []byte(telnetXML)}
	svc := newTestService(runner)
	var events []engine.EventKind
	rep, err := svc.RunScan(context.Background(), ScanRequest{
		Target:   "localhost",
		Ports:    "23, 80",
		SkipPing: true,
	}, func(ev engine.Event) {
		events = append(events, ev.Kind)
	})
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].CheckID != "telnet-open" {
		t.Fatalf("unexpected findings: %+v", rep.Findings)
	}
	if !slices.Contains(runner.args, "23,80") || !slices.Contains(runner.args, "-Pn") {
		t.Fatalf("unexpected nmap args: %v", runner.args)
	}
	if !slices.Contains(events, engine.DiscoveryStarted) || !slices.Contains(events, engine.ScanDone) {
		t.Fatalf("missing expected events: %v", events)
	}
}
