// Tests running scans in the background: status, live updates, stop, one at a time and forgetting old ones.

package tools

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

const telnetXML = `<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="probed"/></port></ports></host></nmaprun>`

// blockingRunner waits until released or cancelled, so tests can look at a running scan.
type blockingRunner struct {
	release chan struct{}
	xml     []byte
}

func (b *blockingRunner) Run(ctx context.Context, _ []string, out io.Writer) error {
	select {
	case <-b.release:
		_, err := out.Write(b.xml)
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitFor watches a scan until done says it's there, or fails after 5 seconds.
func waitFor(t *testing.T, m *Scans, id string, done func(Scan) bool) Scan {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		s, changed, ok := m.Watch(id)
		if !ok {
			t.Fatalf("scan %s is gone", id)
		}
		if done(s) {
			return s
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("scan %s never got there, last state %+v", id, s)
		}
	}
}

func finished(s Scan) bool { return s.Status != ScanRunning }

func TestScanRunsInBackground(t *testing.T) {
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)})}
	s, err := m.Start(NewScan{Kind: "full", Settings: ScanRequest{Target: "localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "1" || s.Name != "127.0.0.1" || s.Status != ScanRunning || s.KindName() != "Full scan" {
		t.Errorf("new scan %+v", s)
	}
	done := waitFor(t, m, s.ID, finished)
	if done.Status != ScanCompleted || done.Report == nil || len(done.Report.Findings) != 1 {
		t.Fatalf("finished scan %+v", done)
	}
	if done.HostsFound != 1 || done.ChecksTotal != 1 || done.ChecksDone != 1 || done.Phase != "" || done.Percent != 100 || done.Remaining != "" {
		t.Errorf("progress not tracked: %+v", done)
	}
	if done.Elapsed() <= 0 || done.Elapsed() > 5*time.Second {
		t.Errorf("elapsed %v", done.Elapsed())
	}
}

// halfwayRunner prints a progress update, waits to be released, then prints the host.
type halfwayRunner struct{ release chan struct{} }

func (h *halfwayRunner) Run(ctx context.Context, _ []string, out io.Writer) error {
	if _, err := io.WriteString(out, `<nmaprun><taskprogress task="Service scan" percent="50" remaining="10"/>`); err != nil {
		return err
	}
	select {
	case <-h.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	_, err := io.WriteString(out, strings.TrimPrefix(telnetXML, "<nmaprun>"))
	return err
}

func TestProgressWhileRunning(t *testing.T) {
	r := &halfwayRunner{release: make(chan struct{})}
	m := &Scans{Service: newTestService(r)}
	s, err := m.Start(NewScan{Kind: "full", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Phase != "Starting Nmap" || s.Percent != 0 {
		t.Errorf("new scan %q %v", s.Phase, s.Percent)
	}
	mid := waitFor(t, m, s.ID, func(s Scan) bool { return s.Percent > 0 })
	// Halfway through service detection is 85% * 77.5%, so about 66%.
	if mid.Phase != "Identifying services" || mid.Percent < 65 || mid.Percent > 67 {
		t.Errorf("halfway: %q %.1f", mid.Phase, mid.Percent)
	}
	if list := m.List(); list[0].Percent != mid.Percent {
		t.Errorf("List should show the same progress, got %.1f", list[0].Percent)
	}
	close(r.release)
	done := waitFor(t, m, s.ID, finished)
	if done.Status != ScanCompleted || done.Percent != 100 {
		t.Errorf("done %+v", done)
	}
}

func TestOneScanAtATimeAndStop(t *testing.T) {
	r := &blockingRunner{release: make(chan struct{})}
	m := &Scans{Service: newTestService(r)}
	s, err := m.Start(NewScan{Name: "  Office router  ", Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "Office router" {
		t.Errorf("name %q", s.Name)
	}

	if _, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}}); !errors.Is(err, ErrBusy) {
		t.Errorf("second scan should be refused while one runs, got %v", err)
	}
	if err := m.Stop(s.ID); err != nil {
		t.Fatal(err)
	}
	stopped := waitFor(t, m, s.ID, finished)
	if stopped.Status != ScanStopped || stopped.Finished.IsZero() {
		t.Errorf("stopped scan %+v", stopped)
	}
	if err := m.Stop(s.ID); err != nil {
		t.Errorf("stopping a finished scan is fine, got %v", err)
	}
	if err := m.Stop("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want not found, got %v", err)
	}

	// Once it's stopped a new one can start.
	s2, err := m.Start(NewScan{Kind: "custom", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if s2.KindName() != "Custom scan" {
		t.Errorf("kind %q", s2.KindName())
	}
	if list := m.List(); len(list) != 2 || list[0].ID != s2.ID {
		t.Errorf("list should be newest first: %+v", list)
	}
	m.StopAll()
	waitFor(t, m, s2.ID, finished)
}

func TestScanFailsWithFriendlyError(t *testing.T) {
	m := &Scans{Service: newTestService(&fakeRunner{err: errors.New(`exec: "nmap": executable file not found in $PATH`)})}
	s, err := m.Start(NewScan{Kind: "full", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	failed := waitFor(t, m, s.ID, finished)
	if failed.Status != ScanFailed || !strings.Contains(failed.Error, "Nmap isn't installed") {
		t.Errorf("failed scan %+v", failed)
	}
}

func TestStartRejectsBadInput(t *testing.T) {
	m := &Scans{Service: newTestService(&fakeRunner{})}
	for name, in := range map[string]NewScan{
		"outside scope": {Kind: "full", Settings: ScanRequest{Target: "192.0.2.1"}},
		"unknown kind":  {Kind: "discover", Settings: ScanRequest{Target: "127.0.0.1"}},
		"long name":     {Kind: "full", Name: strings.Repeat("x", 101), Settings: ScanRequest{Target: "127.0.0.1"}},
	} {
		t.Run(name, func(t *testing.T) {
			var ve *ValidationError
			if _, err := m.Start(in); !errors.As(err, &ve) {
				t.Errorf("want a validation error, got %v", err)
			}
		})
	}
	if len(m.List()) != 0 {
		t.Error("rejected scans must not be listed")
	}
	if _, ok := m.Get("1"); ok {
		t.Error("nothing should be there")
	}
}

func TestOldScansAreForgotten(t *testing.T) {
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Keep: 3}
	for range 5 {
		s, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, m, s.ID, finished)
	}
	list := m.List()
	if len(list) != 3 || list[0].ID != "5" || list[2].ID != "3" {
		t.Errorf("want the 3 newest, got %d starting at %s", len(list), list[0].ID)
	}
}
