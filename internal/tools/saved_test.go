// Tests for saving web UI scans to the store and loading them after a restart.

package tools

import (
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/store"
)

func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestScansAreSavedAndComeBackAfterARestart(t *testing.T) {
	dir := t.TempDir()
	st := openStore(t, dir)
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	s, err := m.Start(NewScan{Name: "Lab", Description: "telnet box", Kind: "full", Settings: ScanRequest{Target: "127.0.0.1", Ports: "23"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "1" {
		t.Errorf("the store gives the ID, got %q", s.ID)
	}
	done := waitFor(t, m, s.ID, finished)

	// The store has it as soon as the scan shows as finished.
	saved, err := st.Run(1)
	if err != nil || saved.Status != store.Completed || saved.Report == nil || len(saved.Report.Findings) != 1 {
		t.Fatalf("saved: %+v, %v", saved, err)
	}

	// A new server on the same store shows the same scan.
	again := &Scans{Service: m.Service, Store: openStore(t, dir)}
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	list := again.List()
	if len(list) != 1 {
		t.Fatalf("after restart: %+v", list)
	}
	got := list[0]
	if got.ID != "1" || got.Name != "Lab" || got.Description != "telnet box" || got.Kind != "full" ||
		got.Settings.Ports != "23" || got.Status != ScanCompleted || got.Percent != 100 || got.HostsFound != 1 ||
		len(got.Report.Findings) != 1 || !got.Finished.Equal(done.Finished) {
		t.Errorf("after restart: %+v", got)
	}

	// IDs keep counting up from the saved ones.
	next, err := again.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, again, next.ID, finished)
	if next.ID != "2" {
		t.Errorf("next ID %q", next.ID)
	}
	again.StopAll() // loaded scans can be "stopped" safely, they're done
}

func TestOlderScansLoadFromTheStore(t *testing.T) {
	st := openStore(t, t.TempDir())
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st, Keep: 1}
	first, _ := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	waitFor(t, m, first.ID, finished)
	second, _ := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	waitFor(t, m, second.ID, finished)

	if len(m.List()) != 1 {
		t.Fatalf("memory keeps %d", len(m.List()))
	}
	old, ok := m.Get(first.ID)
	if !ok || old.Status != ScanCompleted || old.Report == nil {
		t.Errorf("the first scan should load from the store: %+v", old)
	}
	if err := m.Stop(first.ID); err != nil {
		t.Errorf("stopping a finished saved scan: %v", err)
	}
	for _, id := range []string{"99", "abc"} {
		if _, ok := m.Get(id); ok {
			t.Errorf("scan %s shouldn't exist", id)
		}
		if err := m.Stop(id); err != ErrNotFound {
			t.Errorf("stop %s: %v", id, err)
		}
	}
}

func TestLoadClosesScansACrashLeftRunning(t *testing.T) {
	st := openStore(t, t.TempDir())
	r := store.Run{Name: "cut off", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: time.Now()}
	if err := st.Create(&r); err != nil {
		t.Fatal(err)
	}
	m := &Scans{Service: newTestService(&fakeRunner{}), Store: st}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	s, ok := m.Get("1")
	if !ok || s.Status != ScanStopped || s.Error == "" || s.Settings.Target != "" {
		t.Errorf("%+v", s)
	}
	// A new scan can start, the old one doesn't count as running.
	if _, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}}); err != nil {
		t.Error(err)
	}
}

func TestStoreProblemsAreReported(t *testing.T) {
	st := openStore(t, t.TempDir())
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st}
	st.Close()
	if err := m.Load(); err == nil {
		t.Error("load from a closed store should fail")
	}
	if _, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}}); err == nil {
		t.Error("start should fail when the scan can't be saved")
	}
}

func TestFinishedButNotSaved(t *testing.T) {
	st := openStore(t, t.TempDir())
	release := make(chan struct{})
	m := &Scans{Service: newTestService(&blockingRunner{release: release, xml: []byte(telnetXML)}), Store: st}
	s, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	st.Close() // the disk went away mid-scan
	close(release)
	done := waitFor(t, m, s.ID, finished)
	if done.Status != ScanCompleted || done.Report == nil || !strings.Contains(done.Error, "couldn't be saved") {
		t.Errorf("%+v", done)
	}
}

func TestCommandLineScanKind(t *testing.T) {
	if got := (Scan{Kind: "cli"}).KindName(); got != "Command line scan" {
		t.Errorf("got %q", got)
	}
}
