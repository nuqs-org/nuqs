// Tests that the progress estimate only goes forward, gives each Nmap step its slice and guesses time left sensibly.

package progress

import (
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func nmapAt(task string, pct float64) engine.Event {
	return engine.Event{Kind: engine.ScanProgress, Progress: engine.ScannerProgress{Task: task, Percent: pct}}
}

func TestWholeScan(t *testing.T) {
	tr := New(t0)
	if tr.Percent() != 0 || tr.Step() != "Starting Nmap" || tr.Remaining(t0) != "" {
		t.Fatalf("start: %v %q %q", tr.Percent(), tr.Step(), tr.Remaining(t0))
	}
	steps := []struct {
		ev       engine.Event
		at       time.Duration
		want     float64 // percent
		wantStep string
	}{
		{engine.Event{Kind: engine.DiscoveryStarted}, 0, 0, "Starting Nmap"},
		{nmapAt("Ping Scan", 50), 1 * time.Second, 0.85 * 4, "Finding live hosts"},
		{nmapAt("Parallel DNS resolution of 1 host.", 100), 2 * time.Second, 0.85 * 10, "Looking up host names"},
		{nmapAt("Connect Scan", 0), 3 * time.Second, 0.85 * 10, "Scanning ports"},
		{nmapAt("Connect Scan", 100), 10 * time.Second, 0.85 * 55, "Scanning ports"},
		{nmapAt("Service scan", 50), 20 * time.Second, 0.85 * 77.5, "Identifying services"},
		{engine.Event{Kind: engine.DiscoveryDone, Count: 2}, 30 * time.Second, 85, "Found 2 live hosts"},
		{engine.Event{Kind: engine.ChecksStarted, Count: 4}, 30 * time.Second, 85, "Running checks, 0 of 4 done"},
		{engine.Event{Kind: engine.CheckDone}, 31 * time.Second, 85 + 15.0/4, "Running checks, 1 of 4 done"},
		{engine.Event{Kind: engine.CheckDone}, 32 * time.Second, 85 + 15.0/2, "Running checks, 2 of 4 done"},
		{engine.Event{Kind: engine.ScanDone}, 33 * time.Second, 100, "Writing the report"},
	}
	for _, s := range steps {
		tr.Add(s.ev, t0.Add(s.at))
		if diff := tr.Percent() - s.want; diff > 0.01 || diff < -0.01 {
			t.Errorf("after %v: percent %.2f, want %.2f", s.ev.Kind, tr.Percent(), s.want)
		}
		if tr.Step() != s.wantStep {
			t.Errorf("after %v: step %q, want %q", s.ev.Kind, tr.Step(), s.wantStep)
		}
	}
	if tr.Remaining(t0.Add(33*time.Second)) != "" {
		t.Error("a finished scan has no time left")
	}
}

func TestBatches(t *testing.T) {
	tr := New(t0)
	tr.Add(nmapAt("Connect Scan", 100), t0)
	tr.Add(nmapAt("Service scan", 100), t0) // first batch done: Nmap's part is full...
	first := tr.Percent()
	if first < 84.9 {
		t.Fatalf("first batch %.1f", first)
	}
	// ...but Nmap starts on the next batch of hosts. The bar must not go
	// back, and must not freeze either.
	tr = New(t0)
	tr.Add(nmapAt("Connect Scan", 100), t0)
	tr.Add(nmapAt("Service scan", 50), t0) // 77.5% of Nmap's part
	tr.Add(nmapAt("Connect Scan", 0), t0)  // next batch, can fill half the 22.5% left
	at := tr.Percent()
	tr.Add(nmapAt("Connect Scan", 100), t0)
	tr.Add(nmapAt("Service scan", 100), t0)
	want := 0.85 * (77.5 + 22.5/2)
	if tr.Percent() <= at || tr.Percent()-want > 0.01 || want-tr.Percent() > 0.01 {
		t.Errorf("second batch: from %.2f to %.2f, want %.2f", at, tr.Percent(), want)
	}
	tr.Add(nmapAt("Connect Scan", 50), t0) // a third batch keeps going, slower
	if tr.Percent() <= want {
		t.Errorf("third batch should still move, got %.2f", tr.Percent())
	}
}

func TestNeverGoesBack(t *testing.T) {
	tr := New(t0)
	tr.Add(nmapAt("Service scan", 80), t0.Add(time.Second))
	before := tr.Percent()
	// An odd update arrives late, or Nmap starts its next batch of hosts.
	tr.Add(nmapAt("Connect Scan", 10), t0.Add(2*time.Second))
	tr.Add(nmapAt("Ping Scan", 0), t0.Add(3*time.Second))
	if tr.Percent() < before {
		t.Errorf("went back from %.1f to %.1f", before, tr.Percent())
	}
	// Bad numbers are clamped, unknown tasks are ignored.
	tr.Add(nmapAt("Service scan", 500), t0.Add(4*time.Second))
	tr.Add(nmapAt("Something new", 100), t0.Add(5*time.Second))
	if tr.Percent() > 99 {
		t.Errorf("only ScanDone may reach 100, got %.1f", tr.Percent())
	}
	tr.Add(engine.Event{Kind: engine.CheckDone}, t0) // a stray event without ChecksStarted
	tr.Add(engine.Event{Kind: "something else"}, t0)
	if tr.Percent() > 99 {
		t.Errorf("got %.1f", tr.Percent())
	}
}

func TestNoChecksMeansChecksAreDone(t *testing.T) {
	tr := New(t0)
	tr.Add(engine.Event{Kind: engine.DiscoveryDone, Count: 0}, t0.Add(time.Second))
	tr.Add(engine.Event{Kind: engine.ChecksStarted, Count: 0}, t0.Add(time.Second))
	if tr.Percent() != 99 || tr.Step() != "Running checks" {
		t.Errorf("no checks to run: %.1f %q", tr.Percent(), tr.Step())
	}
}

func TestChecksStartedKeepsNmapProgressAndUsesCumulativeTotal(t *testing.T) {
	tr := New(t0)
	tr.Add(nmapAt("Service scan", 50), t0)
	before := tr.Percent()
	tr.Add(engine.Event{Kind: engine.ChecksStarted, Count: 2}, t0)
	if tr.Percent() < before || tr.Percent()-before > 0.01 {
		t.Fatalf("first host changed progress incorrectly: before %.1f after %.1f", before, tr.Percent())
	}
	tr.Add(engine.Event{Kind: engine.CheckDone}, t0)
	tr.Add(engine.Event{Kind: engine.ChecksStarted, Count: 5}, t0)
	if !strings.Contains(tr.Step(), "1 of 5 done") {
		t.Fatalf("step = %q, want cumulative total", tr.Step())
	}
}

func TestTimeLeft(t *testing.T) {
	early := New(t0)
	early.Add(nmapAt("Connect Scan", 10), t0.Add(time.Second))
	if got := early.Remaining(t0.Add(time.Second)); got != "" {
		t.Errorf("too early to guess, got %q", got)
	}

	tr3 := New(t0)
	tr3.Add(nmapAt("Service scan", 0), t0.Add(20*time.Second)) // 0.85*0.55 = 46.75%
	got := tr3.Remaining(t0.Add(20 * time.Second))
	if got != "about 25s left" { // 20s * (1-0.4675)/0.4675 = 22.8s, shown rounded up to 25s
		t.Errorf("first guess %q", got)
	}
	// It counts down between updates.
	if got := tr3.Remaining(t0.Add(30 * time.Second)); got != "about 15s left" {
		t.Errorf("counted down %q", got)
	}
	if got := tr3.Remaining(t0.Add(50 * time.Second)); got != "almost done" {
		t.Errorf("past the guess %q", got)
	}
	// A new update is blended with the old guess instead of jumping to it.
	tr3.Add(nmapAt("Service scan", 50), t0.Add(30*time.Second)) // 65.875%: fresh guess 15.5s
	if got := tr3.Remaining(t0.Add(30 * time.Second)); got != "about 15s left" {
		t.Errorf("blended %q", got) // 0.7*12.8s + 0.3*15.5s = 13.6s
	}
}

func TestWords(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                         "almost done",
		4 * time.Second:           "almost done",
		6 * time.Second:           "about 10s left",
		41 * time.Second:          "about 45s left",
		59 * time.Second:          "about 60s left",
		90 * time.Second:          "about 2 min left",
		10 * time.Minute:          "about 10 min left",
		3*time.Hour + time.Minute: "about 3 hours left",
	} {
		if got := Words(d); got != want {
			t.Errorf("Words(%v) = %q, want %q", d, got, want)
		}
	}
}
