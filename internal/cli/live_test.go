// Tests the one-line live progress: it redraws in place, counts down, and leaves a clean line behind.

package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
)

// fakeClock is a clock tests move by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// lastLine is what's on screen now: the text after the last "clear the line".
func lastLine(out string) string {
	i := strings.LastIndex(out, "\r\033[K")
	if i < 0 {
		return out
	}
	return out[i+len("\r\033[K"):]
}

func TestLiveStatusLine(t *testing.T) {
	var buf bytes.Buffer
	clock := &fakeClock{t: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	l := newLiveStatus(&buf, clock.now)

	l.event(engine.Event{Kind: engine.DiscoveryStarted})
	if got := lastLine(buf.String()); got != "  0% ░░░░░░░░░░░░░░░░░░░░  Starting Nmap" {
		t.Errorf("start: %q", got)
	}

	clock.add(20 * time.Second)
	l.event(engine.Event{Kind: engine.ScanProgress, Progress: engine.ScannerProgress{Task: "Service scan", Percent: 0}})
	if got := lastLine(buf.String()); got != " 46% █████████░░░░░░░░░░░  Identifying services, about 25s left" {
		t.Errorf("service scan: %q", got)
	}

	// Nothing new from Nmap, but the time left still counts down.
	before := strings.Count(buf.String(), "\r")
	clock.add(10 * time.Second)
	l.mu.Lock()
	l.draw()
	l.draw() // the same line twice is drawn once
	l.mu.Unlock()
	if got := lastLine(buf.String()); !strings.HasSuffix(got, "about 15s left") {
		t.Errorf("countdown: %q", got)
	}
	if n := strings.Count(buf.String(), "\r") - before; n != 1 {
		t.Errorf("drew %d times, want 1", n)
	}

	l.event(engine.Event{Kind: engine.ChecksStarted, Count: 2})
	l.event(engine.Event{Kind: engine.CheckDone})
	if got := lastLine(buf.String()); !strings.Contains(got, "Running checks, 1 of 2 done") {
		t.Errorf("checks: %q", got)
	}

	go l.tick(time.Millisecond)
	time.Sleep(20 * time.Millisecond) // let the ticker redraw a few times
	l.finish()
	if !strings.HasSuffix(buf.String(), "\r\033[K") {
		t.Errorf("finish should leave an empty line: %q", buf.String()[max(0, buf.Len()-40):])
	}
	if strings.Contains(buf.String(), "\n") {
		t.Error("the live line must never move down")
	}
}

func TestScanWithLiveProgress(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	app.LiveProgress = true
	if code := app.Run(context.Background(), []string{"scan", "192.168.1.0/30"}); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out.String(), "telnet-open") {
		t.Error("the report goes to stdout as usual")
	}
	e := errOut.String()
	if !strings.Contains(e, "\r\033[K") || !strings.Contains(e, "Scanned in ") || strings.Contains(e, "Finding hosts and open ports with Nmap") {
		t.Errorf("stderr should be the live line, then how long it took: %q", e)
	}

	// A scan that can't run clears the line and only shows the error.
	app, _, errOut = newApp(t, &fakeRunner{err: os.ErrNotExist})
	app.LiveProgress = true
	if code := app.Run(context.Background(), []string{"scan", "10.0.0.1"}); code != ExitError {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(errOut.String(), "Scanned in") || !strings.Contains(errOut.String(), "error:") {
		t.Errorf("failed scan stderr: %q", errOut.String())
	}
}
