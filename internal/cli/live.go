// Keeps one status line on the terminal up to date while a scan runs.

package cli

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/progress"
)

// barWidth is how many characters the progress bar takes.
const barWidth = 20

// liveStatus redraws a single line like
//
//	62% ████████████░░░░░░░░  Identifying services, about 40s left
//
// on every scan event, and once a second so the time left counts down.
// It's only used when stderr is a terminal, a log file would fill up with
// half-drawn lines.
type liveStatus struct {
	mu      sync.Mutex
	w       io.Writer
	now     func() time.Time
	tracker *progress.Tracker
	last    string // what's on screen, so we only redraw when it changes
	stop    chan struct{}
	stopped chan struct{}
}

func newLiveStatus(w io.Writer, now func() time.Time) *liveStatus {
	return &liveStatus{w: w, now: now, tracker: progress.New(now()), stop: make(chan struct{}), stopped: make(chan struct{})}
}

// event takes one scan event and redraws. It's the engine's OnEvent.
func (l *liveStatus) event(ev engine.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tracker.Add(ev, l.now())
	l.draw()
}

// tick redraws every interval until finish is called.
func (l *liveStatus) tick(interval time.Duration) {
	defer close(l.stopped)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.mu.Lock()
			l.draw()
			l.mu.Unlock()
		case <-l.stop:
			return
		}
	}
}

// draw writes the line if it changed. Callers hold l.mu.
func (l *liveStatus) draw() {
	pct := l.tracker.Percent()
	filled := int(math.Round(pct / 100 * barWidth))
	line := fmt.Sprintf("%3.0f%% %s%s  %s", math.Floor(pct), strings.Repeat("█", filled), strings.Repeat("░", barWidth-filled), l.tracker.Step())
	if left := l.tracker.Remaining(l.now()); left != "" {
		line += ", " + left
	}
	if line == l.last {
		return
	}
	l.last = line
	fmt.Fprint(l.w, "\r\033[K"+line) // back to the start of the line, clear it, draw
}

// finish stops the ticker and clears the line, so the report starts clean.
func (l *liveStatus) finish() {
	close(l.stop)
	<-l.stopped
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.w, "\r\033[K")
}
