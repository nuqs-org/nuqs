// Package progress turns scan events into one steady progress estimate,
// so the CLI and the web UI show the same percent, step and time left.
//
// Nmap reports each of its steps from 0 to 100% on its own (ping, port scan,
// service detection), and then the checks run. Shown as they are, the numbers
// jump back to 0 at every step and say nothing about the whole scan. So:
//
//   - Nmap gets 85% of the bar and the checks the last 15%, because on most
//     scans Nmap is where the time goes.
//   - Inside Nmap's part, each step gets its own slice: finding live hosts
//     the first 8%, host names up to 10%, port scanning up to 55% and
//     service detection the rest.
//   - On bigger networks Nmap works through the hosts in batches, and its
//     steps start again from 0% for each batch. We can't know how many
//     batches are left, so each new batch fills half of what's left of
//     Nmap's part. The bar keeps moving, just slower, instead of stalling.
//   - The bar never goes backwards, and stays below 100% until the scan is done.
//   - Time left comes from how fast the bar has moved so far, smoothed so it
//     doesn't jump around, and it counts down between updates.
package progress

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
)

// nmapShare is how much of the bar Nmap gets, the checks get the rest.
const nmapShare = 0.85

// step is one of Nmap's steps and the slice of Nmap's part it covers.
type step struct {
	match  string // matched against Nmap's task name, lower case
	name   string // what we show
	lo, hi float64
}

// steps is checked in order, so "service scan" comes before plain "scan".
var steps = []step{
	{"ping", "Finding live hosts", 0, 0.08},
	{"dns", "Looking up host names", 0.08, 0.10},
	{"service scan", "Identifying services", 0.55, 1},
	{"scan", "Scanning ports", 0.10, 0.55},
}

// Tracker follows one scan. Feed it every event with Add. It's not safe for
// use from more than one goroutine at a time, callers lock around it.
type Tracker struct {
	started     time.Time
	nmap        float64 // how far Nmap is, 0 to 1
	lastStep    int     // index in steps of the last step Nmap was on, to spot a new batch
	batchFrom   float64 // where the current batch starts in Nmap's part
	batchSize   float64 // how much of Nmap's part the current batch can fill
	checksDone  int
	checksTotal int
	checking    bool
	done        bool
	step        string
	shown       float64 // the highest overall fraction so far

	eta    time.Duration // time left when it was last worked out
	etaAt  time.Time     // when that was
	hasETA bool
}

// New starts tracking a scan that started at now.
func New(now time.Time) *Tracker {
	return &Tracker{started: now, step: "Starting Nmap", lastStep: -1, batchSize: 1}
}

// Add takes one scan event, at time now.
func (t *Tracker) Add(ev engine.Event, now time.Time) {
	switch ev.Kind {
	case engine.ScanProgress:
		task := strings.ToLower(ev.Progress.Task)
		for i, s := range steps {
			if !strings.Contains(task, s.match) {
				continue
			}
			if t.lastStep >= 0 && s.lo < steps[t.lastStep].lo {
				// An earlier step again: Nmap moved on to the next batch of hosts.
				t.batchFrom = t.nmap
				t.batchSize = (1 - t.nmap) / 2
			}
			t.lastStep = i
			pct := math.Min(math.Max(ev.Progress.Percent, 0), 100)
			inBatch := s.lo + (s.hi-s.lo)*pct/100
			t.nmap = math.Max(t.nmap, t.batchFrom+t.batchSize*inBatch)
			t.step = s.name
			break
		}
	case engine.DiscoveryDone:
		t.nmap = 1
		t.step = "Found " + plural(ev.Count, "live host", "live hosts")
	case engine.ChecksStarted:
		t.nmap = 1
		t.checking = true
		t.checksTotal = ev.Count
		t.step = "Running checks"
	case engine.CheckDone:
		t.checksDone++
	case engine.ScanDone:
		t.done = true
		t.step = "Writing the report"
	default:
		return
	}
	if t.checking && t.checksTotal > 0 && !t.done {
		t.step = fmt.Sprintf("Running checks, %d of %d done", t.checksDone, t.checksTotal)
	}
	t.update(now)
}

// update works out the new overall fraction and time left.
func (t *Tracker) update(now time.Time) {
	checks := 0.0
	switch {
	case t.done || (t.checking && t.checksTotal == 0):
		checks = 1
	case t.checksTotal > 0:
		checks = float64(t.checksDone) / float64(t.checksTotal)
	}
	f := nmapShare*t.nmap + (1-nmapShare)*checks
	if !t.done {
		f = math.Min(f, 0.99)
	} else {
		f = 1
	}
	t.shown = math.Max(t.shown, f)

	// Guess the time left from the speed so far, once there's enough to go on.
	elapsed := now.Sub(t.started)
	if t.done || t.shown < 0.03 || elapsed < 2*time.Second {
		return
	}
	guess := time.Duration(float64(elapsed) * (1 - t.shown) / t.shown)
	if t.hasETA {
		// Blend with the old guess, counted down to now, so it moves smoothly.
		guess = time.Duration(0.7*float64(t.left(now)) + 0.3*float64(guess))
	}
	t.eta, t.etaAt, t.hasETA = guess, now, true
}

// left is the last time-left guess, counted down to now.
func (t *Tracker) left(now time.Time) time.Duration {
	return max(t.eta-now.Sub(t.etaAt), 0)
}

// Percent is how far the whole scan is, 0 to 100. It never goes down.
func (t *Tracker) Percent() float64 { return t.shown * 100 }

// Step is what the scan is doing right now, in plain words.
func (t *Tracker) Step() string { return t.step }

// Remaining is the time left in plain words, like "about 40s left". It's
// empty while there isn't enough to go on yet.
func (t *Tracker) Remaining(now time.Time) string {
	if t.done || !t.hasETA {
		return ""
	}
	return Words(t.left(now))
}

// Words says a time left the way people read it, rounded so it doesn't
// flicker: "almost done", "about 40s left", "about 3 min left".
func Words(d time.Duration) string {
	switch {
	case d < 5*time.Second:
		return "almost done"
	case d < time.Minute:
		return fmt.Sprintf("about %ds left", int(d.Seconds()+4)/5*5) // nearest 5s
	case d < 90*time.Minute:
		return fmt.Sprintf("about %d min left", int(math.Round(d.Minutes())))
	default:
		return fmt.Sprintf("about %.0f hours left", math.Round(d.Hours()))
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
