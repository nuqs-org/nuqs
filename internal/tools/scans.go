// Keeps the scans started from the web UI in memory and runs them in the background.

package tools

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/progress"
)

// ScanStatus is where a scan is in its life.
type ScanStatus string

// Scan statuses.
const (
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanStopped   ScanStatus = "stopped" // the user stopped it, Report has what was found so far
	ScanFailed    ScanStatus = "failed"  // it couldn't run at all, Error says why
)

// ErrBusy is returned when a scan is already running. We run one at a time
// so a few clicks can't start a pile of Nmap processes.
var ErrBusy = errors.New("a scan is already running, wait for it or stop it first")

// ErrNotFound is returned for a scan ID we don't have.
var ErrNotFound = errors.New("no scan with that ID")

// NewScan is what the user filled in on the new scan page.
type NewScan struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Kind        string      `json:"kind"` // quick, full or custom
	Settings    ScanRequest `json:"settings"`
}

// Scan is one scan and everything we know about it so far. Values handed
// out by Scans are copies, so callers can read them without locking.
type Scan struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Kind        string         `json:"kind"`
	Settings    ScanRequest    `json:"settings"`
	Targets     []string       `json:"targets"`
	Status      ScanStatus     `json:"status"`
	Phase       string         `json:"phase,omitempty"`     // what it's doing right now, in plain words
	Percent     float64        `json:"percent"`             // how far the whole scan is, 0 to 100, never goes down
	Remaining   string         `json:"remaining,omitempty"` // time left in plain words, like "about 40s left"
	HostsFound  int            `json:"hosts_found"`
	ChecksDone  int            `json:"checks_done"`
	ChecksTotal int            `json:"checks_total"`
	Started     time.Time      `json:"started"`
	Finished    time.Time      `json:"finished,omitzero"`
	Error       string         `json:"error,omitempty"`
	Report      *engine.Report `json:"report,omitempty"`
}

// Elapsed is how long the scan ran, or has been running.
func (s Scan) Elapsed() time.Duration {
	if s.Finished.IsZero() {
		return time.Since(s.Started)
	}
	return s.Finished.Sub(s.Started)
}

// KindName is the scan type as people read it.
func (s Scan) KindName() string {
	switch s.Kind {
	case "quick":
		return "Quick scan"
	case "full":
		return "Full scan"
	default:
		return "Custom scan"
	}
}

// Scans runs scans in the background and remembers the last few in memory.
// They're gone when the server stops, until we have a proper store.
type Scans struct {
	Service *Service
	// Keep is how many scans to remember. 0 means 50.
	Keep int

	mu     sync.Mutex
	list   []*entry // newest first
	nextID int
}

type entry struct {
	scan    Scan
	tracker *progress.Tracker // the same estimate the CLI shows
	cancel  context.CancelFunc
	changed chan struct{} // closed and replaced on every change, so watchers wake up
}

// snapshot copies the scan with its progress worked out for now, since the
// time left counts down between updates. Callers hold m.mu.
func (e *entry) snapshot() Scan {
	s := e.scan
	if s.Status == ScanRunning {
		now := time.Now()
		s.Percent = e.tracker.Percent()
		s.Phase = e.tracker.Step()
		s.Remaining = e.tracker.Remaining(now)
	}
	return s
}

// Start checks the settings and starts the scan in the background.
func (m *Scans) Start(in NewScan) (Scan, error) {
	valid, err := m.Service.ValidateScan(in.Settings)
	if err != nil {
		return Scan{}, err
	}
	switch in.Kind {
	case "quick", "full", "custom":
	default:
		return Scan{}, &ValidationError{Message: "Pick a scan type: quick, full or custom."}
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = strings.Join(valid.Targets, ", ")
	}
	if len(name) > 100 || len(in.Description) > 500 {
		return Scan{}, &ValidationError{Message: "Keep the name under 100 characters and the description under 500."}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.list {
		if e.scan.Status == ScanRunning {
			return Scan{}, ErrBusy
		}
	}
	m.nextID++
	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{
		scan: Scan{
			ID:          strconv.Itoa(m.nextID),
			Name:        name,
			Description: strings.TrimSpace(in.Description),
			Kind:        in.Kind,
			Settings:    in.Settings,
			Targets:     valid.Targets,
			Status:      ScanRunning,
			Phase:       "Starting Nmap",
			Started:     time.Now(),
		},
		cancel:  cancel,
		changed: make(chan struct{}),
	}
	e.tracker = progress.New(e.scan.Started)
	m.list = append([]*entry{e}, m.list...)
	m.trim()
	go m.run(ctx, e, valid)
	return e.snapshot(), nil
}

// trim forgets the oldest finished scans past Keep. Callers hold m.mu.
func (m *Scans) trim() {
	keep := m.Keep
	if keep <= 0 {
		keep = 50
	}
	for i := len(m.list) - 1; i >= 0 && len(m.list) > keep; i-- {
		if m.list[i].scan.Status != ScanRunning {
			m.list = append(m.list[:i], m.list[i+1:]...)
		}
	}
}

func (m *Scans) run(ctx context.Context, e *entry, valid ValidatedScan) {
	defer e.cancel()
	rep, err := m.Service.RunValidated(ctx, valid, func(ev engine.Event) {
		m.update(e, func(s *Scan) {
			e.tracker.Add(ev, time.Now())
			switch ev.Kind {
			case engine.DiscoveryDone:
				s.HostsFound = ev.Count
			case engine.ChecksStarted:
				s.ChecksTotal = ev.Count
			case engine.CheckDone:
				s.ChecksDone++
			}
		})
	})
	m.update(e, func(s *Scan) {
		s.Finished = time.Now()
		s.Report = rep
		s.Phase, s.Remaining = "", ""
		if rep != nil {
			s.Percent = 100
		}
		switch {
		case ctx.Err() != nil:
			s.Status = ScanStopped
		case rep == nil:
			s.Status = ScanFailed
			s.Error = FriendlyError(err)
		default:
			s.Status = ScanCompleted
			if err != nil {
				s.Error = FriendlyError(err)
			}
		}
	})
}

// update changes a scan under the lock and wakes anyone watching it.
func (m *Scans) update(e *entry, change func(*Scan)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	change(&e.scan)
	close(e.changed)
	e.changed = make(chan struct{})
}

// List returns every scan we remember, newest first.
func (m *Scans) List() []Scan {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Scan, len(m.list))
	for i, e := range m.list {
		out[i] = e.snapshot()
	}
	return out
}

// Get returns one scan.
func (m *Scans) Get(id string) (Scan, bool) {
	s, _, ok := m.Watch(id)
	return s, ok
}

// Watch returns the scan as it is now and a channel that's closed the next
// time it changes. That's how the live page knows when to update.
func (m *Scans) Watch(id string) (Scan, <-chan struct{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.list {
		if e.scan.ID == id {
			return e.snapshot(), e.changed, true
		}
	}
	return Scan{}, nil, false
}

// Stop stops a running scan. What it found so far is kept.
func (m *Scans) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.list {
		if e.scan.ID == id {
			if e.scan.Status == ScanRunning {
				e.cancel()
			}
			return nil
		}
	}
	return ErrNotFound
}

// StopAll stops every running scan, for when the server shuts down.
func (m *Scans) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.list {
		e.cancel()
	}
}
