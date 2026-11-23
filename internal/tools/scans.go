// Runs the scans started from the web UI in the background, keeps the recent
// ones in memory and saves every one to the store.

package tools

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/progress"
	"github.com/nuqs-org/nuqs/internal/store"
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
	case "cli":
		return "Command line scan"
	default:
		return "Custom scan"
	}
}

// Scans runs scans in the background. The last few stay in memory for fast
// pages and live progress. With a Store, every scan is also saved, so it's
// still there after a restart, and older ones load from the store on demand.
type Scans struct {
	Service *Service
	// Store saves scans. Nil keeps them in memory only, like in tests.
	Store *store.Store
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
	started := time.Now()
	id, err := m.newID(name, in, valid, started)
	if err != nil {
		return Scan{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{
		scan: Scan{
			ID:          id,
			Name:        name,
			Description: strings.TrimSpace(in.Description),
			Kind:        in.Kind,
			Settings:    in.Settings,
			Targets:     valid.Targets,
			Status:      ScanRunning,
			Phase:       "Starting Nmap",
			Started:     started,
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

// newID saves the new scan to get its ID, or counts up without a store.
// Callers hold m.mu.
func (m *Scans) newID(name string, in NewScan, valid ValidatedScan, started time.Time) (string, error) {
	if m.Store == nil {
		m.nextID++
		return strconv.Itoa(m.nextID), nil
	}
	settings, _ := json.Marshal(in.Settings) // plain strings and numbers, can't fail
	r := store.Run{Name: name, Description: strings.TrimSpace(in.Description), Kind: in.Kind,
		Settings: string(settings), Targets: valid.Targets, Status: store.Running, Started: started}
	if err := m.Store.Create(&r); err != nil {
		return "", fmt.Errorf("couldn't save the scan: %w", err)
	}
	return strconv.FormatInt(r.ID, 10), nil
}

// trim forgets the oldest finished scans past Keep. Callers hold m.mu.
func (m *Scans) trim() {
	keep := m.keep()
	for i := len(m.list) - 1; i >= 0 && len(m.list) > keep; i-- {
		if m.list[i].scan.Status != ScanRunning {
			m.list = append(m.list[:i], m.list[i+1:]...)
		}
	}
}

func (m *Scans) keep() int {
	if m.Keep <= 0 {
		return 50
	}
	return m.Keep
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
	// Work out how it ended once, save that, then show it. Saving first
	// means anyone who sees the scan finish can also find it in the store,
	// and the store and the page can't disagree. No events come after
	// RunValidated returns, so nothing else changes the scan meanwhile.
	m.mu.Lock()
	done := e.scan
	m.mu.Unlock()
	done.Finished = time.Now()
	done.Report = rep
	done.Phase, done.Remaining = "", ""
	if rep != nil {
		done.Percent = 100
	}
	switch {
	case ctx.Err() != nil:
		done.Status = ScanStopped
	case rep == nil:
		done.Status = ScanFailed
		done.Error = FriendlyError(err)
	default:
		done.Status = ScanCompleted
		if err != nil {
			done.Error = FriendlyError(err)
		}
	}
	if saveErr := m.save(done); saveErr != nil {
		done.Error = strings.TrimSpace(done.Error + " This scan couldn't be saved (" + saveErr.Error() + "), so it'll be gone after a restart.")
	}
	m.update(e, func(s *Scan) { *s = done })
}

// save writes a finished scan to the store, if there is one.
func (m *Scans) save(s Scan) error {
	if m.Store == nil {
		return nil
	}
	id, _ := strconv.ParseInt(s.ID, 10, 64)
	return m.Store.Finish(store.Run{ID: id, Status: string(s.Status), Error: s.Error, Finished: s.Finished, Report: s.Report})
}

// Load marks scans a crashed server left running as stopped, then fills
// the memory with the newest saved scans. "nuqs serve" calls it once at start.
func (m *Scans) Load() error {
	if m.Store == nil {
		return nil
	}
	if err := m.Store.CloseUnfinished(); err != nil {
		return err
	}
	return m.sync()
}

// sync makes the memory match the newest saved scans, adding ones it
// doesn't have yet, like ones "nuqs scan" saved while the server runs. That
// way the web UI and the CLI show the same list.
func (m *Scans) sync() error {
	if m.Store == nil {
		return nil
	}
	runs, err := m.Store.Runs(m.keep())
	if err != nil {
		return err
	}
	m.mu.Lock()
	have := map[string]*entry{}
	for _, e := range m.list {
		have[e.scan.ID] = e
	}
	m.mu.Unlock()
	loaded := map[string]*entry{}
	for _, sum := range runs {
		id := strconv.FormatInt(sum.ID, 10)
		// Skip what we have, and a scan another server is still running.
		if have[id] != nil || sum.Status == store.Running {
			continue
		}
		r, err := m.Store.Run(sum.ID)
		if err != nil {
			return err
		}
		loaded[id] = &entry{scan: fromRun(r), cancel: func() {}, changed: make(chan struct{})}
	}
	// Rebuild under the lock from the memory as it is now, not the copy from
	// before loading: a scan may have started meanwhile, and dropping it
	// would cut its page off from progress and Stop.
	m.mu.Lock()
	defer m.mu.Unlock()
	current := map[string]*entry{}
	for _, e := range m.list {
		current[e.scan.ID] = e
	}
	list := make([]*entry, 0, len(runs)+1)
	for _, e := range m.list {
		if e.scan.Status == ScanRunning {
			list = append(list, e) // ours, the newest, never dropped
		}
	}
	for _, sum := range runs {
		id := strconv.FormatInt(sum.ID, 10)
		if e := cmp.Or(current[id], loaded[id]); e != nil && e.scan.Status != ScanRunning {
			list = append(list, e)
		}
	}
	m.list = list
	return nil
}

// fromRun turns a saved run back into a scan.
func fromRun(r store.Run) Scan {
	s := Scan{
		ID:          strconv.FormatInt(r.ID, 10),
		Name:        r.Name,
		Description: r.Description,
		Kind:        r.Kind,
		Targets:     r.Targets,
		Status:      ScanStatus(r.Status),
		Started:     r.Started,
		Finished:    r.Finished,
		Error:       r.Error,
		Report:      r.Report,
	}
	_ = json.Unmarshal([]byte(r.Settings), &s.Settings) // a scan from "nuqs scan" has no web settings
	if r.Report != nil {
		s.Percent = 100
		s.HostsFound = len(r.Report.Hosts)
	}
	return s
}

// update changes a scan under the lock and wakes anyone watching it.
func (m *Scans) update(e *entry, change func(*Scan)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	change(&e.scan)
	close(e.changed)
	e.changed = make(chan struct{})
}

// List returns the newest scans, newest first. With a store that includes
// scans the CLI saved since the server started.
func (m *Scans) List() []Scan {
	_ = m.sync() // if the store can't be read, the scans in memory still show
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
// time it changes. That's how the live page knows when to update. A scan
// that's only in the store is finished, so it never changes.
func (m *Scans) Watch(id string) (Scan, <-chan struct{}, bool) {
	m.mu.Lock()
	for _, e := range m.list {
		if e.scan.ID == id {
			defer m.mu.Unlock()
			return e.snapshot(), e.changed, true
		}
	}
	m.mu.Unlock()
	return m.saved(id)
}

// saved loads an older scan that's no longer in memory.
func (m *Scans) saved(id string) (Scan, <-chan struct{}, bool) {
	n, err := strconv.ParseInt(id, 10, 64)
	if m.Store == nil || err != nil {
		return Scan{}, nil, false
	}
	r, err := m.Store.Run(n)
	if err != nil {
		return Scan{}, nil, false
	}
	return fromRun(r), make(chan struct{}), true
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
	if _, _, ok := m.saved(id); ok {
		return nil // a saved scan is already done
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
