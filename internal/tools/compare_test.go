// Tests comparing two saved scans and the notes about less certain comparisons.

package tools

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/store"
)

func saveRun(t *testing.T, st *store.Store, status, settings string, withReport bool, findings ...model.Finding) int64 {
	t.Helper()
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	r := store.Run{Name: "x", Kind: "cli", Settings: settings, Targets: []string{"10.0.0.1"}, Status: status, Started: at, Finished: at}
	if withReport {
		r.Report = &engine.Report{Targets: r.Targets, Started: at, Finished: at,
			Hosts: []model.Host{{Address: "10.0.0.1"}}, Findings: findings}
	}
	var err error
	if withReport {
		err = st.Save(&r)
	} else {
		err = st.Create(&r)
	}
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestCompare(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	telnet := model.Finding{ID: model.FindingID("10.0.0.1", "telnet-open", 23, "tcp"), CheckID: "telnet-open", Host: "10.0.0.1", Port: 23, Protocol: "tcp"}

	first := saveRun(t, st, store.Completed, `{"ports":"23"}`, true, telnet)
	if _, err := Compare(st, 0, first); !errors.Is(err, ErrNoEarlierScan) {
		t.Errorf("nothing before the first scan: %v", err)
	}
	second := saveRun(t, st, store.Completed, `{"ports":"23"}`, true)
	d, err := Compare(st, 0, second)
	if err != nil || d.Old.ID != first || d.New.ID != second || len(d.Fixed) != 1 || len(d.Notes) != 0 || d.Fixed[0].LastSeen.IsZero() {
		t.Fatalf("compare with the last scan: %v %+v", err, d)
	}

	for _, old := range []int64{second, second + 1} {
		if _, err := Compare(st, old, second); !errors.Is(err, ErrNotOlder) {
			t.Errorf("old %d against %d should be refused: %v", old, second, err)
		}
	}

	stopped := saveRun(t, st, store.Stopped, `{"ports":"22"}`, true)
	d, err = Compare(st, first, stopped)
	if err != nil || len(d.Notes) != 2 || !strings.Contains(d.Notes[0], "didn't finish cleanly (stopped)") ||
		!strings.Contains(d.Notes[1], "same targets and ports") {
		t.Errorf("notes: %v %q", err, d.Notes)
	}

	running := saveRun(t, st, store.Running, "{}", false)
	for _, old := range []int64{0, first} {
		if _, err := Compare(st, old, running); !errors.Is(err, ErrNoReport) {
			t.Errorf("a running scan has no report (old %d): %v", old, err)
		}
	}
	for _, ids := range [][2]int64{{0, 99}, {first, 99}} {
		if _, err := Compare(st, ids[0], ids[1]); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v: %v", ids, err)
		}
	}
}
