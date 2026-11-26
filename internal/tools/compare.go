// Comparing two saved scans, shared by "nuqs diff" and GET /api/scans/{id}/diff.

package tools

import (
	"errors"
	"fmt"
	"time"

	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/store"
)

// Why two scans can't be compared.
var (
	ErrNoEarlierScan = errors.New("there's no earlier finished scan of the same targets and ports")
	ErrNoReport      = errors.New("there's no report to compare")
	ErrNotOlder      = errors.New("the scan to compare with has to be older")
)

// Compare says what changed from the saved scan old to the saved scan cur.
// With old 0 it picks the last clean scan of the same targets and ports.
// The result's Notes say when the comparison is less certain, like two scans
// of different ports. A scan that isn't saved gives ErrNotFound, and an old
// scan that isn't older than cur gives ErrNotOlder, so new and fixed never
// come out the wrong way round.
func Compare(st *store.Store, old, cur int64) (diff.Result, error) {
	if old != 0 && old >= cur {
		return diff.Result{}, ErrNotOlder
	}
	newer, err := st.Run(cur)
	var older store.Run
	switch {
	case err != nil:
	case newer.Report == nil:
		return diff.Result{}, fmt.Errorf("scan %d %s without a report: %w", newer.ID, newer.Status, ErrNoReport)
	case old == 0:
		older, err = st.Previous(cur)
		if errors.Is(err, store.ErrNotFound) {
			return diff.Result{}, ErrNoEarlierScan
		}
	default:
		older, err = st.Run(old)
	}
	if errors.Is(err, store.ErrNotFound) {
		return diff.Result{}, ErrNotFound
	}
	if err != nil {
		return diff.Result{}, err
	}

	var notes []string
	for _, r := range []store.Run{older, newer} {
		if r.Report == nil {
			return diff.Result{}, fmt.Errorf("scan %d %s without a report: %w", r.ID, r.Status, ErrNoReport)
		}
		if r.Status != store.Completed || r.Error != "" {
			why := r.Status
			if r.Error != "" {
				why = r.Error
			}
			notes = append(notes, fmt.Sprintf("scan %d didn't finish cleanly (%s), so it may have missed findings", r.ID, why))
		}
	}
	if !store.SameScope(older, newer) {
		notes = append(notes, "these scans didn't cover the same targets and ports, so some findings may show as new or fixed only because of that")
	}

	d := diff.Compare(older.Report, newer.Report)
	d.Old.ID, d.New.ID = older.ID, newer.ID
	d.Notes = notes
	seen, err := st.Seen(d.IDs())
	if err != nil {
		return diff.Result{}, err
	}
	d.SetSeen(func(id string) (time.Time, time.Time) { return seen[id].First, seen[id].Last })
	return d, nil
}
