// Package diff compares two scan reports and sorts every finding into new,
// fixed, still open, or not checked. A finding only counts as fixed when the
// newer scan looked again and didn't find it: if the host didn't answer or
// the check couldn't finish, it goes in "not checked" instead. A fixed
// finding says why: its port is no longer open, or the check passed.
package diff

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
)

// Why a finding from the older scan is in Fixed or NotChecked.
const (
	PortClosed  = "port no longer open"
	CheckPassed = "check no longer finds it"
	HostDown    = "host didn't answer"
	CheckFailed = "check couldn't finish"
)

// Scan says which scan one side of the comparison is.
type Scan struct {
	ID      int64     `json:"id,omitzero"`
	Started time.Time `json:"started"`
	Targets []string  `json:"targets"`
}

// Item is one finding in the comparison.
type Item struct {
	model.Finding
	FirstSeen time.Time `json:"first_seen,omitzero"` // the first saved scan that found it
	LastSeen  time.Time `json:"last_seen,omitzero"`  // the last saved scan that found it
	Reason    string    `json:"reason,omitempty"`    // why it's in Fixed or NotChecked
}

// Result is what changed between two scans. Each list is sorted worst first.
type Result struct {
	Old        Scan   `json:"old"`
	New        Scan   `json:"new"`
	Added      []Item `json:"new_findings"`
	Fixed      []Item `json:"fixed"`
	Open       []Item `json:"still_open"`
	NotChecked []Item `json:"not_checked"`

	// Notes say when the comparison is less certain. Compare leaves it
	// empty, the caller knows more about the two scans.
	Notes []string `json:"notes,omitempty"`
}

// Compare sorts the findings of old and new. Findings match on their ID,
// which is the same for the same check, host and port in every scan.
func Compare(old, new *engine.Report) Result {
	res := Result{
		Old: Scan{Started: old.Started, Targets: old.Targets},
		New: Scan{Started: new.Started, Targets: new.Targets},
		// Empty lists rather than null in the JSON.
		Added: []Item{}, Fixed: []Item{}, Open: []Item{}, NotChecked: []Item{},
	}
	before := map[string]bool{}
	for _, f := range old.Findings {
		before[f.ID] = true
	}
	now := map[string]bool{}
	for _, f := range new.Findings {
		now[f.ID] = true
		if before[f.ID] {
			res.Open = append(res.Open, Item{Finding: f})
		} else {
			res.Added = append(res.Added, Item{Finding: f})
		}
	}

	up := map[string]bool{}
	open := map[string]bool{} // host|port/protocol of every service the newer scan found
	for _, h := range new.Hosts {
		up[h.Address] = true
		for _, sv := range h.Services {
			open[fmt.Sprintf("%s|%d/%s", h.Address, sv.Port, sv.Protocol)] = true
		}
	}
	failed := map[string]bool{}
	for _, e := range new.Errors {
		failed[fmt.Sprintf("%s|%s|%d", e.CheckID, e.Host, e.Port)] = true
	}
	for _, f := range old.Findings {
		switch {
		case now[f.ID]:
		case !up[f.Host]:
			res.NotChecked = append(res.NotChecked, Item{Finding: f, Reason: HostDown})
		case failed[fmt.Sprintf("%s|%s|%d", f.CheckID, f.Host, f.Port)]:
			res.NotChecked = append(res.NotChecked, Item{Finding: f, Reason: CheckFailed})
		case !open[fmt.Sprintf("%s|%d/%s", f.Host, f.Port, f.Protocol)]:
			res.Fixed = append(res.Fixed, Item{Finding: f, Reason: PortClosed})
		default:
			res.Fixed = append(res.Fixed, Item{Finding: f, Reason: CheckPassed})
		}
	}
	for _, list := range [][]Item{res.Added, res.Fixed, res.Open, res.NotChecked} {
		slices.SortFunc(list, worstFirst)
	}
	return res
}

// IDs lists the IDs of every finding in the comparison, to look up when each was seen.
func (r Result) IDs() []string {
	var ids []string
	for _, list := range [][]Item{r.Added, r.Fixed, r.Open, r.NotChecked} {
		for _, it := range list {
			ids = append(ids, it.ID)
		}
	}
	return ids
}

// SetSeen fills in FirstSeen and LastSeen, asking seen for each finding ID.
func (r *Result) SetSeen(seen func(id string) (first, last time.Time)) {
	for _, list := range [][]Item{r.Added, r.Fixed, r.Open, r.NotChecked} {
		for i := range list {
			list[i].FirstSeen, list[i].LastSeen = seen(list[i].ID)
		}
	}
}

// Summary is the short version, like "2 new, 1 fixed, 5 still open".
func (r Result) Summary() string {
	s := fmt.Sprintf("%d new, %d fixed, %d still open", len(r.Added), len(r.Fixed), len(r.Open))
	if len(r.NotChecked) > 0 {
		s += fmt.Sprintf(", %d not checked", len(r.NotChecked))
	}
	return s
}

func worstFirst(a, b Item) int {
	return cmp.Or(
		cmp.Compare(b.Severity, a.Severity),
		strings.Compare(a.Host, b.Host),
		cmp.Compare(a.Port, b.Port),
		strings.Compare(a.CheckID, b.CheckID),
	)
}
