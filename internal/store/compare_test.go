// Tests picking the scan to compare with and when findings were first seen.

package store

import (
	"errors"
	"testing"
	"time"
)

// save stores a finished scan of targets with these port settings, started
// the given number of hours after at.
func save(t *testing.T, s *Store, targets []string, settings, status, errMsg string, hours int) int64 {
	t.Helper()
	rep := sampleReport()
	rep.Targets = targets
	started := at.Add(time.Duration(hours) * time.Hour)
	r := Run{Name: "x", Kind: "cli", Settings: settings, Targets: targets, Status: status, Error: errMsg,
		Started: started, Finished: started.Add(time.Minute), Report: rep}
	if err := s.Save(&r); err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestPrevious(t *testing.T) {
	s, _ := open(t)
	ab := []string{"10.0.0.1", "10.0.0.2"}
	first := save(t, s, ab, `{"ports":"22,23"}`, Completed, "", 0)
	save(t, s, ab, `{"ports":"22"}`, Completed, "", 1)                      // other ports
	save(t, s, []string{"10.0.0.1"}, `{"ports":"22,23"}`, Completed, "", 2) // other targets
	save(t, s, ab, `{"ports":"22,23"}`, Stopped, "", 3)                     // stopped early
	save(t, s, ab, `{"ports":"22,23"}`, Completed, "nmap died", 4)          // finished with an error
	last := save(t, s, []string{"10.0.0.2", "10.0.0.1"}, `{"ports":"22, 23"}`, Completed, "", 5)

	prev, err := s.Previous(last)
	if err != nil || prev.ID != first || prev.Report == nil {
		t.Fatalf("previous of %d: got %d, %v, want %d", last, prev.ID, err, first)
	}
	if _, err := s.Previous(first); !errors.Is(err, ErrNotFound) {
		t.Errorf("the first scan has nothing before it: %v", err)
	}
	if _, err := s.Previous(99); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown scan: %v", err)
	}
}

func TestSameScope(t *testing.T) {
	a := Run{Targets: []string{"10.0.0.1"}, Settings: `{"ports":"","top_ports":100}`}
	cases := []struct {
		name string
		b    Run
		want bool
	}{
		{"same", Run{Targets: []string{"10.0.0.1"}, Settings: `{"top_ports":100,"skip_ping":true}`}, true},
		{"other top ports", Run{Targets: []string{"10.0.0.1"}, Settings: `{"top_ports":1000}`}, false},
		{"other targets", Run{Targets: []string{"10.0.0.2"}, Settings: `{"top_ports":100}`}, false},
		{"defaults", Run{Targets: []string{"10.0.0.1"}}, false},
	}
	for _, c := range cases {
		if got := SameScope(a, c.b); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	if !SameScope(Run{Settings: "not json"}, Run{Settings: "{}"}) {
		t.Error("broken settings should count as the defaults")
	}
}

func TestSeen(t *testing.T) {
	s, _ := open(t)
	ab := []string{"10.0.0.1", "10.0.0.2"}
	save(t, s, ab, "{}", Completed, "", 2)
	save(t, s, ab, "{}", Completed, "", 0) // saved later, but started earlier
	seen, err := s.Seen([]string{"x", "y", "nope"})
	if err != nil {
		t.Fatal(err)
	}
	later := at.Add(2 * time.Hour)
	if len(seen) != 2 || !seen["x"].First.Equal(at) || !seen["y"].Last.Equal(later) {
		t.Errorf("seen: %v", seen)
	}
	if seen, err := s.Seen(nil); err != nil || len(seen) != 0 {
		t.Errorf("no IDs: %v %v", seen, err)
	}
}
