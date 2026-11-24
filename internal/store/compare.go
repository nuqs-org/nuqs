// Finding the scan to compare a run with, and when each finding was first and last seen.

package store

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Previous returns the newest finished scan before run id with the same
// targets and ports, the one "since last scan" compares against. It skips
// scans that stopped early or failed, since everything they missed would
// look fixed. ErrNotFound means there's no such scan yet.
func (s *Store) Previous(id int64) (Run, error) {
	cur, err := s.Run(id)
	if err != nil {
		return Run{}, err
	}
	rows, err := s.db.Query(`SELECT id, targets, settings FROM runs
		WHERE id < ? AND status = ? AND error = '' AND has_report = 1 ORDER BY id DESC`, id, Completed)
	if err != nil {
		return Run{}, fmt.Errorf("find previous scan: %w", err)
	}
	match := int64(0)
	for rows.Next() {
		var r Run
		var targets string
		if err := rows.Scan(&r.ID, &targets, &r.Settings); err != nil {
			_ = rows.Close()
			return Run{}, fmt.Errorf("find previous scan: %w", err)
		}
		if json.Unmarshal([]byte(targets), &r.Targets) == nil && SameScope(cur, r) {
			match = r.ID
			break
		}
	}
	if err := cmp.Or(rows.Err(), rows.Close()); err != nil {
		return Run{}, fmt.Errorf("find previous scan: %w", err)
	}
	if match == 0 {
		return Run{}, ErrNotFound
	}
	return s.Run(match)
}

// SameScope reports whether two runs scanned the same targets on the same
// ports. Only then can a finding missing from the newer one count as fixed.
func SameScope(a, b Run) bool {
	return slices.Equal(sorted(a.Targets), sorted(b.Targets)) && portsOf(a) == portsOf(b)
}

// portsOf reads the port settings, the only part of Settings the store looks
// inside. "nuqs scan" and the web UI both save them under these names.
func portsOf(r Run) string {
	var p struct {
		Ports    string `json:"ports"`
		TopPorts int    `json:"top_ports"`
	}
	_ = json.Unmarshal([]byte(r.Settings), &p) // no settings means the defaults
	return fmt.Sprintf("%s|%d", strings.ReplaceAll(p.Ports, " ", ""), p.TopPorts)
}

func sorted(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return out
}

// Seen is when a finding was found first and last, as scan start times.
type Seen struct {
	First, Last time.Time
}

// Seen returns when each of these findings was first and last found, across
// every saved scan.
func (s *Store) Seen(ids []string) (map[string]Seen, error) {
	seen := map[string]Seen{}
	if len(ids) == 0 {
		return seen, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.Query(`SELECT f.finding_id, min(r.started), max(r.started) FROM findings f JOIN runs r ON r.id = f.run_id
		WHERE f.finding_id IN (?`+strings.Repeat(", ?", len(ids)-1)+`) GROUP BY f.finding_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("seen: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var first, last int64
		if err := rows.Scan(&id, &first, &last); err != nil {
			return nil, fmt.Errorf("seen: %w", err)
		}
		seen[id] = Seen{First: fromUnix(first), Last: fromUnix(last)}
	}
	return seen, rows.Err()
}
