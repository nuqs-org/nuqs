// Package model holds the small set of types that every part of Nuqs shares.
//
// A scan finds hosts, each host has services (open ports), and checks turn
// services into findings. Nothing in here does any work, it only describes data.
package model

import (
	"fmt"
	"strings"
)

// Severity says how bad a finding is.
type Severity int

// Severity levels, lowest first.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

// String returns the lowercase name, for example "high".
func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity turns a name like "High" or "high" back into a Severity.
func ParseSeverity(name string) (Severity, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	for i, v := range severityNames {
		if v == n {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q", name)
}

// MarshalText writes the severity as its name, so JSON shows "high" and not 3.
func (s Severity) MarshalText() ([]byte, error) {
	if s < Info || s > Critical {
		return nil, fmt.Errorf("invalid severity %d", int(s))
	}
	return []byte(s.String()), nil
}

// UnmarshalText reads a severity name back.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Confidence says how sure we are that a finding is real.
type Confidence string

// The two confidence levels.
const (
	// Confirmed means we saw the problem ourselves, like a login that worked.
	Confirmed Confidence = "confirmed"
	// Inferred means we only know it from a version number, or Nmap only
	// guessed the service from the port. Either way it may not be real.
	Inferred Confidence = "inferred"
)

// Valid reports whether c is Confirmed or Inferred.
func (c Confidence) Valid() bool { return c == Confirmed || c == Inferred }

// UnmarshalText reads a confidence back and refuses unknown values, so a
// broken saved report fails loudly.
func (c *Confidence) UnmarshalText(b []byte) error {
	v := Confidence(b)
	if !v.Valid() {
		return fmt.Errorf("unknown confidence %q", string(b))
	}
	*c = v
	return nil
}

// Service is one open port on a host, plus whatever Nmap could tell about it.
type Service struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`          // "tcp" or "udp"
	Name     string `json:"name,omitempty"`    // what Nmap thinks it is, like "http" or "ftp"
	Product  string `json:"product,omitempty"` // like "OpenSSH"
	Version  string `json:"version,omitempty"` // like "9.6p1"
	Tunnel   string `json:"tunnel,omitempty"`  // "ssl" when the service runs over TLS
	// Guessed is true when Nmap couldn't recognise the service and only
	// named it from the port number, like "telnet" for anything on port 23.
	Guessed bool `json:"guessed,omitempty"`
}

// Host is one machine that answered during the scan.
type Host struct {
	Address   string    `json:"address"`
	Hostnames []string  `json:"hostnames,omitempty"`
	Services  []Service `json:"services,omitempty"`
}

// Finding is one problem that a check found on a service.
type Finding struct {
	ID         string     `json:"id"`
	CheckID    string     `json:"check_id"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Protocol   string     `json:"protocol"`
	Evidence   string     `json:"evidence"` // what we actually saw, so people can trust it
	Fix        string     `json:"fix"`
}

// FindingID builds a stable ID for a finding. The same problem on the same
// host and port always gets the same ID, which lets us compare scans later.
func FindingID(host, checkID string, port int, protocol string) string {
	return fmt.Sprintf("%s|%s|%d/%s", checkID, host, port, protocol)
}
