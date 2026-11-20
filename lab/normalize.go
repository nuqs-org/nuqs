// Command normalize validates and fixes the two timestamps in a Nuqs JSON report,
// and drops Nmap's product guess for the Telnet server, which changes between runs.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nuqs-org/nuqs/internal/model"
)

// telnetEvidence replaces the telnet-open evidence. Nmap names the lab's
// BusyBox telnetd ("BusyBox telnetd 1.14.0 or later") on some runs and just
// "telnet" on others, and the evidence includes that name.
const telnetEvidence = "(Nmap's name for the Telnet server changes between runs)"

func main() {
	if err := normalize(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func normalize(input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(input)
	if err != nil {
		return err
	}
	// Preserve all report fields, including fields added in future releases.
	var report map[string]json.RawMessage
	if err := json.Unmarshal(data, &report); err != nil {
		return err
	}
	var started, finished time.Time
	if err := json.Unmarshal(report["started"], &started); err != nil {
		return fmt.Errorf("started: %w", err)
	}
	if err := json.Unmarshal(report["finished"], &finished); err != nil {
		return fmt.Errorf("finished: %w", err)
	}
	if started.IsZero() || finished.Before(started) {
		return errors.New("invalid report time interval")
	}
	report["started"] = json.RawMessage(`"2000-01-01T00:00:00Z"`)
	report["finished"] = json.RawMessage(`"2000-01-01T00:00:01Z"`)
	if err := forgetTelnetName(report); err != nil {
		return err
	}
	enc := json.NewEncoder(output)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// forgetTelnetName drops what Nmap guessed about the Telnet server's product
// and version, so the comparison is the same on every run.
func forgetTelnetName(report map[string]json.RawMessage) error {
	var hosts []model.Host
	if err := json.Unmarshal(report["hosts"], &hosts); err != nil {
		return fmt.Errorf("hosts: %w", err)
	}
	for i := range hosts {
		for j := range hosts[i].Services {
			if s := &hosts[i].Services[j]; s.Name == "telnet" {
				s.Product, s.Version = "", ""
			}
		}
	}
	var findings []model.Finding
	if err := json.Unmarshal(report["findings"], &findings); err != nil {
		return fmt.Errorf("findings: %w", err)
	}
	for i := range findings {
		if findings[i].CheckID == "telnet-open" {
			findings[i].Evidence = telnetEvidence
		}
	}
	var err error
	if report["hosts"], err = json.Marshal(hosts); err != nil {
		return err
	}
	report["findings"], err = json.Marshal(findings)
	return err
}
