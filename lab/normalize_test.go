// Tests the timestamp normalization used by the lab report comparison.

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestNormalizePreservesReport(t *testing.T) {
	want, err := os.ReadFile("expected-report.json")
	if err != nil {
		t.Fatal(err)
	}
	// Use the reviewed report with a different run interval as input.
	input := strings.NewReplacer(
		"2000-01-01T00:00:00Z", "2026-11-20T08:00:00Z",
		"2000-01-01T00:00:01Z", "2026-11-20T08:00:05Z",
	).Replace(string(want))
	var got bytes.Buffer
	if err := normalize(strings.NewReader(input), &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("normalized report differs from expected-report.json:\n%s", &got)
	}
}

func TestNormalizeRejectsReversedInterval(t *testing.T) {
	const input = `{"started":"2026-11-20T08:00:05Z","finished":"2026-11-20T08:00:00Z"}`
	if err := normalize(strings.NewReader(input), io.Discard); err == nil {
		t.Fatal("expected an error when the scan finishes before it starts")
	}
}

func TestNormalizeDropsTelnetName(t *testing.T) {
	want, err := os.ReadFile("expected-report.json")
	if err != nil {
		t.Fatal(err)
	}
	// The same report as a run where Nmap named BusyBox.
	input := strings.NewReplacer(
		`"name": "telnet"`, `"name": "telnet", "product": "BusyBox telnetd", "version": "1.14.0 or later"`,
		telnetEvidence, "port 12323/tcp is open and Nmap identified it as BusyBox telnetd 1.14.0 or later",
	).Replace(string(want))
	if input == string(want) {
		t.Fatal("the replacements didn't change anything, update this test")
	}
	var got bytes.Buffer
	if err := normalize(strings.NewReader(input), &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("Nmap's Telnet name should be dropped:\n%s", &got)
	}
}
