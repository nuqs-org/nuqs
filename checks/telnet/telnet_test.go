// Tests the Telnet check.

package telnet

import (
	"context"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

func TestInfo(t *testing.T) {
	if err := check.Validate([]check.Check{Check{}}); err != nil {
		t.Fatal(err)
	}
	in := Check{}.Info()
	if !check.Applies(in, model.Service{Port: 2323, Name: "telnet"}) {
		t.Error("should apply to any service Nmap calls telnet")
	}
	if check.Applies(in, model.Service{Port: 23, Name: "ssh"}) {
		t.Error("should not apply to SSH just because it runs on port 23")
	}
}

func TestRunWithProduct(t *testing.T) {
	res, err := Check{}.Run(context.Background(), check.Target{Host: "10.0.0.1", Service: model.Service{Port: 23, Protocol: "tcp", Name: "telnet", Product: "BusyBox telnetd", Version: "1.36"}})
	if err != nil || res == nil {
		t.Fatalf("expected a finding, got %v, %v", res, err)
	}
	if res.Evidence != "port 23/tcp is open and Nmap identified it as BusyBox telnetd 1.36" {
		t.Errorf("unexpected evidence: %q", res.Evidence)
	}
}

func TestRunWithoutProduct(t *testing.T) {
	res, err := Check{}.Run(context.Background(), check.Target{Host: "10.0.0.1", Service: model.Service{Port: 23, Protocol: "tcp", Name: "telnet"}})
	if err != nil || res == nil || !strings.HasSuffix(res.Evidence, "as a Telnet server") {
		t.Errorf("unexpected result: %+v, %v", res, err)
	}
}

func TestRunGuessed(t *testing.T) {
	res, err := Check{}.Run(context.Background(), check.Target{Host: "10.0.0.1", Service: model.Service{Port: 23, Protocol: "tcp", Name: "telnet", Guessed: true}})
	if err != nil || res == nil {
		t.Fatalf("expected a finding, got %v, %v", res, err)
	}
	if res.Confidence != model.Inferred {
		t.Errorf("a guessed service must be inferred, got %q", res.Confidence)
	}
	if !strings.Contains(res.Evidence, "guessed Telnet from the port number") {
		t.Errorf("evidence should say it was guessed: %q", res.Evidence)
	}
}

func TestRunProbedIsConfirmed(t *testing.T) {
	res, _ := Check{}.Run(context.Background(), check.Target{Host: "10.0.0.1", Service: model.Service{Port: 23, Protocol: "tcp", Name: "telnet"}})
	if res.Confidence != "" {
		t.Errorf("a probed service should leave confidence empty (confirmed), got %q", res.Confidence)
	}
}
