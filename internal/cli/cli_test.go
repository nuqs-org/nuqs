// Runs the whole CLI with a fake Nmap, so no network is needed.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/checks/telnet"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/nmap"
)

// fakeRunner returns canned Nmap XML and remembers what it was asked.
type fakeRunner struct {
	out  []byte
	err  error
	path string
	args []string
}

func (f *fakeRunner) Run(_ context.Context, args []string, out io.Writer) error {
	f.args = args
	if _, err := out.Write(f.out); err != nil {
		return err
	}
	return f.err
}

// newApp builds an App with a fake Nmap. Only the telnet check is used,
// because it needs no network, so these tests stay fast and offline.
func newApp(t *testing.T, r *fakeRunner) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	if r.out == nil && r.err == nil {
		xml, err := os.ReadFile("testdata/router.xml")
		if err != nil {
			t.Fatal(err)
		}
		r.out = xml
	}
	var out, errOut bytes.Buffer
	return &App{
		Version: "v0.0.1-test",
		Stdout:  &out,
		Stderr:  &errOut,
		NewRunner: func(path string) nmap.Runner {
			r.path = path
			return r
		},
		Checks: func() []check.Check { return []check.Check{telnet.Check{}} },
	}, &out, &errOut
}

func TestScanText(t *testing.T) {
	r := &fakeRunner{}
	app, out, errOut := newApp(t, r)
	code := app.Run(context.Background(), []string{"scan", "192.168.1.0/30"})
	if code != ExitOK {
		t.Fatalf("exit %d, stderr:\n%s", code, errOut)
	}
	for _, want := range []string{"Findings (1):", "telnet-open", "BusyBox telnetd", "Fix:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout is missing %q:\n%s", want, out)
		}
	}
	for _, want := range []string{"Finding hosts", "Found 3 hosts.", "Running 1 check...", "Done at"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("progress is missing %q:\n%s", want, errOut)
		}
	}
	if r.args[len(r.args)-1] != "192.168.1.0/30" {
		t.Errorf("target not passed to nmap: %q", r.args)
	}
}

func TestScanJSON(t *testing.T) {
	app, out, _ := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "--json", "192.168.1.1"}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	var rep engine.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout must be pure JSON (progress goes to stderr): %v\n%s", err, out)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].CheckID != "telnet-open" {
		t.Errorf("unexpected findings: %+v", rep.Findings)
	}
}

func TestFlagsAfterTargets(t *testing.T) {
	r := &fakeRunner{}
	app, _, errOut := newApp(t, r)
	code := app.Run(context.Background(), []string{"scan", "10.0.0.1", "-p", "22,23", "10.0.0.2", "-Pn", "--nmap", "/opt/nmap"})
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !slices.Contains(r.args, "22,23") || !slices.Contains(r.args, "-Pn") {
		t.Errorf("flags after targets were ignored: %q", r.args)
	}
	if r.args[len(r.args)-2] != "10.0.0.1" || r.args[len(r.args)-1] != "10.0.0.2" {
		t.Errorf("both targets should reach nmap: %q", r.args)
	}
	if r.path != "/opt/nmap" {
		t.Errorf("--nmap path not used: %q", r.path)
	}
}

func TestScanUsageErrors(t *testing.T) {
	cases := map[string][]string{
		"no targets":       {"scan"},
		"bad target":       {"scan", "not_a_host!"},
		"nmap option":      {"scan", "--", "-oN"},
		"unknown flag":     {"scan", "--nope", "10.0.0.1"},
		"bad workers":      {"scan", "--workers", "0", "10.0.0.1"},
		"bad timeout":      {"scan", "--timeout", "-1s", "10.0.0.1"},
		"too many targets": {"scan", "10.0.0.0/16"},
	}
	for name, args := range cases {
		app, out, _ := newApp(t, &fakeRunner{})
		if code := app.Run(context.Background(), args); code != ExitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, ExitUsage)
		}
		if out.Len() != 0 {
			t.Errorf("%s: nothing should be printed to stdout on usage errors", name)
		}
	}
}

func TestForceAllowsBigScans(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "--force", "10.0.0.0/16"}); code != ExitOK {
		t.Errorf("--force should allow big ranges, exit %d: %s", code, errOut)
	}
}

func TestScanHelp(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "-h"}); code != ExitOK {
		t.Errorf("scan -h exit %d", code)
	}
	if !strings.Contains(errOut.String(), "-json") {
		t.Errorf("help should list flags:\n%s", errOut)
	}
}

func TestNmapFailure(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{err: errors.New("nmap: command not found")})
	if code := app.Run(context.Background(), []string{"scan", "10.0.0.1"}); code != ExitError {
		t.Errorf("exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(errOut.String(), "command not found") || out.Len() != 0 {
		t.Errorf("the nmap error should be shown on stderr only:\nstdout=%s\nstderr=%s", out, errOut)
	}
}

func TestCancelledScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	app, _, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(ctx, []string{"scan", "10.0.0.1"}); code != ExitError {
		t.Errorf("cancelled scan exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(errOut.String(), "stopped early") {
		t.Errorf("user should be told the scan stopped early:\n%s", errOut)
	}
}

func TestOutputWriteFailure(t *testing.T) {
	app, _, _ := newApp(t, &fakeRunner{})
	app.Stdout = failWriter{}
	if code := app.Run(context.Background(), []string{"scan", "10.0.0.1"}); code != ExitError {
		t.Errorf("exit %d, want %d", code, ExitError)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestOtherCommands(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{nil, ExitUsage, "", "Usage:"},
		{[]string{"version"}, ExitOK, "nuqs v0.0.1-test", ""},
		{[]string{"--version"}, ExitOK, "nuqs v0.0.1-test", ""},
		{[]string{"help"}, ExitOK, "Usage:", ""},
		{[]string{"-h"}, ExitOK, "Usage:", ""},
		{[]string{"checks"}, ExitOK, "telnet-open", ""},
		{[]string{"bogus"}, ExitUsage, "", `unknown command "bogus"`},
	}
	for _, c := range cases {
		app, out, errOut := newApp(t, &fakeRunner{})
		if code := app.Run(context.Background(), c.args); code != c.code {
			t.Errorf("%q: exit %d, want %d", c.args, code, c.code)
		}
		if !strings.Contains(out.String(), c.inStdout) || !strings.Contains(errOut.String(), c.inStderr) {
			t.Errorf("%q: stdout=%q stderr=%q", c.args, out, errOut)
		}
	}
}

func TestPlural(t *testing.T) {
	if plural(1, "host", "hosts") != "host" || plural(0, "host", "hosts") != "hosts" || plural(2, "host", "hosts") != "hosts" {
		t.Error("plural is wrong")
	}
}
