// Tests "nuqs diff" and the "since last scan" line after a scan.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/checks/telnet"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/model"
)

// withoutTelnet is the router scan after telnet was turned off.
func withoutTelnet(t *testing.T) []byte {
	t.Helper()
	xml, err := os.ReadFile("testdata/router.xml")
	if err != nil {
		t.Fatal(err)
	}
	fixed := regexp.MustCompile(`<port protocol="tcp" portid="23">.*</port>\n`).ReplaceAll(xml, nil)
	if bytes.Equal(fixed, xml) {
		t.Fatal("testdata/router.xml has no telnet port to remove")
	}
	return fixed
}

func TestSinceLastScanAndDiff(t *testing.T) {
	r := &fakeRunner{}
	app, out, errOut := newApp(t, r)
	scan := func(args ...string) {
		t.Helper()
		errOut.Reset()
		if code := app.Run(context.Background(), append([]string{"scan"}, args...)); code != ExitOK {
			t.Fatalf("scan exit %d:\n%s", code, errOut)
		}
	}

	scan("192.168.1.0/30", "-p", "23")
	if strings.Contains(errOut.String(), "Since scan") {
		t.Errorf("the first scan has nothing to compare with:\n%s", errOut)
	}
	scan("192.168.1.0/30", "-p", "23")
	if !strings.Contains(errOut.String(), "): 0 new, 0 fixed, 1 still open. See what changed with: nuqs diff 2") {
		t.Errorf("second scan should compare with the first:\n%s", errOut)
	}
	scan("192.168.1.0/30", "-p", "22") // other ports, not compared
	if strings.Contains(errOut.String(), "Since scan") {
		t.Errorf("a scan of other ports isn't compared:\n%s", errOut)
	}
	r.out = withoutTelnet(t)
	scan("192.168.1.0/30", "-p", "23")
	if !strings.Contains(errOut.String(), "Since scan 2 (") || !strings.Contains(errOut.String(), "0 new, 1 fixed, 0 still open") {
		t.Errorf("telnet should show as fixed since scan 2:\n%s", errOut)
	}

	out.Reset()
	if code := app.Run(context.Background(), []string{"diff", "4"}); code != ExitOK {
		t.Fatalf("diff exit %d:\n%s", code, errOut)
	}
	for _, want := range []string{"Comparing scan 2 (", "with scan 4 (", "Targets: 192.168.1.0/30", "0 new, 1 fixed, 0 still open",
		"Fixed (1):", "MEDIUM", "192.168.1.1", "23/tcp", "telnet-open", "port no longer open"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("diff is missing %q:\n%s", want, out)
		}
	}

	out.Reset()
	if code := app.Run(context.Background(), []string{"diff", "1", "2"}); code != ExitOK || !strings.Contains(out.String(), "Still open (1):") ||
		!regexp.MustCompile(`telnet-open .*\d{4}-\d{2}-\d{2}`).MatchString(out.String()) {
		t.Errorf("still open should say since when:\n%s", out)
	}

	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"diff", "--json", "1", "3"}); code != ExitOK {
		t.Fatalf("diff --json exit %d:\n%s", code, errOut)
	}
	var d diff.Result
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || d.Old.ID != 1 || d.New.ID != 3 || len(d.Open) != 1 { // the fake Nmap ignores -p
		t.Errorf("diff --json: %v %+v", err, d)
	}
	if !strings.Contains(errOut.String(), "didn't cover the same targets and ports") {
		t.Errorf("scans of other ports should get a note:\n%s", errOut)
	}
}

func TestDiffErrors(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	ctx := context.Background()
	for _, args := range [][]string{{"diff"}, {"diff", "x"}, {"diff", "1", "2", "3"}, {"diff", "1", "y"}} {
		if code := app.Run(ctx, args); code != ExitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
	if code := app.Run(ctx, []string{"diff", "-h"}); code != ExitOK {
		t.Errorf("-h: exit %d", code)
	}
	if code := app.Run(ctx, []string{"diff", "--nope"}); code != ExitUsage {
		t.Errorf("bad flag: exit %d", code)
	}
	if code := app.Run(ctx, []string{"diff", "7"}); code != ExitError {
		t.Errorf("unknown scan: exit %d", code)
	}
	if code := app.Run(ctx, []string{"scan", "10.0.0.1", "-p", "23"}); code != ExitOK {
		t.Fatal("scan failed")
	}
	errOut.Reset()
	if code := app.Run(ctx, []string{"diff", "1"}); code != ExitError || !strings.Contains(errOut.String(), "Pick one with: nuqs diff <old> 1") {
		t.Errorf("nothing to compare with: exit %d\n%s", code, errOut)
	}
	if code := app.Run(ctx, []string{"diff", "1", "9"}); code != ExitError {
		t.Errorf("unknown second scan: exit %d", code)
	}
	for _, args := range [][]string{{"diff", "9", "1"}, {"diff", "1", "1"}} {
		errOut.Reset()
		if code := app.Run(ctx, args); code != ExitUsage || !strings.Contains(errOut.String(), "first ID should be the older scan") {
			t.Errorf("%v: exit %d, want usage\n%s", args, code, errOut)
		}
	}
}

func TestFailOn(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	ctx := context.Background()
	cases := []struct {
		level string
		want  int
	}{
		{"", ExitOK},
		{"critical", ExitOK},
		{"high", ExitOK},
		{"medium", ExitFindings},
		{"INFO", ExitFindings},
		{"bad", ExitUsage},
	}
	for _, c := range cases {
		errOut.Reset()
		args := []string{"scan", "--no-save", "192.168.1.0/30", "-p", "23"}
		if c.level != "" {
			args = append(args, "--fail-on", c.level)
		}
		if code := app.Run(ctx, args); code != c.want {
			t.Errorf("--fail-on %q: exit %d, want %d\n%s", c.level, code, c.want, errOut)
		}
		if c.want == ExitFindings && !strings.Contains(errOut.String(), "1 finding(s) at") {
			t.Errorf("--fail-on %q should say why it failed:\n%s", c.level, errOut)
		}
	}
	if code := app.Run(ctx, []string{"diff", "0", "1"}); code != ExitUsage {
		t.Errorf("scan IDs start at 1: exit %d", code)
	}
}

// brokenCheck always fails, like a check that couldn't reach the service.
type brokenCheck struct{}

func (brokenCheck) Info() check.Info { return testInfo("broken") }

// testInfo copies the telnet check's info, so it always passes check.Validate,
// with a new ID and critical severity.
func testInfo(id string) check.Info {
	in := telnet.Check{}.Info()
	in.ID, in.Severity, in.RemediationTitle = id, model.Critical, ""
	return in
}

func (brokenCheck) Run(context.Context, check.Target) (*check.Result, error) {
	return nil, errors.New("connection refused")
}

// stopCheck stops the scan while it runs, like Ctrl+C, and still finds something.
type stopCheck struct{ stop context.CancelFunc }

func (stopCheck) Info() check.Info { return testInfo("stops") }

func (c stopCheck) Run(context.Context, check.Target) (*check.Result, error) {
	c.stop()
	return &check.Result{Evidence: "stopped"}, nil
}

// TestFailOnPrecedence pins which exit code wins when a scan has findings and errors.
func TestFailOnPrecedence(t *testing.T) {
	args := []string{"scan", "--no-save", "192.168.1.0/30", "-p", "23"}

	// Check errors don't change the code: telnet (medium) still trips medium,
	// and nothing trips critical, because the broken check found nothing.
	app, _, errOut := newApp(t, &fakeRunner{})
	app.Checks = func() []check.Check { return []check.Check{telnet.Check{}, brokenCheck{}} }
	for level, want := range map[string]int{"medium": ExitFindings, "critical": ExitOK} {
		errOut.Reset()
		if code := app.Run(context.Background(), append(args, "--fail-on", level)); code != want {
			t.Errorf("check error with --fail-on %s: exit %d, want %d\n%s", level, code, want, errOut)
		}
	}

	// A stopped scan exits with 1 even when --fail-on would match.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app, _, errOut = newApp(t, &fakeRunner{})
	app.Checks = func() []check.Check { return []check.Check{telnet.Check{}, stopCheck{stop: cancel}} }
	if code := app.Run(ctx, append(args, "--fail-on", "info")); code != ExitError {
		t.Errorf("stopped scan with --fail-on: exit %d, want %d\n%s", code, ExitError, errOut)
	}
	if !strings.Contains(errOut.String(), "stopped early") || strings.Contains(errOut.String(), "Failing because of --fail-on") {
		t.Errorf("a stopped scan shouldn't blame --fail-on:\n%s", errOut)
	}
}
