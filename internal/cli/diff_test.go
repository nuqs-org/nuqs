// Tests "nuqs diff" and the "since last scan" line after a scan.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/internal/diff"
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
}
