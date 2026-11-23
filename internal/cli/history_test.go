// Tests for saving scans from the CLI, "nuqs history" and "nuqs show".

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/store"
)

func TestScanIsSavedAndShownAgain(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "192.168.1.0/30", "-p", "23"}); code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, errOut)
	}
	if !strings.Contains(errOut.String(), "Saved as scan 1. See it again with: nuqs show 1") {
		t.Errorf("stderr should say where the scan went:\n%s", errOut)
	}
	scanned := out.String()

	out.Reset()
	if code := app.Run(context.Background(), []string{"show", "1"}); code != ExitOK {
		t.Fatalf("show exit %d:\n%s", code, errOut)
	}
	if out.String() != scanned {
		t.Errorf("show should print what scan printed:\n got %s\nwant %s", out, scanned)
	}

	out.Reset()
	if code := app.Run(context.Background(), []string{"show", "--json", "1"}); code != ExitOK {
		t.Fatalf("show --json exit %d", code)
	}
	var rep engine.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || len(rep.Findings) != 1 {
		t.Errorf("show --json: %v, %+v", err, rep.Findings)
	}

	out.Reset()
	if code := app.Run(context.Background(), []string{"history"}); code != ExitOK {
		t.Fatalf("history exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "ID") || !strings.HasPrefix(lines[1], "1 ") ||
		!strings.Contains(lines[1], "completed") || !strings.HasSuffix(lines[1], "192.168.1.0/30") {
		t.Errorf("history:\n%s", out)
	}
}

func TestHistoryNewestFirstAndLimit(t *testing.T) {
	app, out, _ := newApp(t, &fakeRunner{})
	for _, target := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if code := app.Run(context.Background(), []string{"scan", target}); code != ExitOK {
			t.Fatal(code)
		}
	}
	out.Reset()
	app.Run(context.Background(), []string{"history", "-n", "2"})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[1], "10.0.0.3") || !strings.HasSuffix(lines[2], "10.0.0.2") {
		t.Errorf("history -n 2:\n%s", out)
	}
}

func TestNoSave(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "--no-save", "10.0.0.1"}); code != ExitOK {
		t.Fatal(code)
	}
	if strings.Contains(errOut.String(), "Saved") {
		t.Errorf("--no-save still saved:\n%s", errOut)
	}
	out.Reset()
	app.Run(context.Background(), []string{"history"})
	if !strings.Contains(out.String(), "No saved scans yet") {
		t.Errorf("history after --no-save:\n%s", out)
	}
}

func TestStoppedScanIsSavedAsStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	app, out, _ := newApp(t, &fakeRunner{})
	app.Run(ctx, []string{"scan", "10.0.0.1"})
	out.Reset()
	app.Run(context.Background(), []string{"history"})
	if !strings.Contains(out.String(), "stopped") {
		t.Errorf("history:\n%s", out)
	}
}

func TestScanStillWorksWhenSavingFails(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	app.DataDir = filepath.Join(file, "data") // can't make a folder inside a file
	if code := app.Run(context.Background(), []string{"scan", "10.0.0.1"}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "telnet-open") || !strings.Contains(errOut.String(), "warning: couldn't save this scan") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", out, errOut)
	}
	for _, args := range [][]string{{"history"}, {"show", "1"}} {
		if code := app.Run(context.Background(), args); code != ExitError {
			t.Errorf("%v with a broken data folder: exit %d", args, code)
		}
	}
}

func TestHistoryAndShowUsage(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"history", "extra"}, ExitUsage},
		{[]string{"history", "-n", "-1"}, ExitUsage},
		{[]string{"history", "--bogus"}, ExitUsage},
		{[]string{"history", "-h"}, ExitOK},
		{[]string{"show"}, ExitUsage},
		{[]string{"show", "abc"}, ExitUsage},
		{[]string{"show", "1", "2"}, ExitUsage},
		{[]string{"show", "--bogus"}, ExitUsage},
		{[]string{"show", "-h"}, ExitOK},
		{[]string{"show", "7"}, ExitError}, // nothing saved yet
	}
	for _, c := range cases {
		if code := app.Run(context.Background(), c.args); code != c.code {
			t.Errorf("%v: exit %d, want %d\n%s", c.args, code, c.code, errOut)
		}
	}
}

func TestShowRunWithoutReport(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	st, err := store.Open(app.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	r := store.Run{Name: "broken", Kind: "quick", Targets: []string{"10.0.0.1"}, Status: store.Failed, Error: "Nmap isn't installed", Started: time.Now()}
	if err := st.Save(&r); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if code := app.Run(context.Background(), []string{"show", "1"}); code != ExitError || !strings.Contains(errOut.String(), "Scan 1 failed without a report: Nmap isn't installed") {
		t.Errorf("exit %d:\n%s", code, errOut)
	}
}

func TestServeShowsScansSavedByTheCLI(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "10.0.0.1"}); code != ExitOK {
		t.Fatal(code)
	}
	app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	var handler http.Handler
	app.ListenAndServe = func(_ context.Context, _ string, h http.Handler) error {
		handler = h
		return nil
	}
	if code := app.Run(context.Background(), []string{"serve", "--addr", "127.0.0.1:9124"}); code != ExitOK {
		t.Fatalf("serve exit %d:\n%s", code, errOut)
	}
	for path, want := range map[string]string{"/scans": "10.0.0.1", "/scans/1": "Command line scan", "/api/scans/1": `"status":"completed"`} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9124"+path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("GET %s: %d, missing %q", path, rec.Code, want)
		}
	}
}

func TestServeFailsWithoutItsStore(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	app.DataDir = filepath.Join(file, "data")
	if code := app.Run(context.Background(), []string{"serve"}); code != ExitError || !strings.Contains(errOut.String(), "error:") {
		t.Errorf("exit %d:\n%s", code, errOut)
	}
}
