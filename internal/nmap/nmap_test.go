// Tests building the Nmap command, reading its XML and running it.

package nmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/model"
)

func TestArgs(t *testing.T) {
	got := Args([]string{"10.0.0.1", "example.com"}, Options{})
	want := []string{"-sT", "-sV", "--open", "-T4", "--stats-every", "5s", "-oX", "-", "--", "10.0.0.1", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Args = %q\nwant  %q", got, want)
	}

	got = Args([]string{"10.0.0.1"}, Options{Ports: "22,80", SkipPing: true})
	if !slices.Contains(got, "-Pn") {
		t.Error("SkipPing should add -Pn")
	}
	i := slices.Index(got, "-p")
	if i < 0 || got[i+1] != "22,80" {
		t.Errorf("ports not passed: %q", got)
	}
	// Targets must always come after "--" so Nmap never reads them as options.
	dash := slices.Index(got, "--")
	if dash < 0 || got[dash+1] != "10.0.0.1" || dash != len(got)-2 {
		t.Errorf("targets must follow --: %q", got)
	}

	got = Args([]string{"10.0.0.1"}, Options{TopPorts: 100, LightVersion: true})
	if !slices.Contains(got, "--version-light") {
		t.Errorf("LightVersion should add --version-light: %q", got)
	}
	tp := slices.Index(got, "--top-ports")
	if tp < 0 || got[tp+1] != "100" {
		t.Errorf("TopPorts not passed: %q", got)
	}

	// Explicit Ports takes precedence over TopPorts so Nmap never gets both.
	got = Args([]string{"10.0.0.1"}, Options{Ports: "80,443", TopPorts: 100})
	if slices.Contains(got, "--top-ports") || !slices.Contains(got, "-p") {
		t.Errorf("Ports should override TopPorts: %q", got)
	}
}

func TestParseFixture(t *testing.T) {
	f, err := os.Open("testdata/scan.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hosts, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}

	want := []model.Host{
		{
			Address:   "192.168.1.1",
			Hostnames: []string{"router.lan"},
			Services: []model.Service{
				{Port: 22, Protocol: "tcp", Name: "ssh", Product: "Dropbear sshd", Version: "2020.81"},
				{Port: 23, Protocol: "tcp", Name: "telnet", Product: "BusyBox telnetd"},
				{Port: 53, Protocol: "tcp", Name: "domain", Product: "dnsmasq", Version: "2.80"},
				{Port: 80, Protocol: "tcp", Name: "http", Product: "lighttpd"},
				{Port: 443, Protocol: "tcp", Name: "http", Product: "lighttpd", Tunnel: "ssl"},
				// 8080 is filtered, so it must be left out
			},
		},
		// 192.168.1.2 is down, so it must be left out
		{
			Address:   "fd00::10",
			Hostnames: []string{"nas.lan"}, // the empty PTR name is dropped
			Services: []model.Service{
				{Port: 21, Protocol: "tcp", Name: "ftp", Product: "vsftpd", Version: "3.0.3"},
				{Port: 161, Protocol: "udp", Name: "snmp", Guessed: true}, // method="table"
			},
		},
		// the MAC-only host has no IP, so it must be left out
		{Address: "192.168.1.3"}, // up with no open ports is still a host
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("Parse got:\n%+v\nwant:\n%+v", hosts, want)
	}
}

func TestParseEmptyRun(t *testing.T) {
	hosts, err := Parse(strings.NewReader(`<nmaprun></nmaprun>`))
	if err != nil || len(hosts) != 0 {
		t.Errorf("empty run: %v, %v", hosts, err)
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		``,
		`not xml`,
		`<nmaprun><host>`,
		`<nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="abc"><state state="open"/></port></ports></host></nmaprun>`,
		`<nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="70000"><state state="open"/></port></ports></host></nmaprun>`,
		`<nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="0"><state state="open"/></port></ports></host></nmaprun>`,
	}
	for _, in := range bad {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
}

// fakeRunner records the arguments and returns canned output.
type fakeRunner struct {
	out  []byte
	err  error
	args []string
}

func (f *fakeRunner) Run(_ context.Context, args []string, out io.Writer) error {
	f.args = args
	if _, err := out.Write(f.out); err != nil {
		return err
	}
	return f.err
}

func TestScanner(t *testing.T) {
	xml, err := os.ReadFile("testdata/scan.xml")
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{out: xml}
	s := Scanner{Runner: r, Options: Options{Ports: "1-1000"}}
	hosts, err := s.Scan(context.Background(), []string{"192.168.1.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Errorf("expected 3 hosts, got %d", len(hosts))
	}
	if !slices.Contains(r.args, "1-1000") || r.args[len(r.args)-1] != "192.168.1.0/30" {
		t.Errorf("runner got wrong args: %q", r.args)
	}
}

func TestScannerErrors(t *testing.T) {
	if _, err := (Scanner{}).Scan(context.Background(), []string{"x"}); err == nil {
		t.Error("no runner should be an error")
	}
	boom := errors.New("boom")
	if _, err := (Scanner{Runner: &fakeRunner{err: boom}}).Scan(context.Background(), []string{"x"}); !errors.Is(err, boom) {
		t.Errorf("runner error should pass through, got %v", err)
	}
	if _, err := (Scanner{Runner: &fakeRunner{out: []byte("garbage")}}).Scan(context.Background(), []string{"x"}); err == nil {
		t.Error("bad XML should be an error")
	}
}

// TestHelperProcess is not a real test. ExecRunner tests run the test binary
// itself as a fake "nmap", and this function decides what that fake does.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("NUQS_FAKE_NMAP")
	if mode == "" {
		return
	}
	switch mode {
	case "ok":
		fmt.Print("<nmaprun>" + strings.Join(os.Args[len(os.Args)-2:], " ") + "</nmaprun>")
		os.Exit(0)
	case "fail":
		fmt.Fprint(os.Stderr, "Failed to resolve given hostname/IP")
		os.Exit(1)
	case "fail-quiet":
		os.Exit(3)
	case "hang":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "slow":
		// One host, then a long pause before the rest, like a real scan.
		fmt.Print(`<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>`)
		os.Stdout.Sync()
		time.Sleep(time.Minute)
		fmt.Print(`</nmaprun>`)
		os.Exit(0)
	}
}

// fakeNmap returns an ExecRunner that runs this test binary in helper mode.
func fakeNmap(t *testing.T, mode string) ExecRunner {
	t.Helper()
	t.Setenv("NUQS_FAKE_NMAP", mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return ExecRunner{Path: exe}
}

func TestExecRunnerOK(t *testing.T) {
	r := fakeNmap(t, "ok")
	var out bytes.Buffer
	err := r.Run(context.Background(), []string{"-test.run=TestHelperProcess", "--", "10.0.0.1"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "10.0.0.1") {
		t.Errorf("stdout not returned: %q", out)
	}
}

func TestExecRunnerFailure(t *testing.T) {
	r := fakeNmap(t, "fail")
	err := r.Run(context.Background(), []string{"-test.run=TestHelperProcess"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Failed to resolve") {
		t.Errorf("stderr should be in the error, got %v", err)
	}

	r = fakeNmap(t, "fail-quiet")
	err = r.Run(context.Background(), []string{"-test.run=TestHelperProcess"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "nmap failed") {
		t.Errorf("expected nmap failed error, got %v", err)
	}
}

func TestExecRunnerCancel(t *testing.T) {
	r := fakeNmap(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := r.Run(ctx, []string{"-test.run=TestHelperProcess"}, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected deadline error, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("cancel did not stop nmap")
	}
}

// chunks is a fake runner that writes its parts one at a time. After each
// part it calls after, which tests use to wait for something to happen.
type chunks struct {
	parts []string
	after func(i int)
	err   error // returned at the end
}

func (c chunks) Run(_ context.Context, _ []string, out io.Writer) error {
	for i, p := range c.parts {
		if _, err := io.WriteString(out, p); err != nil {
			return err
		}
		if c.after != nil {
			c.after(i)
		}
	}
	return c.err
}

const (
	upHost   = `<host><status state="up"/><address addr="10.0.0.%d" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>`
	progress = `<taskprogress task="Service scan" time="1" percent="40.50" remaining="12" etc="13"/>`
)

func TestStreamHandsHostsOnEarly(t *testing.T) {
	first := make(chan struct{})
	early := false
	r := chunks{
		parts: []string{
			`<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>`,
			fmt.Sprintf(upHost, 1),
			// A host split across two writes must still come out whole.
			fmt.Sprintf(upHost, 2)[:40], fmt.Sprintf(upHost, 2)[40:],
			`<host><status state="down"/><address addr="10.0.0.3" addrtype="ipv4"/></host>`,
			`</nmaprun>`,
		},
		after: func(i int) {
			if i != 1 {
				return
			}
			// Don't write anything more until the first host is out. If
			// Stream waited for the end, this would time out.
			select {
			case <-first:
				early = true
			case <-time.After(5 * time.Second):
			}
		},
	}
	var got []string
	err := Scanner{Runner: r}.Stream(context.Background(), []string{"x"}, Events{Host: func(h model.Host) {
		got = append(got, h.Address)
		if len(got) == 1 {
			close(first)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !early {
		t.Error("the first host wasn't handed on before the rest of the output")
	}
	if !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("hosts %v", got)
	}
}

func TestStreamProgress(t *testing.T) {
	var ps []Progress
	r := chunks{parts: []string{
		`<nmaprun>`, progress,
		`<taskprogress task="Connect Scan" percent="5"/>`,    // no remaining
		`<taskprogress task="Connect Scan" percent="lots"/>`, // skipped
		`<taskprogress percent="5"/>`,                        // no task, skipped
		`<taskprogress task="Connect Scan" percent="140"/>`,  // skipped
		`<taskprogress task="Connect Scan" percent="NaN"/>`,  // skipped, JSON can't encode it
		`</nmaprun>`,
	}}
	err := Scanner{Runner: r}.Stream(context.Background(), []string{"x"}, Events{Progress: func(p Progress) { ps = append(ps, p) }})
	if err != nil {
		t.Fatal(err)
	}
	want := []Progress{{"Service scan", 40.5, 12 * time.Second}, {"Connect Scan", 5, 0}}
	if !reflect.DeepEqual(ps, want) {
		t.Errorf("progress %+v, want %+v", ps, want)
	}
}

func TestStreamNilEvents(t *testing.T) {
	r := chunks{parts: []string{`<nmaprun>`, progress, fmt.Sprintf(upHost, 1), `</nmaprun>`}}
	if err := (Scanner{Runner: r}).Stream(context.Background(), []string{"x"}, Events{}); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRunnerFails(t *testing.T) {
	boom := errors.New("nmap failed: boom")
	var got []string
	// Nmap dies halfway through a host. We keep the host we already had and
	// report Nmap's error, not an XML error about the cut off output.
	r := chunks{parts: []string{`<nmaprun>`, fmt.Sprintf(upHost, 1), `<host><status st`}, err: boom}
	err := Scanner{Runner: r}.Stream(context.Background(), []string{"x"}, Events{Host: func(h model.Host) { got = append(got, h.Address) }})
	if !errors.Is(err, boom) || strings.Contains(err.Error(), "XML") {
		t.Errorf("want nmap's error, got %v", err)
	}
	if !reflect.DeepEqual(got, []string{"10.0.0.1"}) {
		t.Errorf("hosts %v", got)
	}
}

func TestStreamBadXMLStopsNmap(t *testing.T) {
	r := fakeNmap(t, "slow")
	// A port number that's no good makes reading fail at the first host.
	// Stream must stop Nmap right away, not wait out its minute.
	bad := Scanner{Runner: badFirstHost{r}}
	start := time.Now()
	err := bad.Stream(context.Background(), []string{"x"}, Events{})
	if err == nil || !strings.Contains(err.Error(), "bad port") {
		t.Errorf("want a bad port error, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("nmap wasn't stopped")
	}
}

// badFirstHost runs r but swaps the first host's port for a bad one.
type badFirstHost struct{ r ExecRunner }

func (b badFirstHost) Run(ctx context.Context, args []string, out io.Writer) error {
	return b.r.Run(ctx, []string{"-test.run=TestHelperProcess"}, &replacer{w: out, old: `addrtype="ipv4"/>`, new: `addrtype="ipv4"/><ports><port protocol="tcp" portid="0"><state state="open"/></port></ports>`})
}

// replacer swaps old for new in what passes through it. Fine for tests where
// old is never split across writes.
type replacer struct {
	w        io.Writer
	old, new string
}

func (r *replacer) Write(p []byte) (int, error) {
	if _, err := io.WriteString(r.w, strings.Replace(string(p), r.old, r.new, 1)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func TestStreamRealProcessIsLive(t *testing.T) {
	// The fake nmap prints one host and then sleeps for a minute. We must see
	// the host long before that, then cancel.
	r := fakeNmap(t, "slow")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- Scanner{Runner: helperArgs{r}}.Stream(ctx, []string{"x"}, Events{Host: func(h model.Host) { got <- h.Address }})
	}()
	select {
	case a := <-got:
		if a != "10.0.0.1" {
			t.Errorf("host %q", a)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("host not handed on while nmap was still running")
	}
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Errorf("want canceled, got %v", err)
	}
}

// helperArgs runs the helper process no matter what args Stream builds.
type helperArgs struct{ r ExecRunner }

func (h helperArgs) Run(ctx context.Context, _ []string, out io.Writer) error {
	return h.r.Run(ctx, []string{"-test.run=TestHelperProcess"}, out)
}

func TestExecRunnerMissingBinary(t *testing.T) {
	err := ExecRunner{Path: "/definitely/not/nmap"}.Run(context.Background(), nil, io.Discard)
	if err == nil {
		t.Error("missing binary should be an error")
	}
}

// FuzzParse makes sure hostile XML can't crash the parser, and that every
// port it returns is a real port number.
func FuzzParse(f *testing.F) {
	if b, err := os.ReadFile("testdata/scan.xml"); err == nil {
		f.Add(string(b))
	}
	f.Add(`<nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/></host></nmaprun>`)
	f.Fuzz(func(t *testing.T, s string) {
		hosts, err := Parse(strings.NewReader(s))
		if err != nil {
			return
		}
		for _, h := range hosts {
			if h.Address == "" {
				t.Fatal("host without address")
			}
			for _, svc := range h.Services {
				if svc.Port < 1 || svc.Port > 65535 {
					t.Fatalf("bad port %d", svc.Port)
				}
			}
		}
	})
}
