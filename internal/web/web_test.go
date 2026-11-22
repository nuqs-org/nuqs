// Tests every page of the web UI: rendering, links between pages, live scan state, escaping and 404s.

package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/checks/telnet"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/tools"
)

const xss = `<script>alert("x")</script>`

// scanXML has one host with telnet open and a product name that tries to inject HTML.
const scanXML = `<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="lab.local"/></hostnames><ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" method="probed"/></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" method="probed"/></port>
</ports></host></nmaprun>`

type fakeRunner struct {
	xml     string
	err     error
	release chan struct{} // if set, wait for it or ctx
}

func (f *fakeRunner) Run(ctx context.Context, _ []string) ([]byte, error) {
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []byte(f.xml), f.err
}

// brokenCheck always fails, so pages have a check error to show.
type brokenCheck struct{}

func (brokenCheck) Info() check.Info {
	return check.Info{ID: "ftp-anonymous-login", Title: "FTP allows anonymous login", Severity: model.High, Fix: "Turn it off.", Ports: []int{21}, Services: []string{"ftp"}}
}
func (brokenCheck) Run(context.Context, check.Target) (*check.Result, error) {
	return nil, errors.New("banner failed: " + xss)
}

func newTestWeb(t *testing.T, r nmap.Runner) *Handler {
	t.Helper()
	svc := &tools.Service{
		Version:      "v0.1.0-test",
		RunnerName:   "nmap",
		NewRunner:    func() nmap.Runner { return r },
		Checks:       func() []check.Check { return []check.Check{telnet.Check{}, brokenCheck{}} },
		EnforceScope: true,
		MaxWorkers:   128,
	}
	scans := &tools.Scans{Service: svc}
	t.Cleanup(scans.StopAll)
	h, err := New(svc, scans, "127.0.0.1:9002")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	return h
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002"+path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func mustContain(t *testing.T, where, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("%s is missing %q", where, want)
		}
	}
}

// startAndWait starts a full scan of 127.0.0.1 and waits for it to finish.
func startAndWait(t *testing.T, h *Handler, name string) tools.Scan {
	t.Helper()
	s, err := h.Scans.Start(tools.NewScan{Name: name, Kind: "full", Settings: tools.ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	for range 500 {
		if got, _ := h.Scans.Get(s.ID); got.Status != tools.ScanRunning {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan never finished")
	return s
}

func TestEmptyPages(t *testing.T) {
	h := newTestWeb(t, &fakeRunner{xml: scanXML})

	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/scans" {
		t.Errorf("/ should go to /scans, got %d %s", w.Code, w.Header().Get("Location"))
	}

	code, body := get(t, h, "/scans")
	if code != http.StatusOK {
		t.Fatalf("/scans: %d", code)
	}
	mustContain(t, "/scans", body, "No scans yet", `id="tryScan"`, `data-target="127.0.0.1"`, `href="/scans/new"`,
		`aria-current="page">`, "/static/app.js", "Checking engine…")

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/scans", nil))
	for _, hdr := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if w.Header().Get(hdr) == "" {
			t.Errorf("missing header %s", hdr)
		}
	}

	code, body = get(t, h, "/scans/new")
	if code != http.StatusOK {
		t.Fatalf("/scans/new: %d", code)
	}
	mustContain(t, "gallery", body, "Discovery", "Vulnerabilities", `aria-disabled="true"`, "Coming soon",
		`href="/scans/new/quick"`, `href="/scans/new/full"`, `href="/scans/new/custom"`)
	if strings.Contains(body, `href="/scans/new/discover"`) {
		t.Error("discover isn't ready, it must not be a link")
	}

	code, body = get(t, h, "/checks")
	if code != http.StatusOK {
		t.Fatalf("/checks: %d", code)
	}
	mustContain(t, "/checks", body, `hx-get="/partials/checks"`, "telnet-open", "ftp-anonymous-login")
	_, body = get(t, h, "/partials/checks?q=ftp")
	if !strings.Contains(body, "ftp-anonymous-login") || strings.Contains(body, "telnet-open") {
		t.Errorf("search didn't filter: %s", body)
	}
	_, body = get(t, h, "/partials/checks?q=nothing-like-this")
	mustContain(t, "empty search", body, "No matching checks.")

	for _, path := range []string{"/static/nuqs.css", "/static/htmx.min.js", "/static/app.js", "/static/nuqs-logo.png"} {
		if code, _ := get(t, h, path); code != http.StatusOK {
			t.Errorf("GET %s: %d", path, code)
		}
	}
}

func TestSettingsPage(t *testing.T) {
	h := newTestWeb(t, &fakeRunner{xml: scanXML})

	code, body := get(t, h, "/scans/new/full")
	if code != http.StatusOK {
		t.Fatalf("full: %d", code)
	}
	mustContain(t, "full settings", body, "New full scan", `data-kind="full"`, `id="modifiedTag" hidden`,
		`data-section="basic"`, `data-section="discovery"`, `data-section="advanced"`,
		`value="top1000" selected`, `id="largeNet" hidden`, `id="targetInfo"`, `form="scanForm"`, ">Launch<", `href="/scans">Cancel`,
		"You can scan this computer (127.0.0.1).", `href="/scans/new">Change type`)
	if strings.Contains(body, `id="lightVersion" checked`) {
		t.Error("full scan shouldn't use light version detection")
	}

	_, body = get(t, h, "/scans/new/quick")
	mustContain(t, "quick settings", body, `value="top100" selected`, `id="lightVersion" checked`)
	_, body = get(t, h, "/scans/new/custom")
	mustContain(t, "custom settings", body, "New custom scan", `data-kind="custom"`)

	for _, path := range []string{"/scans/new/discover", "/scans/new/nope"} {
		if code, _ := get(t, h, path); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, code)
		}
	}
}

func TestCompletedScanPages(t *testing.T) {
	h := newTestWeb(t, &fakeRunner{xml: scanXML})
	s := startAndWait(t, h, "Lab box")

	_, body := get(t, h, "/scans")
	mustContain(t, "scans list", body, `href="/scans/`+s.ID+`"`, "Lab box", "Full scan", "Finished with errors in", "1 medium", `statusPill partial`)
	if strings.Contains(body, "data-watch") {
		t.Error("nothing is running, the list shouldn't watch")
	}

	code, body := get(t, h, "/scans/"+s.ID)
	if code != http.StatusOK {
		t.Fatalf("scan page: %d", code)
	}
	mustContain(t, "hosts tab", body, "Finished with errors in", `aria-current="page">Hosts`, `href="/scans/`+s.ID+`/hosts/127.0.0.1"`,
		"lab.local", `class="sevbar"`, "Scan details", "Full scan", "conic-gradient", "1 check couldn", "These aren't findings",
		`href="/api/scans/`+s.ID+`/report" download`)
	if strings.Contains(body, xss) || strings.Contains(body, "data-watch") || strings.Contains(body, `id="stopScan"`) {
		t.Error("finished scan page must escape errors and not watch or offer stop")
	}

	_, body = get(t, h, "/scans/"+s.ID+"?tab=vulns")
	mustContain(t, "vulns tab", body, `aria-current="page">Vulnerabilities`, `href="/scans/`+s.ID+`/vulns/telnet-open"`, "Unencrypted Telnet")

	code, body = get(t, h, "/scans/"+s.ID+"/hosts/127.0.0.1")
	if code != http.StatusOK {
		t.Fatalf("host page: %d", code)
	}
	mustContain(t, "host page", body, "127.0.0.1", "lab.local", "23/tcp", "telnet", "21/tcp", "Copy fix", `href="/scans/`+s.ID+`"`,
		`href="/scans/`+s.ID+`/vulns/telnet-open"`, "&lt;script&gt;")
	if strings.Contains(body, xss) {
		t.Error("host page must escape the product name and check errors")
	}

	code, body = get(t, h, "/scans/"+s.ID+"/vulns/telnet-open")
	if code != http.StatusOK {
		t.Fatalf("finding page: %d", code)
	}
	mustContain(t, "finding page", body, "How to fix it", "Found on 1 host", "This check looks at telnet", `href="/scans/`+s.ID+`/hosts/127.0.0.1"`)

	for _, path := range []string{"/scans/99", "/scans/99/hosts/127.0.0.1", "/scans/" + s.ID + "/hosts/10.0.0.1", "/scans/" + s.ID + "/vulns/nope", "/scans/99/vulns/telnet-open", "/does-not-exist"} {
		if code, _ := get(t, h, path); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002/scans", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /scans: %d", w.Code)
	}
}

func TestRunningAndFailedScan(t *testing.T) {
	runner := &fakeRunner{xml: scanXML, release: make(chan struct{})}
	h := newTestWeb(t, runner)
	s, err := h.Scans.Start(tools.NewScan{Kind: "quick", Settings: tools.ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	_, body := get(t, h, "/scans/"+s.ID)
	mustContain(t, "running scan", body, `data-watch="`+s.ID+`"`, `id="stopScan"`, `class="spinner"`, "Scanning", "show up here when the scan finishes")
	_, body = get(t, h, "/scans")
	mustContain(t, "list while running", body, `data-watch="`+s.ID+`"`, "Scanning")
	h.Scans.StopAll()
	for range 500 {
		if got, _ := h.Scans.Get(s.ID); got.Status != tools.ScanRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, body = get(t, h, "/scans/"+s.ID)
	mustContain(t, "stopped scan", body, "Stopped after", "Stopped before Nmap finished")

	h2 := newTestWeb(t, &fakeRunner{err: errors.New(`exec: "nmap": executable file not found in $PATH`)})
	failed := startAndWait(t, h2, "")
	_, body = get(t, h2, "/scans/"+failed.ID)
	mustContain(t, "failed scan", body, "The scan couldn", "Nmap isn&#39;t installed", "Failed")
}

func TestHelpers(t *testing.T) {
	for in, want := range map[float64]string{-1: "0.0s", 0: "0.0s", 0.05: "0.05s", 0.23: "0.2s", 12.34: "12.3s", 75: "1m 15s"} {
		if got := formatDuration(in); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", in, got, want)
		}
	}
	if got := string(donut(sevCounts{})); !strings.Contains(got, "var(--rule)") {
		t.Errorf("empty donut %q", got)
	}
	if got := string(donut(sevCounts{High: 1, Low: 3})); !strings.Contains(got, "var(--high) 0.00% 25.00%") || !strings.Contains(got, "var(--low) 25.00% 100.00%") {
		t.Errorf("donut %q", got)
	}
	if suggestedTarget([]netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")}) != "10.0.0.5" ||
		suggestedTarget([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) != "10.0.0.1" {
		t.Error("suggestedTarget")
	}
	var c sevCounts
	for _, sev := range []model.Severity{model.Critical, model.High, model.Medium, model.Low, model.Info} {
		c.add(sev)
	}
	if c != (sevCounts{1, 1, 1, 1, 1}) || c.Total() != 5 {
		t.Errorf("counts %+v", c)
	}
	for settings, want := range map[tools.ScanRequest]string{
		{}:                               "Top 1,000",
		{TopPorts: 100}:                  "Top 100",
		{Ports: "22,80", SkipPing: true}: "22,80",
	} {
		d := scanDetails(tools.Scan{Settings: settings, Started: time.Now()})
		if d[2].Value != want {
			t.Errorf("ports for %+v: %q, want %q", settings, d[2].Value, want)
		}
		if settings.SkipPing != (d[3].Value == "Scan every address") {
			t.Errorf("discovery for %+v: %q", settings, d[3].Value)
		}
	}
	if badgeClass("nope") != "info" || severityRank("nope") != 5 {
		t.Error("unknown severities fall back to info")
	}
}

func TestLocalNetwork(t *testing.T) {
	orig := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = orig })
	cidr := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	cases := []struct {
		name  string
		addrs []net.Addr
		err   error
		want  string
	}{
		{"home wifi", []net.Addr{cidr("127.0.0.1/8"), cidr("192.168.1.23/24")}, nil, "192.168.1.0/24"},
		{"big office network is cut to a /24", []net.Addr{cidr("10.20.30.40/16")}, nil, "10.20.30.0/24"},
		{"small network stays small", []net.Addr{cidr("172.16.5.9/28")}, nil, "172.16.5.0/28"},
		{"public and IPv6 are skipped", []net.Addr{cidr("8.8.8.8/24"), cidr("fd00::5/64"), &net.IPAddr{IP: net.ParseIP("10.0.0.1")}}, nil, ""},
		{"no addresses", nil, nil, ""},
		{"error", nil, errors.New("boom"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			interfaceAddrs = func() ([]net.Addr, error) { return c.addrs, c.err }
			if got := localNetwork(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestUseMyNetwork(t *testing.T) {
	orig := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = orig })
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.23").To4(), Mask: net.CIDRMask(24, 32)}}, nil
	}

	// Default scope is loopback only, so we only explain how to allow it.
	_, body := get(t, newTestWeb(t, &fakeRunner{}), "/scans/new/full")
	if strings.Contains(body, `id="useNetwork"`) || !strings.Contains(body, "nuqs serve --allow 192.168.1.0/24") {
		t.Error("outside the scope there should be a hint, not a button")
	}

	h := newTestWeb(t, &fakeRunner{})
	h.Service.AllowedScope = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	_, body = get(t, h, "/scans/new/full")
	if !strings.Contains(body, `data-network="192.168.1.0/24"`) || strings.Contains(body, "nuqs serve --allow") {
		t.Error("inside the scope there should be a use my network button")
	}
	mustContain(t, "scope hint", body, "You can scan 192.168.0.0/16.")
}
