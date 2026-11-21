// Tests the web handlers, template rendering, htmx partials and HTML escaping.

package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/checks"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/tools"
)

func newTestWeb(t *testing.T, checkList func() []check.Check) *Handler {
	t.Helper()
	svc := &tools.Service{
		Version:      "v0.1.0-test",
		RunnerName:   "nmap",
		Checks:       checkList,
		EnforceScope: true,
		MaxWorkers:   128,
	}
	h, err := New(svc, "127.0.0.1:9002")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	return h
}

func TestIndexAndStaticAssets(t *testing.T) {
	h := newTestWeb(t, checks.All)

	t.Run("GET / renders workspace with security headers and htmx", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", w.Code)
		}
		for _, hdr := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
			if w.Header().Get(hdr) == "" {
				t.Errorf("missing header %s", hdr)
			}
		}
		body := w.Body.String()
		for _, want := range []string{
			"/static/nuqs.css",
			"/static/htmx.min.js",
			"/static/workbench.js",
			`hx-get="/partials/checks"`,
			`hx-get="/partials/report"`,
			"telnet-open",
			"127.0.0.1:9002",
			`data-preset="quick"`,
			`data-preset="full"`,
			`data-preset="custom"`,
			`id="portPreset"`,
			"Common web ports",
			"Scan hosts even if they don't answer ping",
			`id="advancedOptions"`,
			"Run your first scan",
			`data-target="127.0.0.1"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("index missing %q", want)
			}
		}
	})

	t.Run("GET /static assets return 200", func(t *testing.T) {
		for _, path := range []string{"/static/nuqs.css", "/static/htmx.min.js", "/static/workbench.js", "/static/nuqs-logo.png"} {
			r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("GET %s: got %d, want 200", path, w.Code)
			}
		}
	})

	t.Run("unknown paths return 404 and non-GET returns 405", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/does-not-exist", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("got %d, want 404", w.Code)
		}

		for _, path := range []string{"/", "/partials/checks", "/partials/inventory", "/partials/report"} {
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("POST %s: got %d, want 405", path, w.Code)
			}
		}
	})
}

func TestChecksPartialsAndEmptyTemplates(t *testing.T) {
	t.Run("renders empty check list and empty report without error", func(t *testing.T) {
		h := newTestWeb(t, func() []check.Check { return nil })
		for _, path := range []string{"/", "/partials/checks", "/partials/inventory", "/partials/report"} {
			r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("GET %s with empty data: got %d, want 200", path, w.Code)
			}
		}
	})

	t.Run("filters check library partial by query", func(t *testing.T) {
		h := newTestWeb(t, checks.All)
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/partials/checks?q=telnet", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		body := w.Body.String()
		if !strings.Contains(body, "telnet-open") || strings.Contains(body, "ftp-anonymous-login") {
			t.Fatalf("unexpected filtered checks body: %s", body)
		}
	})

	t.Run("displays custom allowed scope hint and suggested target", func(t *testing.T) {
		h := newTestWeb(t, checks.All)
		h.Service.AllowedScope = []netip.Prefix{netip.MustParsePrefix("192.168.56.0/24")}
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		body := w.Body.String()
		if !strings.Contains(body, "Allowed scope: 192.168.56.0/24.") {
			t.Fatalf("expected custom allowed scope hint in index")
		}
		if !strings.Contains(body, `data-target="192.168.56.0/24"`) {
			t.Fatalf("expected suggested target from custom allowed scope")
		}

		// Single /32 host scope suggests the bare IP.
		h.Service.AllowedScope = []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")}
		w2 := httptest.NewRecorder()
		h.ServeHTTP(w2, r)
		if !strings.Contains(w2.Body.String(), `data-target="10.0.0.5"`) {
			t.Fatalf("expected bare IP suggested target for /32 scope")
		}
	})
}

func TestReportEscapingFilteringAndIncompleteStatus(t *testing.T) {
	h := newTestWeb(t, checks.All)
	started := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	xss := `<script>alert("xss")</script>`

	rep := &engine.Report{
		Targets:  []string{"127.0.0.1"},
		Started:  started,
		Finished: started.Add(1500 * time.Millisecond),
		Hosts: []model.Host{
			{
				Address: "127.0.0.1",
				Services: []model.Service{
					{Port: 23, Protocol: "tcp", Name: "telnet"},
					{Port: 80, Protocol: "tcp", Name: "http"},
				},
			},
		},
		Findings: []model.Finding{
			{
				ID:       "http-headers|127.0.0.1|80/tcp",
				CheckID:  "http-security-headers",
				Title:    "Missing headers " + xss,
				Severity: model.Low,
				Host:     "127.0.0.1",
				Port:     80,
				Protocol: "tcp",
				Evidence: "Server banner: " + xss,
				Fix:      "Add headers " + xss,
			},
			{
				ID:       "telnet-open|127.0.0.1|23/tcp",
				CheckID:  "telnet-open",
				Title:    "Unencrypted Telnet server",
				Severity: model.High,
				Host:     "127.0.0.1",
				Port:     23,
				Protocol: "tcp",
				Evidence: "Port 23 open",
				Fix:      "Disable Telnet and use SSH.",
			},
		},
		Errors: []engine.CheckError{
			{
				CheckID: "ftp-anonymous-login",
				Host:    "127.0.0.1",
				Port:    21,
				Error:   "banner failed: " + xss,
			},
		},
	}
	h.SetReport(rep, "")

	t.Run("escapes script tags on both / and /partials/report", func(t *testing.T) {
		for _, path := range []string{"/", "/partials/report?fresh=1"} {
			r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			body := w.Body.String()
			if strings.Contains(body, xss) {
				t.Fatalf("%s rendered raw unescaped script tag!", path)
			}
			if !strings.Contains(body, "&lt;script&gt;") {
				t.Fatalf("%s did not render escaped script text", path)
			}
		}
	})

	t.Run("sorts high before low, shows counts and incomplete status", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/partials/report?fresh=1", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		body := w.Body.String()
		for _, want := range []string{"Scan incomplete in 1.5s", "1 host up · 2 open services", "1 high", "1 low", "Scan errors"} {
			if !strings.Contains(body, want) {
				t.Errorf("report missing %q", want)
			}
		}
		_, findingsSection, ok := strings.Cut(body, `<div id="findings">`)
		if !ok {
			t.Fatal("missing findings section")
		}
		highPos := strings.Index(findingsSection, "Unencrypted Telnet server")
		lowPos := strings.Index(findingsSection, "Missing headers")
		if highPos < 0 || lowPos < 0 || highPos > lowPos {
			t.Fatalf("findings not sorted worst-first: high=%d low=%d", highPos, lowPos)
		}
	})

	t.Run("filters report findings by severity query param", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/partials/report?severity=low", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		_, findingsSection, ok := strings.Cut(w.Body.String(), `<div id="findings">`)
		if !ok {
			t.Fatal("missing findings section")
		}
		if !strings.Contains(findingsSection, "http-security-headers") || strings.Contains(findingsSection, "Unencrypted Telnet server") {
			t.Fatalf("severity=low filter did not isolate low finding: %s", findingsSection)
		}
	})

	t.Run("shows concise Finished status for clean fast scan", func(t *testing.T) {
		cleanRep := &engine.Report{
			Targets:  []string{"127.0.0.1"},
			Started:  started,
			Finished: started.Add(200 * time.Millisecond),
		}
		h.SetReport(cleanRep, "")
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/partials/report?fresh=1", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		body := w.Body.String()
		if !strings.Contains(body, "Finished in 0.2s") || !strings.Contains(body, "statusPill done") {
			t.Fatalf("expected clean finished status, got: %s", body)
		}
		if !strings.Contains(body, "Scan hosts even if they don&#39;t answer ping") {
			t.Fatalf("expected plain-English ping hint when zero hosts up, got: %s", body)
		}
		if got := formatDuration(0.04); got != "0.04s" {
			t.Fatalf("formatDuration(0.04) = %q, want 0.04s", got)
		}
		if got := formatDuration(-1); got != "0.0s" {
			t.Fatalf("formatDuration(-1) = %q, want 0.0s", got)
		}
	})
}
