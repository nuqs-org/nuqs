// Tests the JSON API endpoints, request security checks and SSE scan streaming.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/checks/telnet"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/tools"
)

type fakeRunner struct {
	xml  []byte
	err  error
	args []string
}

func (f *fakeRunner) Run(_ context.Context, args []string) ([]byte, error) {
	f.args = slices.Clone(args)
	return f.xml, f.err
}

func newTestHandler(r nmap.Runner) *Handler {
	svc := &tools.Service{
		Version:      "v0.1.0-test",
		RunnerName:   "nmap",
		NewRunner:    func() nmap.Runner { return r },
		Checks:       func() []check.Check { return []check.Check{telnet.Check{}} },
		EnforceScope: true,
		MaxWorkers:   128,
	}
	return New(svc, "127.0.0.1:9002")
}

func TestRejectScanRequest(t *testing.T) {
	const host = "127.0.0.1:9002"
	const origin = "http://" + host
	h := newTestHandler(&fakeRunner{})

	for _, tc := range []struct {
		name, method, host, origin, media, body string
		want                                    int
	}{
		{"wrong method", http.MethodGet, host, origin, "application/json", "", http.StatusMethodNotAllowed},
		{"foreign origin", http.MethodPost, host, "https://example.org", "application/json", `{"target":"localhost"}`, http.StatusForbidden},
		{"mismatched localhost origin", http.MethodPost, host, "http://localhost:9002", "application/json", `{"target":"localhost"}`, http.StatusForbidden},
		{"foreign host", http.MethodPost, "example.org:9002", origin, "application/json", `{"target":"localhost"}`, http.StatusForbidden},
		{"form body", http.MethodPost, host, origin, "text/plain", `{"target":"localhost"}`, http.StatusUnsupportedMediaType},
		{"outside range", http.MethodPost, host, origin, "application/json", `{"target":"192.0.2.1","force":true}`, http.StatusBadRequest},
		{"overlapping range", http.MethodPost, host, origin, "application/json", `{"target":"127.0.0.1/7","force":true}`, http.StatusBadRequest},
		{"blank target", http.MethodPost, host, origin, "application/json", `{"target":" "}`, http.StatusBadRequest},
		{"bad timeout", http.MethodPost, host, origin, "application/json", `{"target":"localhost","timeout":"later"}`, http.StatusBadRequest},
		{"negative timeout", http.MethodPost, host, origin, "application/json", `{"target":"localhost","timeout":"-5s"}`, http.StatusBadRequest},
		{"bad workers", http.MethodPost, host, origin, "application/json", `{"target":"localhost","workers":200}`, http.StatusBadRequest},
		{"bad ports text", http.MethodPost, host, origin, "application/json", `{"target":"localhost","ports":"abc"}`, http.StatusBadRequest},
		{"bad ports flag", http.MethodPost, host, origin, "application/json", `{"target":"localhost","ports":"-oN"}`, http.StatusBadRequest},
		{"client executable", http.MethodPost, host, origin, "application/json", `{"target":"localhost","nmap_path":"other"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://"+tc.host+"/api/scan", strings.NewReader(tc.body))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", tc.media)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestStatusAndChecksEndpoints(t *testing.T) {
	const host = "127.0.0.1:9002"
	h := newTestHandler(&fakeRunner{})

	t.Run("GET /api/status", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/api/status", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", w.Code)
		}
		var st tools.Status
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if st.Engine != "nuqs" || st.Addr != host || st.Modules != 1 {
			t.Fatalf("unexpected status: %+v", st)
		}
	})

	t.Run("GET /api/checks", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/api/checks?q=telnet", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", w.Code)
		}
		var items []tools.CheckInfo
		if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if len(items) != 1 || items[0].ID != "telnet-open" {
			t.Fatalf("unexpected checks: %+v", items)
		}
	})

	t.Run("reject non-GET", func(t *testing.T) {
		for _, path := range []string{"/api/status", "/api/checks"} {
			r := httptest.NewRequest(http.MethodPost, "http://"+host+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s POST: got %d, want 405", path, w.Code)
			}
		}
	})
}

func TestScanStreamsEventsAndReport(t *testing.T) {
	const telnetXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	runner := &fakeRunner{xml: []byte(telnetXML)}
	h := newTestHandler(runner)
	var savedReport *engine.Report
	h.OnReport = func(rep *engine.Report, _ string) {
		savedReport = rep
	}

	r := httptest.NewRequest(http.MethodPost, "http://localhost:9002/api/scan", strings.NewReader(`{"target":"localhost","ports":"23, 80, 443","timeout":"5s","workers":2}`))
	r.Header.Set("Origin", "http://localhost:9002")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("got Content-Type %q, want text/event-stream", ct)
	}
	if !slices.Contains(runner.args, "23,80,443") {
		t.Fatalf("expected normalized ports in nmap args, got %v", runner.args)
	}
	if savedReport == nil || len(savedReport.Findings) != 1 {
		t.Fatalf("expected OnReport callback with 1 finding, got %+v", savedReport)
	}

	var gotProgress, gotReport bool
	for _, frame := range strings.Split(w.Body.String(), "\n\n") {
		if !strings.HasPrefix(frame, "data: ") {
			continue
		}
		var msg SSEMessage
		if err := json.Unmarshal([]byte(strings.TrimPrefix(frame, "data: ")), &msg); err != nil {
			t.Fatalf("invalid SSE JSON %q: %v", frame, err)
		}
		if msg.Type == "progress" {
			gotProgress = true
		}
		if msg.Type == "report" && msg.Report != nil && len(msg.Report.Findings) == 1 {
			gotReport = true
		}
	}
	if !gotProgress || !gotReport {
		t.Fatalf("gotProgress=%v gotReport=%v", gotProgress, gotReport)
	}
}

func TestScanStreamsErrorWhenDiscoveryFails(t *testing.T) {
	const host = "127.0.0.1:9002"
	h := newTestHandler(&fakeRunner{err: errors.New("nmap unavailable")})
	r := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/scan", strings.NewReader(`{"target":"127.0.0.1"}`))
	r.Header.Set("Origin", "http://"+host)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"type":"error"`) || !strings.Contains(w.Body.String(), "nmap unavailable") {
		t.Fatalf("expected SSE error event, got: %s", w.Body.String())
	}

	// Missing Nmap should translate into a friendly install hint.
	h2 := newTestHandler(&fakeRunner{err: exec.ErrNotFound})
	r2 := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/scan", strings.NewReader(`{"target":"127.0.0.1","top_ports":100,"light_version":true}`))
	r2.Header.Set("Origin", "http://"+host)
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h2.ServeHTTP(w2, r2)
	if !strings.Contains(w2.Body.String(), "Nmap isn't installed") {
		t.Fatalf("expected friendly missing-nmap message, got: %s", w2.Body.String())
	}
}

func TestScanStreamsErrorWhenCancelled(t *testing.T) {
	const host = "127.0.0.1:9002"
	h := newTestHandler(&fakeRunner{err: context.Canceled})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/scan", strings.NewReader(`{"target":"127.0.0.1"}`)).WithContext(ctx)
	r.Header.Set("Origin", "http://"+host)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !strings.Contains(w.Body.String(), "Scan aborted by user.") {
		t.Fatalf("expected abort error event, got: %s", w.Body.String())
	}
}
