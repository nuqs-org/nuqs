// Tests GET /api/scans/{id}/diff.

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/store"
	"github.com/nuqs-org/nuqs/internal/tools"
)

// hostWithoutTelnetXML is the same host after telnet was turned off.
const hostWithoutTelnetXML = `<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports></ports></host></nmaprun>`

func TestDiffScan(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	runner := &fakeRunner{xml: []byte(telnetHostXML)}
	h := newTestHandler(runner)
	h.Scans = &tools.Scans{Service: h.Service, Store: st}
	t.Cleanup(h.Scans.StopAll)

	start := func() string {
		t.Helper()
		w := do(h, http.MethodPost, "/api/scans", `{"kind":"full","settings":{"target":"127.0.0.1"}}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("start: %d %s", w.Code, w.Body)
		}
		var s tools.Scan
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		waitDone(t, h, s.ID)
		return s.ID
	}
	first := start()
	if w := do(h, http.MethodGet, "/api/scans/"+first+"/diff", ""); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "no earlier") {
		t.Errorf("first scan: %d %s", w.Code, w.Body)
	}
	runner.xml = []byte(hostWithoutTelnetXML)
	second := start()

	for _, path := range []string{"/api/scans/" + second + "/diff", "/api/scans/" + second + "/diff?with=" + first} {
		w := do(h, http.MethodGet, path, "")
		var d diff.Result
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &d) != nil {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if len(d.Fixed) != 1 || d.Fixed[0].CheckID != "telnet-open" || d.Fixed[0].Reason != diff.PortClosed ||
			d.Fixed[0].FirstSeen.IsZero() || len(d.Notes) != 0 {
			t.Errorf("%s: %s", path, w.Body)
		}
	}

	cases := []struct {
		path string
		code int
	}{
		{"/api/scans/" + second + "/diff?with=x", http.StatusBadRequest},
		{"/api/scans/" + second + "/diff?with=0", http.StatusBadRequest},
		{"/api/scans/" + second + "/diff?with=" + second, http.StatusBadRequest},
		{"/api/scans/" + first + "/diff?with=" + second, http.StatusBadRequest},
		{"/api/scans/9/diff", http.StatusNotFound},
		{"/api/scans/9/diff?with=" + second, http.StatusNotFound},
		{"/api/scans/abc/diff", http.StatusNotFound},
	}
	for _, c := range cases {
		if w := do(h, http.MethodGet, c.path, ""); w.Code != c.code {
			t.Errorf("%s: got %d, want %d", c.path, w.Code, c.code)
		}
	}
}

func TestDiffScanRunningAndUnsaved(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	slow := &slowRunner{release: make(chan struct{})}
	h := newTestHandler(slow)
	h.Scans = &tools.Scans{Service: h.Service, Store: st}
	t.Cleanup(h.Scans.StopAll)
	if w := do(h, http.MethodPost, "/api/scans", `{"kind":"full","settings":{"target":"127.0.0.1"}}`); w.Code != http.StatusCreated {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	if w := do(h, http.MethodGet, "/api/scans/1/diff", ""); w.Code != http.StatusConflict {
		t.Errorf("running scan: %d %s", w.Code, w.Body)
	}
	close(slow.release)
	waitDone(t, h, "1")

	if w := do(newScansHandler(t, &fakeRunner{}), http.MethodGet, "/api/scans/1/diff", ""); w.Code != http.StatusNotFound {
		t.Errorf("no store: %d", w.Code)
	}
}
