// Tests the status and checks endpoints. The scan endpoints are tested in scans_test.go.

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/nuqs-org/nuqs/checks/telnet"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/tools"
)

type fakeRunner struct {
	xml  []byte
	err  error
	args []string
}

func (f *fakeRunner) Run(_ context.Context, args []string, out io.Writer) error {
	f.args = slices.Clone(args)
	if _, err := out.Write(f.xml); err != nil {
		return err
	}
	return f.err
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
