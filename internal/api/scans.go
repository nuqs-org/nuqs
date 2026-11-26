// The /api/scans endpoints: start a scan in the background, list scans, follow one live, stop it and compare it with an older one.

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/output"
	"github.com/nuqs-org/nuqs/internal/tools"
)

// ScanSummary is a scan without its report, for lists.
type ScanSummary struct {
	tools.Scan
	Counts map[string]int `json:"counts,omitempty"` // findings per severity
}

// Progress is what GET /api/scans/{id}/events sends each time a scan changes.
type Progress struct {
	Status      tools.ScanStatus `json:"status"`
	Phase       string           `json:"phase,omitempty"`
	Percent     float64          `json:"percent"`             // the whole scan, 0 to 100, never goes down
	Remaining   string           `json:"remaining,omitempty"` // like "about 40s left"
	HostsFound  int              `json:"hosts_found"`
	ChecksDone  int              `json:"checks_done"`
	ChecksTotal int              `json:"checks_total"`
	Seconds     float64          `json:"seconds"` // how long it has run
	Error       string           `json:"error,omitempty"`
}

func (h *Handler) registerScans(mux *http.ServeMux) {
	if h.Scans == nil {
		return
	}
	mux.HandleFunc("GET /api/scans", h.listScans)
	mux.HandleFunc("POST /api/scans", h.startScan)
	mux.HandleFunc("GET /api/scans/{id}", h.getScan)
	mux.HandleFunc("GET /api/scans/{id}/report", h.downloadReport)
	mux.HandleFunc("GET /api/scans/{id}/report/{format}", h.downloadReport)
	mux.HandleFunc("GET /api/scans/{id}/events", h.scanEvents)
	mux.HandleFunc("POST /api/scans/{id}/stop", h.stopScan)
	mux.HandleFunc("GET /api/scans/{id}/diff", h.diffScan)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Summarize drops the report from a scan and counts its findings instead.
func Summarize(s tools.Scan) ScanSummary {
	out := ScanSummary{Scan: s}
	if s.Report != nil {
		out.Counts = map[string]int{}
		for _, f := range s.Report.Findings {
			out.Counts[f.Severity.String()]++
		}
	}
	out.Report = nil
	return out
}

func (h *Handler) listScans(w http.ResponseWriter, _ *http.Request) {
	list := h.Scans.List()
	out := make([]ScanSummary, len(list))
	for i, s := range list {
		out[i] = Summarize(s)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) startScan(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		http.Error(w, "Open the scan page on this server.", http.StatusForbidden)
		return
	}
	var startedBy string
	if h.Auth != nil {
		p, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, auth.ErrUnauthorized.Error(), http.StatusUnauthorized)
			return
		}
		startedBy = p.Username
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Expected application/json.", http.StatusUnsupportedMediaType)
		return
	}
	var in tools.NewScan
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		http.Error(w, "Invalid scan settings.", http.StatusBadRequest)
		return
	}
	in.StartedBy = startedBy
	s, err := h.Scans.Start(in)
	var ve *tools.ValidationError
	switch {
	case errors.As(err, &ve):
		http.Error(w, ve.Message, http.StatusBadRequest)
		return
	case errors.Is(err, tools.ErrBusy):
		http.Error(w, "A scan is already running. Wait for it to finish or stop it first.", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", "/scans/"+s.ID)
	writeJSON(w, http.StatusCreated, Summarize(s))
}

func (h *Handler) getScan(w http.ResponseWriter, r *http.Request) {
	s, ok := h.Scans.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "No scan with that ID.", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) downloadReport(w http.ResponseWriter, r *http.Request) {
	s, ok := h.Scans.Get(r.PathValue("id"))
	if !ok || s.Report == nil {
		http.Error(w, "This scan has no report yet.", http.StatusNotFound)
		return
	}
	format := r.PathValue("format")
	if format == "" {
		format = "json"
	}
	var body bytes.Buffer
	contentType := ""
	var err error
	switch format {
	case "json":
		contentType, err = "application/json", output.JSON(&body, s.Report)
	case "html":
		contentType, err = "text/html; charset=utf-8", output.HTML(&body, s.Report)
	case "csv":
		contentType, err = "text/csv; charset=utf-8", output.CSV(&body, s.Report)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Could not create this report.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="nuqs-scan-%s.%s"`, s.ID, format))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body.Bytes())
}

// diffScan says what changed since an older scan: ?with=<id>, or by default
// the last clean scan of the same targets and ports. The JSON is the same as
// "nuqs diff --json".
func (h *Handler) diffScan(w http.ResponseWriter, r *http.Request) {
	if h.Scans.Store == nil {
		http.Error(w, "Comparing needs saved scans.", http.StatusNotFound)
		return
	}
	cur, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || cur < 1 {
		http.Error(w, "No scan with that ID.", http.StatusNotFound)
		return
	}
	var old int64
	if with := r.URL.Query().Get("with"); with != "" {
		if old, err = strconv.ParseInt(with, 10, 64); err != nil || old < 1 {
			http.Error(w, "with should be the ID of an older scan.", http.StatusBadRequest)
			return
		}
	}
	d, err := tools.Compare(h.Scans.Store, old, cur)
	switch {
	case errors.Is(err, tools.ErrNotOlder):
		http.Error(w, "with should be the ID of an older scan.", http.StatusBadRequest)
	case errors.Is(err, tools.ErrNotFound):
		http.Error(w, "No scan with that ID.", http.StatusNotFound)
	case errors.Is(err, tools.ErrNoEarlierScan):
		http.Error(w, "There's no earlier finished scan of the same targets and ports to compare with.", http.StatusNotFound)
	case errors.Is(err, tools.ErrNoReport):
		http.Error(w, "This scan has no report yet.", http.StatusConflict)
	case err != nil:
		http.Error(w, "Could not compare these scans.", http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

func (h *Handler) stopScan(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		http.Error(w, "Open the scan page on this server.", http.StatusForbidden)
		return
	}
	if h.Auth != nil {
		if _, ok := auth.PrincipalFromContext(r.Context()); !ok {
			http.Error(w, auth.ErrUnauthorized.Error(), http.StatusUnauthorized)
			return
		}
	}
	if err := h.Scans.Stop(r.PathValue("id")); err != nil {
		http.Error(w, "No scan with that ID.", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// scanEvents streams the scan's progress with Server-Sent Events, one
// message per change, and ends after the scan finishes.
func (h *Handler) scanEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.Scans.Get(id); !ok {
		http.Error(w, "No scan with that ID.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, _ := w.(http.Flusher)

	// Changes can come in bursts (one per check), so send at most a few a second.
	const gap = 200 * time.Millisecond
	tick := time.NewTicker(time.Second) // keeps the elapsed time moving when nothing changes
	defer tick.Stop()
	for {
		s, changed, ok := h.Scans.Watch(id)
		if !ok {
			return
		}
		data, _ := json.Marshal(Progress{
			Status:      s.Status,
			Phase:       s.Phase,
			Percent:     s.Percent,
			Remaining:   s.Remaining,
			HostsFound:  s.HostsFound,
			ChecksDone:  s.ChecksDone,
			ChecksTotal: s.ChecksTotal,
			Seconds:     s.Elapsed().Seconds(),
			Error:       s.Error,
		})
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		if s.Status != tools.ScanRunning {
			return
		}
		select {
		case <-changed:
			time.Sleep(gap)
		case <-tick.C:
		case <-r.Context().Done():
			return
		}
	}
}

// LocalOnly refuses requests whose Host isn't this server, like
// "127.0.0.1:9002" or "localhost:9002". A web page on another site could
// otherwise point its own domain at 127.0.0.1 (DNS rebinding) and read
// scan results through the visitor's browser.
func LocalOnly(addr string, next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(addr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != addr && (port == "" || r.Host != "localhost:"+port) {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			http.Error(w, "Open Nuqs at "+scheme+"://"+addr, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
