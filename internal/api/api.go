// Package api serves the JSON and Server-Sent Events HTTP API for Nuqs.
//
// It is a thin HTTP layer over internal/tools so the API, web UI and CLI
// always enforce the same validation and produce the same scan reports.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/tools"
)

// SSEMessage is one Server-Sent Event frame streamed by POST /api/scan.
type SSEMessage struct {
	Type    string         `json:"type"`           // "progress", "report", "error"
	Kind    string         `json:"kind,omitempty"` // discovery_started, discovery_done, etc.
	Count   int            `json:"count,omitempty"`
	CheckID string         `json:"check_id,omitempty"`
	Host    string         `json:"host,omitempty"`
	Port    int            `json:"port,omitempty"`
	Report  *engine.Report `json:"report,omitempty"`
	Message string         `json:"message,omitempty"`
}

// Handler serves the /api/ endpoints backed by a shared tools.Service.
type Handler struct {
	Service  *tools.Service
	Addr     string
	OnReport func(rep *engine.Report, message string)
}

// New constructs an API handler for svc bound to addr.
func New(svc *tools.Service, addr string) *Handler {
	return &Handler{Service: svc, Addr: addr}
}

// Register attaches all /api/ routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", h.handleStatus)
	mux.HandleFunc("/api/checks", h.handleChecks)
	mux.HandleFunc("/api/scan", h.handleScan)
}

// ServeHTTP dispatches API requests on a standalone handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	h.Register(mux)
	mux.ServeHTTP(w, r)
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(h.Service.Status(h.Addr))
}

func (h *Handler) handleChecks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	items := h.Service.FilterChecks(r.URL.Query().Get("q"))
	_ = json.NewEncoder(w).Encode(items)
}

func (h *Handler) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !IsLocalOrigin(r, h.Addr) {
		http.Error(w, "Open the scan page on the local server.", http.StatusForbidden)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Expected application/json.", http.StatusUnsupportedMediaType)
		return
	}

	var req tools.ScanRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		http.Error(w, "Invalid scan settings.", http.StatusBadRequest)
		return
	}

	scan, err := h.Service.ValidateScan(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	flusher, hasFlusher := w.(http.Flusher)
	sendSSE := func(msg SSEMessage) {
		data, err := json.Marshal(msg)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		if hasFlusher {
			flusher.Flush()
		}
	}

	ctx := r.Context()
	rep, runErr := h.Service.RunValidated(ctx, scan, func(ev engine.Event) {
		sendSSE(SSEMessage{
			Type:    "progress",
			Kind:    string(ev.Kind),
			Count:   ev.Count,
			CheckID: ev.CheckID,
			Host:    ev.Host,
			Port:    ev.Port,
		})
	})

	if ctx.Err() != nil {
		sendSSE(SSEMessage{
			Type:    "error",
			Message: "Scan aborted by user.",
			Report:  rep,
		})
		return
	}

	if rep == nil && runErr != nil {
		sendSSE(SSEMessage{
			Type:    "error",
			Message: fmt.Sprintf("Scan failed: %v", runErr),
		})
		return
	}

	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	if h.OnReport != nil {
		h.OnReport(rep, errMsg)
	}

	sendSSE(SSEMessage{
		Type:    "report",
		Report:  rep,
		Message: errMsg,
	})
}

// IsLocalOrigin checks that Host is this local server (addr or localhost:<port>)
// and that the browser's Origin header matches it exactly.
func IsLocalOrigin(r *http.Request, addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return r.Host == addr && r.Header.Get("Origin") == "http://"+addr
	}
	if r.Host != addr && r.Host != "localhost:"+port {
		return false
	}
	return r.Header.Get("Origin") == "http://"+r.Host
}
