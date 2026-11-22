// Package api serves the JSON and Server-Sent Events HTTP API for Nuqs.
//
// Scans start with POST /api/scans and run in the background. Follow one
// live with GET /api/scans/{id}/events and read the result with
// GET /api/scans/{id}.
//
// It is a thin HTTP layer over internal/tools so the API, web UI and CLI
// always enforce the same validation and produce the same scan reports.
package api

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/nuqs-org/nuqs/internal/tools"
)

// Handler serves the /api/ endpoints backed by a shared tools.Service.
type Handler struct {
	Service *tools.Service
	Addr    string
	// Scans runs scans in the background. Nil leaves out /api/scans.
	Scans *tools.Scans
}

// New constructs an API handler for svc bound to addr.
func New(svc *tools.Service, addr string) *Handler {
	return &Handler{Service: svc, Addr: addr}
}

// Register attaches all /api/ routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", h.handleStatus)
	mux.HandleFunc("/api/checks", h.handleChecks)
	h.registerScans(mux)
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
