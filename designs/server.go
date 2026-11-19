// Package main provides a lightweight, zero-dependency development server
// for the Nuqs Network Vulnerability Audit Workbench.
//
// Usage:
//   go run ./designs/server.go
//
// Then open http://127.0.0.1:9002 in your browser.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/checks"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/target"
)

type StatusResponse struct {
	Engine   string   `json:"engine"`
	Version  string   `json:"version"`
	Runner   string   `json:"runner"`
	Uptime   string   `json:"uptime"`
	Modules  int      `json:"modules"`
	Loaded   []string `json:"loaded"`
	Addr     string   `json:"addr"`
	Status   string   `json:"status"`
}

type CheckItem struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Fix      string   `json:"fix"`
	Ports    []int    `json:"ports"`
	Services []string `json:"services"`
}

type ScanRequest struct {
	Target   string `json:"target"`
	Ports    string `json:"ports"`
	SkipPing bool   `json:"skip_ping"`
	Force    bool   `json:"force"`
	Workers  int    `json:"workers"`
	Timeout  string `json:"timeout"`
	NmapPath string `json:"nmap_path"`
}

type SSEMessage struct {
	Type     string         `json:"type"`                // "progress", "report", "error"
	Kind     string         `json:"kind,omitempty"`      // DiscoveryStarted, DiscoveryDone, etc.
	Count    int            `json:"count,omitempty"`
	CheckID  string         `json:"check_id,omitempty"`
	Host     string         `json:"host,omitempty"`
	Port     int            `json:"port,omitempty"`
	Report   *engine.Report `json:"report,omitempty"`
	Message  string         `json:"message,omitempty"`
}

var startTime = time.Now()

func main() {
	port := "9002"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	// 1. Static file serving (delivers index.html and design assets)
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get working dir: %v", err)
	}
	designsPath := filepath.Join(dir, "designs")

	fs := http.FileServer(http.Dir(designsPath))
	mux.Handle("/", fs)

	// 2. REST API: GET /api/status
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		allChecks := checks.All()
		var ids []string
		for _, c := range allChecks {
			ids = append(ids, c.Info().ID)
		}
		resp := StatusResponse{
			Engine:  "nuqs",
			Version: "v0.1.0-alpha",
			Runner:  "nmap",
			Uptime:  time.Since(startTime).Truncate(time.Second).String(),
			Modules: len(allChecks),
			Loaded:  ids,
			Addr:    "127.0.0.1:" + port,
			Status:  "READY",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 3. REST API: GET /api/checks
	mux.HandleFunc("/api/checks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		allChecks := checks.All()
		var items []CheckItem
		for _, c := range allChecks {
			info := c.Info()
			items = append(items, CheckItem{
				ID:       info.ID,
				Severity: info.Severity.String(),
				Title:    info.Title,
				Fix:      info.Fix,
				Ports:    info.Ports,
				Services: info.Services,
			})
		}
		_ = json.NewEncoder(w).Encode(items)
	})

	// 4. LIVE SCAN API: POST /api/scan (Streams events via SSE directly from engine.Engine)
	mux.HandleFunc("/api/scan", handleScan)

	serverAddr := "127.0.0.1:" + port
	fmt.Printf("\n=======================================================\n")
	fmt.Printf(" [:: NUQS LIVE AUDIT WORKBENCH SERVER RUNNING]\n")
	fmt.Printf("=======================================================\n")
	fmt.Printf(" Local URL: http://%s\n", serverAddr)
	fmt.Printf(" Design Lab Dir: %s\n", designsPath)
	fmt.Printf(" Engine Modules: %d registered security checks\n", len(checks.All()))
	fmt.Printf(" Real-time Nmap Integration: ACTIVE\n")
	fmt.Printf(" Press Ctrl+C to stop.\n\n")

	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatalf("server terminated: %v", err)
	}
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	targetStr := strings.TrimSpace(req.Target)
	if targetStr == "" {
		targetStr = "127.0.0.1"
	}

	limit := int64(target.DefaultLimit)
	if req.Force {
		limit = 0
	}

	targets, _, err := target.Parse([]string{targetStr}, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid target: %v", err), http.StatusBadRequest)
		return
	}

	workers := req.Workers
	if workers < 1 {
		workers = engine.DefaultWorkers
	}

	timeout := engine.DefaultCheckTimeout
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil && d > 0 {
			timeout = d
		}
	}

	// Setup Server-Sent Events headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

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

	eng := &engine.Engine{
		Scanner: nmap.Scanner{
			Runner: nmap.ExecRunner{Path: req.NmapPath},
			Options: nmap.Options{
				Ports:    req.Ports,
				SkipPing: req.SkipPing,
			},
		},
		Checks:       checks.All(),
		Workers:      workers,
		CheckTimeout: timeout,
		OnEvent: func(ev engine.Event) {
			sendSSE(SSEMessage{
				Type:    "progress",
				Kind:    string(ev.Kind),
				Count:   ev.Count,
				CheckID: ev.CheckID,
				Host:    ev.Host,
				Port:    ev.Port,
			})
		},
	}

	// Run scan with request context (enables immediate cancellation via browser Stop button)
	ctx := r.Context()
	rep, runErr := eng.Run(ctx, targets)

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
	if runErr != nil && !errorsIsContext(runErr) {
		errMsg = runErr.Error()
	}

	sendSSE(SSEMessage{
		Type:    "report",
		Report:  rep,
		Message: errMsg,
	})
}

func errorsIsContext(err error) bool {
	return strings.Contains(err.Error(), context.Canceled.Error()) || strings.Contains(err.Error(), "context deadline exceeded")
}
