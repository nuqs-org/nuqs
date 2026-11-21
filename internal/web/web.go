// Package web serves the embedded HTML web interface for Nuqs.
//
// Templates and static assets (CSS, htmx, logo and client helper script) are
// embedded directly in the binary via go:embed. Every dynamic value from a
// scan is rendered through html/template so untrusted banners are always escaped.
package web

import (
	"bytes"
	"cmp"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/tools"
)

//go:embed templates/*.html static/*
var assets embed.FS

var severityLevels = []string{"critical", "high", "medium", "low", "info"}

const cspPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"

// Handler serves the embedded Nuqs web UI pages, htmx partials and static assets.
type Handler struct {
	Service *tools.Service
	Addr    string

	tmpl   *template.Template
	static http.Handler

	mu          sync.RWMutex
	lastReport  *engine.Report
	lastMessage string
}

// New parses the embedded templates and returns a ready web Handler.
func New(svc *tools.Service, addr string) (*Handler, error) {
	funcs := template.FuncMap{
		"join": strings.Join,
		"joinInts": func(nums []int, sep string) string {
			parts := make([]string, len(nums))
			for i, n := range nums {
				parts[i] = strconv.Itoa(n)
			}
			return strings.Join(parts, sep)
		},
		"badgeClass": badgeClass,
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse templates: %w", err)
	}
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, fmt.Errorf("web: open static assets: %w", err)
	}
	return &Handler{
		Service: svc,
		Addr:    addr,
		tmpl:    tmpl,
		static:  http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))),
	}, nil
}

// Register attaches the HTML workspace, htmx partial endpoints and static assets to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/partials/checks", h.handleChecksPartial)
	mux.HandleFunc("/partials/inventory", h.handleInventoryPartial)
	mux.HandleFunc("/partials/report", h.handleReportPartial)
	mux.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h.static.ServeHTTP(w, r)
	}))
}

// ServeHTTP dispatches web requests on a standalone handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	h.Register(mux)
	mux.ServeHTTP(w, r)
}

// SetReport stores the most recent scan report so server-rendered partials
// and page refreshes display it immediately.
func (h *Handler) SetReport(rep *engine.Report, message string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastReport = rep
	h.lastMessage = message
}

// LatestReport returns the most recent stored scan report and any warning message.
func (h *Handler) LatestReport() (*engine.Report, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lastReport, h.lastMessage
}

type indexData struct {
	Status    tools.Status
	ScopeHint string
	Checks    []tools.CheckInfo
	HasReport bool
	Report    reportView
}

type countBadge struct {
	Level string
	Count int
	Class string
}

type findingView struct {
	Severity string
	Title    string
	Host     string
	Port     int
	Protocol string
	CheckID  string
	Evidence string
	Fix      string
}

type reportView struct {
	HasReport        bool
	Restored         bool
	StatusLine       string
	MetadataLine     string
	Counts           []countBadge
	SelectedSeverity string
	RawJSON          string
	Findings         []findingView
	EmptyMessage     string
	Incomplete       bool
	Message          string
	Errors           []engine.CheckError
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := h.Service.Status(h.Addr)
	scopeHint := "Use localhost or a range within 127.0.0.0/8."
	if status.AllowedScope != "" {
		scopeHint = "Allowed scope: " + status.AllowedScope + "."
	}
	rep, msg := h.LatestReport()
	data := indexData{
		Status:    status,
		ScopeHint: scopeHint,
		Checks:    h.Service.ListChecks(),
		HasReport: rep != nil,
		Report:    buildReportView(rep, msg, "", true),
	}
	h.renderHTML(w, "index.html", data)
}

func (h *Handler) handleChecksPartial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	checks := h.Service.FilterChecks(r.URL.Query().Get("q"))
	h.renderHTML(w, "checks_library.html", checks)
}

func (h *Handler) handleInventoryPartial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.renderHTML(w, "checks_inventory.html", h.Service.ListChecks())
}

func (h *Handler) handleReportPartial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rep, msg := h.LatestReport()
	severity := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity")))
	restored := r.URL.Query().Get("fresh") != "1"
	view := buildReportView(rep, msg, severity, restored)
	h.renderHTML(w, "report.html", view)
}

func (h *Handler) renderHTML(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", cspPolicy)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(buf.Bytes())
}

func buildReportView(rep *engine.Report, message, selectedSeverity string, restored bool) reportView {
	if rep == nil {
		return reportView{SelectedSeverity: selectedSeverity, Restored: restored}
	}
	if !slices.Contains(severityLevels, selectedSeverity) {
		selectedSeverity = ""
	}
	duration := rep.Finished.Sub(rep.Started).Seconds()
	if duration < 0 {
		duration = 0
	}
	incomplete := message != "" || len(rep.Errors) > 0
	outcome := "Scan finished"
	if incomplete {
		outcome = "Scan incomplete"
	}
	prefix := ""
	if restored {
		prefix = "Last report · "
	}
	statusLine := fmt.Sprintf("%s%s in %.2fs", prefix, outcome, duration)

	openServices := 0
	for _, host := range rep.Hosts {
		openServices += len(host.Services)
	}
	hostWord := "hosts"
	if len(rep.Hosts) == 1 {
		hostWord = "host"
	}
	svcWord := "open services"
	if openServices == 1 {
		svcWord = "open service"
	}
	metadataLine := fmt.Sprintf("%s · %d %s up · %d %s · %s",
		strings.Join(rep.Targets, ", "),
		len(rep.Hosts), hostWord,
		openServices, svcWord,
		rep.Finished.Local().Format("2006-01-02 15:04:05"),
	)

	countMap := make(map[string]int, len(severityLevels))
	for _, f := range rep.Findings {
		countMap[f.Severity.String()]++
	}
	counts := make([]countBadge, 0, len(severityLevels))
	for _, level := range severityLevels {
		n := countMap[level]
		cls := "info"
		if n > 0 {
			cls = level
		}
		counts = append(counts, countBadge{Level: level, Count: n, Class: cls})
	}

	findings := make([]findingView, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		sev := f.Severity.String()
		if selectedSeverity != "" && sev != selectedSeverity {
			continue
		}
		findings = append(findings, findingView{
			Severity: sev,
			Title:    f.Title,
			Host:     f.Host,
			Port:     f.Port,
			Protocol: f.Protocol,
			CheckID:  f.CheckID,
			Evidence: f.Evidence,
			Fix:      f.Fix,
		})
	}
	slices.SortFunc(findings, func(a, b findingView) int {
		return cmp.Or(
			cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)),
			cmp.Compare(a.Host, b.Host),
			cmp.Compare(a.Port, b.Port),
			cmp.Compare(a.CheckID, b.CheckID),
		)
	})

	emptyMessage := "No findings reported."
	if selectedSeverity != "" {
		emptyMessage = "No findings at this severity."
	} else if len(rep.Hosts) == 0 {
		emptyMessage = "No live hosts responded (try Skip host discovery if ping is blocked)."
	}

	rawBytes, _ := json.MarshalIndent(rep, "", "  ")
	return reportView{
		HasReport:        true,
		Restored:         restored,
		StatusLine:       statusLine,
		MetadataLine:     metadataLine,
		Counts:           counts,
		SelectedSeverity: selectedSeverity,
		RawJSON:          string(rawBytes),
		Findings:         findings,
		EmptyMessage:     emptyMessage,
		Incomplete:       incomplete,
		Message:          message,
		Errors:           rep.Errors,
	}
}

func badgeClass(level string) string {
	if slices.Contains(severityLevels, level) {
		return level
	}
	return "info"
}

func severityRank(level string) int {
	if i := slices.Index(severityLevels, level); i >= 0 {
		return i
	}
	return len(severityLevels)
}
