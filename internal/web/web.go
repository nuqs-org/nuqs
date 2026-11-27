// Package web serves the embedded HTML web interface for Nuqs.
//
// The pages follow the usual scanner flow: a list of scans, a gallery of
// scan types, a settings form, and a results page with hosts and
// vulnerabilities. Every page has its own URL. Templates and static assets
// are embedded in the binary with go:embed, and everything from a scan goes
// through html/template, so untrusted banners are always escaped.
package web

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/output"
	"github.com/nuqs-org/nuqs/internal/tools"
)

//go:embed templates/*.html static/*
var assets embed.FS

var severityLevels = []string{"critical", "high", "medium", "low", "info"}

const cspPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"

// pages are the full workspace pages, each filling the "content" block of layout.html.
var pages = []string{"scans.html", "new.html", "settings.html", "scan.html", "host.html", "finding.html", "checks.html", "check.html", "users.html"}

// authPages are standalone screens rendered without workspace chrome.
var authPages = []string{"setup.html", "login.html", "reset_password.html"}

// Handler serves the embedded Nuqs web UI pages, htmx partials and static assets.
type Handler struct {
	Service *tools.Service
	Scans   *tools.Scans
	Addr    string
	// Auth enables accounts, sessions, RBAC and user management pages when non-nil.
	Auth *auth.Service
	// HTTPS reports whether the server is listening over TLS.
	HTTPS bool

	pages     map[string]*template.Template
	authPages map[string]*template.Template
	parts     *template.Template
	static    http.Handler
	version   string // changes whenever a static file changes, see assetVersion
}

// New parses the embedded templates and returns a ready web Handler.
func New(svc *tools.Service, scans *tools.Scans, addr string) (*Handler, error) {
	funcs := template.FuncMap{
		"join":       strings.Join,
		"joinInts":   joinInts,
		"badgeClass": badgeClass,
		"duration":   formatDuration,
		"clock":      func(t time.Time) string { return t.Local().Format("Jan 2, 15:04:05") },
		"lower":      strings.ToLower,
		"whole":      func(f float64) int { return int(f) },
		"initials":   userInitials,
		"firstLine":  firstLine,
		"lines":      splitLines,
		"refHost":    refHost,
	}
	base, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/parts.html", "templates/checks_library.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse templates: %w", err)
	}
	authBase, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/auth_layout.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse auth layout: %w", err)
	}
	h := &Handler{
		Service:   svc,
		Scans:     scans,
		Addr:      addr,
		pages:     map[string]*template.Template{},
		authPages: map[string]*template.Template{},
		parts:     base,
	}
	for _, name := range pages {
		t, err := base.Clone()
		if err == nil {
			t, err = t.ParseFS(assets, "templates/"+name)
		}
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", name, err)
		}
		h.pages[name] = t
	}
	for _, name := range authPages {
		t, err := authBase.Clone()
		if err == nil {
			t, err = t.ParseFS(assets, "templates/"+name)
		}
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", name, err)
		}
		h.authPages[name] = t
	}
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, fmt.Errorf("web: open static assets: %w", err)
	}
	h.static = http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))
	h.version = assetVersion(staticFS)
	return h, nil
}

// assetVersion is a short hash of every static file. Pages link to
// /static/app.js?v=<hash>, so a browser never keeps an old copy after an update.
func assetVersion(files fs.FS) string {
	sum := sha256.New()
	_ = fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := fs.ReadFile(files, path)
			sum.Write([]byte(path))
			sum.Write(data)
		}
		return nil
	})
	return hex.EncodeToString(sum.Sum(nil))[:10]
}

// Register attaches the pages, htmx partials and static assets to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/scans", http.StatusFound)
	})
	mux.HandleFunc("GET /scans", h.scansPage)
	mux.HandleFunc("GET /scans/new", h.newPage)
	mux.HandleFunc("GET /scans/new/{kind}", h.settingsPage)
	mux.HandleFunc("GET /scans/{id}", h.scanPage)
	mux.HandleFunc("GET /scans/{id}/report/print", h.printPage)
	mux.HandleFunc("GET /scans/{id}/hosts/{host}", h.hostPage)
	mux.HandleFunc("GET /scans/{id}/vulns/{check}", h.findingPage)
	mux.HandleFunc("GET /checks", h.checksPage)
	mux.HandleFunc("GET /checks/{id}", h.checkPage)
	mux.HandleFunc("GET /partials/checks", h.checksPartial)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/nuqs-logo.png", http.StatusMovedPermanently)
	})
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.static.ServeHTTP(w, r)
	}))
	h.registerAuth(mux)
}

// ServeHTTP dispatches web requests on a standalone handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	h.Register(mux)
	var handler http.Handler = mux
	if h.Auth != nil {
		handler = h.Auth.Gate(handler)
	}
	handler.ServeHTTP(w, r)
}

// crumb is one step in the toolbar path, like "Scans / Office router".
type crumb struct {
	Label string
	Href  string
}

// page is what layout.html needs, plus the page's own data in Data.
type page struct {
	Version      string // the static files version, for cache busting
	Title        string
	Nav          string // which sidebar item is selected: "scans", "checks" or "users"
	Crumbs       []crumb
	Status       tools.Status
	User         *auth.Principal
	IsAdmin      bool
	FlashNotice  string
	FlashError   string
	AccountError string
	ReturnTo     string
	Data         any
}

type checksLibrary struct {
	Checks   []tools.CheckInfo
	Severity string
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	h.renderStatus(w, r, http.StatusOK, name, p)
}

func (h *Handler) renderStatus(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.Status = h.Service.Status(h.Addr)
	p.Version = h.version
	query := r.URL.Query()
	switch query.Get("account_error") {
	case "mismatch":
		p.AccountError = "New passwords do not match."
	case "current-password":
		p.AccountError = "Current password is incorrect."
	case "invalid-password":
		p.AccountError = "Enter a valid new password."
	case "update":
		p.AccountError = "Could not update password."
	}
	query.Del("account_error")
	query.Del("notice")
	returnTo := *r.URL
	returnTo.RawQuery = query.Encode()
	p.ReturnTo = returnTo.RequestURI()
	if h.Auth != nil {
		if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
			copyP := principal
			p.User = &copyP
			p.IsAdmin = principal.IsAdmin()
		}
	}
	if p.FlashNotice == "" {
		p.FlashNotice = noticeText(r.URL.Query().Get("notice"))
	}
	var buf bytes.Buffer
	if err := h.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	h.writeHTMLStatus(w, r, status, buf.Bytes())
}

func (h *Handler) writeHTMLStatus(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", cspPolicy)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	if h.HTTPS || (r != nil && r.TLS != nil) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_, _ = w.Write(body)
}

func writeHTML(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if w.Header().Get("Content-Security-Policy") == "" {
		w.Header().Set("Content-Security-Policy", cspPolicy)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// --- Scans list ---

type scanRow struct {
	tools.Scan
	Label  string // "Finished in 0.2s", "Scanning", "Stopped" and so on
	Class  string // CSS class for the status dot
	Counts sevCounts
}

type scansData struct {
	Rows            []scanRow
	Running         string // ID of the running scan, if any
	SuggestedTarget string
}

func (h *Handler) scansPage(w http.ResponseWriter, r *http.Request) {
	data := scansData{SuggestedTarget: suggestedTarget(h.Service.AllowedScope)}
	for _, s := range h.Scans.List() {
		if s.Status == tools.ScanRunning {
			data.Running = s.ID
		}
		data.Rows = append(data.Rows, scanRow{Scan: s, Label: statusLabel(s), Class: statusClass(s), Counts: countOf(s.Report)})
	}
	h.render(w, r, "scans.html", page{Title: "Scans", Nav: "scans", Crumbs: []crumb{{Label: "Scans"}}, Data: data})
}

// --- New scan: the gallery of scan types ---

// kind is one scan type card.
type kind struct {
	ID, Name, Desc, Time string
	Soon                 bool
}

var kinds = []kind{
	{ID: "discover", Name: "Discover hosts", Desc: "Finds which devices are on the network, without scanning their ports.", Soon: true},
	{ID: "quick", Name: "Quick scan", Desc: "The 100 most common ports with lighter version checks.", Time: "Usually under a minute"},
	{ID: "full", Name: "Full scan", Desc: "The 1,000 most common ports and every check.", Time: "Usually a few minutes"},
	{ID: "custom", Name: "Custom scan", Desc: "Pick the ports, host discovery and limits yourself."},
}

type galleryData struct {
	Discovery, Vulnerabilities []kind
}

func (h *Handler) newPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "new.html", page{
		Title: "New scan", Nav: "scans",
		Crumbs: []crumb{{Label: "Scans", Href: "/scans"}, {Label: "New scan"}},
		Data:   galleryData{Discovery: kinds[:1], Vulnerabilities: kinds[1:]},
	})
}

// --- New scan: settings for the chosen type ---

type settingsData struct {
	Kind                kind
	PortPreset          string
	LightVersion        bool
	OpenSection         string // the section shown first
	SuggestedTarget     string
	ScopeHint           string
	LocalNetwork        string
	LocalNetworkAllowed bool
}

func (h *Handler) settingsPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("kind")
	i := slices.IndexFunc(kinds, func(k kind) bool { return k.ID == id && !k.Soon })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	data := settingsData{
		Kind:            kinds[i],
		PortPreset:      "top1000",
		OpenSection:     "basic",
		SuggestedTarget: suggestedTarget(h.Service.AllowedScope),
		ScopeHint:       "You can scan this computer (127.0.0.1).",
		LocalNetwork:    localNetwork(),
	}
	if scope := tools.FormatAllowedScope(h.Service.AllowedScope); scope != "" {
		data.ScopeHint = "You can scan " + scope + "."
	}
	data.LocalNetworkAllowed = data.LocalNetwork != "" && tools.TargetAllowed(data.LocalNetwork, h.Service.AllowedScope)
	if id == "quick" {
		data.PortPreset, data.LightVersion = "top100", true
	}
	h.render(w, r, "settings.html", page{
		Title: "New " + strings.ToLower(kinds[i].Name), Nav: "scans",
		Crumbs: []crumb{{Label: "Scans", Href: "/scans"}, {Label: "New scan", Href: "/scans/new"}, {Label: kinds[i].Name}},
		Data:   data,
	})
}

// --- One scan's results ---

type sevCounts struct {
	Critical, High, Medium, Low, Info int
}

// Total is every finding.
func (c sevCounts) Total() int { return c.Critical + c.High + c.Medium + c.Low + c.Info }

func (c *sevCounts) add(s model.Severity) {
	switch s {
	case model.Critical:
		c.Critical++
	case model.High:
		c.High++
	case model.Medium:
		c.Medium++
	case model.Low:
		c.Low++
	default:
		c.Info++
	}
}

func countOf(rep *engine.Report) sevCounts {
	var c sevCounts
	if rep != nil {
		for _, f := range rep.Findings {
			c.add(f.Severity)
		}
	}
	return c
}

type hostRow struct {
	Address   string
	Hostnames []string
	Open      int
	Counts    sevCounts
}

type vulnRow struct {
	CheckID  string
	Title    string
	Severity string
	Hosts    int
}

type findingFilters struct {
	Severity   string
	Confidence model.Confidence
}

func (f findingFilters) Active() bool { return f.Severity != "" || f.Confidence != "" }

func readFindingFilters(query url.Values) findingFilters {
	var filters findingFilters
	if severity, err := model.ParseSeverity(query.Get("severity")); err == nil {
		filters.Severity = severity.String()
	}
	if confidence := model.Confidence(query.Get("confidence")); confidence.Valid() {
		filters.Confidence = confidence
	}
	return filters
}

func (f findingFilters) matches(finding model.Finding) bool {
	return (f.Severity == "" || finding.Severity.String() == f.Severity) &&
		(f.Confidence == "" || finding.Confidence == f.Confidence)
}

func (f findingFilters) DetailQuery() string {
	if !f.Active() {
		return ""
	}
	query := url.Values{}
	if f.Severity != "" {
		query.Set("severity", f.Severity)
	}
	if f.Confidence != "" {
		query.Set("confidence", string(f.Confidence))
	}
	return "?" + query.Encode()
}

func groupFindings(findings []model.Finding, filters findingFilters) []vulnRow {
	byCheck := map[string]*vulnRow{}
	type checkHost struct{ check, host string }
	seen := map[checkHost]bool{}
	for _, f := range findings {
		if !filters.matches(f) {
			continue
		}
		row := byCheck[f.CheckID]
		if row == nil {
			row = &vulnRow{CheckID: f.CheckID, Title: f.Title, Severity: f.Severity.String()}
			byCheck[f.CheckID] = row
		}
		key := checkHost{f.CheckID, f.Host}
		if !seen[key] {
			row.Hosts++
			seen[key] = true
		}
	}
	rows := make([]vulnRow, 0, len(byCheck))
	for _, row := range byCheck {
		rows = append(rows, *row)
	}
	slices.SortFunc(rows, func(a, b vulnRow) int {
		return cmp.Or(cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)), cmp.Compare(a.Title, b.Title), cmp.Compare(a.CheckID, b.CheckID))
	})
	return rows
}

type fixInstruction struct {
	CheckID, Title, Text string
}

type fixRow struct {
	SharedFix    string
	Title        string
	Severity     string
	Findings     int
	Hosts        int
	Instructions []fixInstruction
}

func groupByFix(findings []model.Finding, checks []check.Check) []fixRow {
	metadata := make(map[string]check.Info, len(checks))
	for _, c := range checks {
		info := c.Info()
		metadata[info.ID] = info
	}

	type fixKey struct{ remediation, check string }
	type group struct {
		row          fixRow
		highest      model.Severity
		hosts        map[string]bool
		instructions map[fixInstruction]bool
	}
	groups := map[fixKey]*group{}
	for _, finding := range findings {
		info := metadata[finding.CheckID]
		key := fixKey{remediation: info.RemediationID}
		if key.remediation == "" {
			key.check = finding.CheckID
		}
		g := groups[key]
		if g == nil {
			title := info.RemediationTitle
			if title == "" {
				title = finding.Title
			}
			g = &group{row: fixRow{Title: title, SharedFix: info.RemediationFix}, highest: finding.Severity, hosts: map[string]bool{}, instructions: map[fixInstruction]bool{}}
			groups[key] = g
		}
		g.highest = max(g.highest, finding.Severity)
		g.row.Findings++
		g.hosts[finding.Host] = true
		instruction := fixInstruction{CheckID: finding.CheckID, Title: finding.Title, Text: finding.Fix}
		if !g.instructions[instruction] {
			g.instructions[instruction] = true
			g.row.Instructions = append(g.row.Instructions, instruction)
		}
	}
	rows := make([]fixRow, 0, len(groups))
	for _, g := range groups {
		g.row.Severity = g.highest.String()
		g.row.Hosts = len(g.hosts)
		slices.SortFunc(g.row.Instructions, func(a, b fixInstruction) int {
			return cmp.Or(cmp.Compare(a.Title, b.Title), cmp.Compare(a.CheckID, b.CheckID), cmp.Compare(a.Text, b.Text))
		})
		rows = append(rows, g.row)
	}
	slices.SortFunc(rows, func(a, b fixRow) int {
		return cmp.Or(cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)),
			cmp.Compare(a.Title, b.Title), cmp.Compare(a.Instructions[0].CheckID, b.Instructions[0].CheckID))
	})
	return rows
}

type detail struct{ Label, Value string }

type scanData struct {
	tools.Scan
	Tab        string // "hosts", "vulns" or "fixes"
	Label      string
	Class      string
	Counts     sevCounts
	Donut      template.CSS
	Hosts      []hostRow
	Vulns      []vulnRow
	Fixes      []fixRow
	Filters    findingFilters
	TotalVulns int
	Errors     []engine.CheckError
	Details    []detail
}

func (h *Handler) scanPage(w http.ResponseWriter, r *http.Request) {
	s, ok := h.Scans.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	data := scanData{Scan: s, Tab: "hosts", Label: statusLabel(s), Class: statusClass(s), Counts: countOf(s.Report)}
	query := r.URL.Query()
	if query.Get("tab") == "vulns" {
		data.Tab = "vulns"
		data.Filters = readFindingFilters(query)
	} else if query.Get("tab") == "fixes" {
		data.Tab = "fixes"
	}
	data.Donut = donut(data.Counts)
	data.Details = scanDetails(s)
	if rep := s.Report; rep != nil {
		data.Errors = rep.Errors
		data.Fixes = groupByFix(rep.Findings, h.Service.Checks())
		for _, host := range rep.Hosts {
			row := hostRow{Address: host.Address, Hostnames: host.Hostnames, Open: len(host.Services)}
			for _, f := range rep.Findings {
				if f.Host == host.Address {
					row.Counts.add(f.Severity)
				}
			}
			data.Hosts = append(data.Hosts, row)
		}
		all := groupFindings(rep.Findings, findingFilters{})
		data.TotalVulns = len(all)
		data.Vulns = all
		if data.Filters.Active() {
			data.Vulns = groupFindings(rep.Findings, data.Filters)
		}
		slices.SortFunc(data.Hosts, func(a, b hostRow) int {
			return cmp.Or(cmp.Compare(b.Counts.Critical, a.Counts.Critical), cmp.Compare(b.Counts.High, a.Counts.High),
				cmp.Compare(b.Counts.Total(), a.Counts.Total()), cmp.Compare(a.Address, b.Address))
		})
	}
	h.render(w, r, "scan.html", page{
		Title: s.Name, Nav: "scans",
		Crumbs: []crumb{{Label: "Scans", Href: "/scans"}, {Label: s.Name}},
		Data:   data,
	})
}

func (h *Handler) printPage(w http.ResponseWriter, r *http.Request) {
	s, ok := h.Scans.Get(r.PathValue("id"))
	if !ok || s.Report == nil {
		http.NotFound(w, r)
		return
	}
	var body bytes.Buffer
	if err := output.HTML(&body, s.Report); err != nil {
		http.Error(w, "Could not create this report.", http.StatusInternalServerError)
		return
	}
	title := template.HTMLEscapeString(fmt.Sprintf("Nuqs scan %s — %s", s.ID, s.Started.Format("2006-01-02")))
	html := bytes.Replace(body.Bytes(), []byte("<title>Nuqs scan report</title>"), []byte("<title>"+title+"</title>"), 1)
	html = bytes.Replace(html, []byte("</body>"), []byte(`<script src="/static/print.js"></script></body>`), 1)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeHTML(w, html)
}

// scanDetails is the "Scan details" side panel.
func scanDetails(s tools.Scan) []detail {
	ports := "Top 1,000"
	switch {
	case s.Settings.Ports != "":
		ports = s.Settings.Ports
	case s.Settings.TopPorts > 0:
		ports = "Top " + strconv.Itoa(s.Settings.TopPorts)
	}
	discovery := "Ping first"
	if s.Settings.SkipPing {
		discovery = "Scan every address"
	}
	out := []detail{
		{"Type", s.KindName()},
		{"Targets", strings.Join(s.Targets, ", ")},
		{"Ports", ports},
		{"Host discovery", discovery},
		{"Started", s.Started.Local().Format("Jan 2, 15:04:05")},
	}
	if s.StartedBy != "" {
		out = append(out, detail{"Started by", s.StartedBy})
	}
	if !s.Finished.IsZero() {
		out = append(out, detail{"Took", formatDuration(s.Elapsed().Seconds())})
	}
	return out
}

// donut draws the severity ring with a CSS conic gradient.
func donut(c sevCounts) template.CSS {
	total := c.Total()
	if total == 0 {
		return template.CSS("background:conic-gradient(var(--rule) 0 100%)")
	}
	parts := []struct {
		n     int
		color string
	}{{c.Critical, "var(--critical)"}, {c.High, "var(--high)"}, {c.Medium, "var(--medium)"}, {c.Low, "var(--low)"}, {c.Info, "var(--sub)"}}
	var stops []string
	at := 0.0
	for _, p := range parts {
		if p.n == 0 {
			continue
		}
		next := at + float64(p.n)/float64(total)*100
		stops = append(stops, fmt.Sprintf("%s %.2f%% %.2f%%", p.color, at, next))
		at = next
	}
	return template.CSS("background:conic-gradient(" + strings.Join(stops, ",") + ")")
}

// statusLabel says where a scan is, with the real time it took.
func statusLabel(s tools.Scan) string {
	took := formatDuration(s.Elapsed().Seconds())
	switch s.Status {
	case tools.ScanRunning:
		return fmt.Sprintf("Scanning · %d%%", int(s.Percent))
	case tools.ScanStopped:
		return "Stopped after " + took
	case tools.ScanFailed:
		return "Failed"
	}
	if s.Error != "" || (s.Report != nil && len(s.Report.Errors) > 0) {
		return "Finished with errors in " + took
	}
	return "Finished in " + took
}

// statusClass picks the status dot colour: amber when a scan finished but
// some checks couldn't, so it doesn't look as clean as a full run.
func statusClass(s tools.Scan) string {
	if s.Status == tools.ScanCompleted && (s.Error != "" || (s.Report != nil && len(s.Report.Errors) > 0)) {
		return "partial"
	}
	return string(s.Status)
}

// --- One host ---

type hostData struct {
	ScanID   string
	ScanName string
	Host     model.Host
	Findings []model.Finding
	Errors   []engine.CheckError
	Counts   sevCounts
}

func (h *Handler) hostPage(w http.ResponseWriter, r *http.Request) {
	s, ok := h.Scans.Get(r.PathValue("id"))
	if !ok || s.Report == nil {
		http.NotFound(w, r)
		return
	}
	addr := r.PathValue("host")
	i := slices.IndexFunc(s.Report.Hosts, func(host model.Host) bool { return host.Address == addr })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	data := hostData{ScanID: s.ID, ScanName: s.Name, Host: s.Report.Hosts[i]}
	for _, f := range s.Report.Findings {
		if f.Host == addr {
			data.Findings = append(data.Findings, f)
			data.Counts.add(f.Severity)
		}
	}
	for _, e := range s.Report.Errors {
		if e.Host == addr {
			data.Errors = append(data.Errors, e)
		}
	}
	h.render(w, r, "host.html", page{
		Title: addr, Nav: "scans",
		Crumbs: []crumb{{Label: "Scans", Href: "/scans"}, {Label: s.Name, Href: "/scans/" + s.ID}, {Label: addr}},
		Data:   data,
	})
}

// --- One vulnerability, on every host that has it ---

type findingInstance struct {
	model.Finding
	Hostnames     []string
	EvidenceLines []string
	ServiceDetail string
	FirstSeen     time.Time
	LastSeen      time.Time
	Reopened      bool
}

type findingData struct {
	ScanID        string
	CurrentScanID int64
	ScanName      string
	CheckID       string
	HasCheck      bool
	Title         string
	Description   string
	Severity      string
	Fix           string
	Looks         string // what the check looks at, like "ports 23 · telnet"
	References    []check.Reference
	Instances     []findingInstance
	Timelines     []diff.Timeline
	ReopenedHosts []string
	HostCount     int
}

func (h *Handler) findingPage(w http.ResponseWriter, r *http.Request) {
	s, ok := h.Scans.Get(r.PathValue("id"))
	if !ok || s.Report == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("check")
	curID, _ := strconv.ParseInt(s.ID, 10, 64)
	data := findingData{ScanID: s.ID, CurrentScanID: curID, ScanName: s.Name, CheckID: id}
	filters := readFindingFilters(r.URL.Query())
	hostNames, svcDetails := indexReportServices(s.Report.Hosts)
	hosts := map[string]bool{}
	var findingIDs []string
	for _, f := range s.Report.Findings {
		if f.CheckID != id {
			continue
		}
		if data.Title == "" || filters.matches(f) {
			data.Title, data.Severity, data.Fix = f.Title, f.Severity.String(), f.Fix
		}
		if filters.matches(f) {
			data.Instances = append(data.Instances, findingInstance{
				Finding:       f,
				Hostnames:     hostNames[f.Host],
				EvidenceLines: splitLines(f.Evidence),
				ServiceDetail: svcDetails[serviceKey(f.Host, f.Port, f.Protocol)],
			})
			findingIDs = append(findingIDs, f.ID)
			hosts[f.Host] = true
		}
	}
	if data.Severity == "" {
		http.NotFound(w, r)
		return
	}
	data.HostCount = len(hosts)
	timelines := h.Scans.FindingTimelines(s.ID, findingIDs)
	for i := range data.Instances {
		inst := &data.Instances[i]
		tl, ok := timelines[inst.ID]
		if !ok {
			continue
		}
		inst.FirstSeen = tl.FirstSeen
		inst.LastSeen = tl.LastSeen
		inst.Reopened = tl.Reopened
		data.Timelines = append(data.Timelines, tl)
		if tl.Reopened {
			data.ReopenedHosts = append(data.ReopenedHosts, fmt.Sprintf("%s:%d", inst.Host, inst.Port))
		}
	}
	back := "/scans/" + s.ID + "?tab=vulns"
	if filters.Active() {
		back += "&" + strings.TrimPrefix(filters.DetailQuery(), "?")
	}
	if r.URL.Query().Get("from") == "fixes" {
		back = "/scans/" + s.ID + "?tab=fixes"
	}
	if c, ok := h.Service.CheckByID(id); ok {
		data.HasCheck = true
		data.Description = c.Description
		data.References = c.References
		var looks []string
		if len(c.Ports) > 0 {
			looks = append(looks, "ports "+joinInts(c.Ports, ", "))
		}
		looks = append(looks, c.Services...)
		data.Looks = strings.Join(looks, " · ")
	}
	h.render(w, r, "finding.html", page{
		Title: data.Title, Nav: "scans",
		Crumbs: []crumb{{Label: "Scans", Href: "/scans"}, {Label: s.Name, Href: back}, {Label: data.Title}},
		Data:   data,
	})
}

// --- Check library ---

func (h *Handler) checksPage(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	h.render(w, r, "checks.html", page{Title: "Check library", Nav: "checks", Crumbs: []crumb{{Label: "Check library"}}, Data: checksLibrary{Checks: h.Service.FilterChecksWithSeverity(r.URL.Query().Get("q"), severity), Severity: severity}})
}

func (h *Handler) checkPage(w http.ResponseWriter, r *http.Request) {
	c, ok := h.Service.CheckByID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.render(w, r, "check.html", page{
		Title:  c.Title,
		Nav:    "checks",
		Crumbs: []crumb{{Label: "Check library", Href: "/checks"}, {Label: c.Title}},
		Data:   c,
	})
}

func (h *Handler) checksPartial(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if err := h.parts.ExecuteTemplate(&buf, "checks_library.html", h.Service.FilterChecksWithSeverity(r.URL.Query().Get("q"), r.URL.Query().Get("severity"))); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	writeHTML(w, buf.Bytes())
}

// --- Helpers ---

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func refHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return strings.TrimPrefix(u.Host, "www.")
}

func serviceKey(host string, port int, proto string) string {
	return fmt.Sprintf("%s|%d/%s", host, port, proto)
}

func indexReportServices(hosts []model.Host) (map[string][]string, map[string]string) {
	names := make(map[string][]string, len(hosts))
	svcs := map[string]string{}
	for _, h := range hosts {
		if len(h.Hostnames) > 0 {
			names[h.Address] = h.Hostnames
		}
		for _, svc := range h.Services {
			svcs[serviceKey(h.Address, svc.Port, svc.Protocol)] = formatServiceDetail(svc)
		}
	}
	return names, svcs
}

func formatServiceDetail(svc model.Service) string {
	var parts []string
	if svc.Port > 0 && svc.Protocol != "" {
		parts = append(parts, fmt.Sprintf("port %d/%s", svc.Port, svc.Protocol))
	}
	if svc.Name != "" {
		parts = append(parts, svc.Name)
	}
	if product := strings.TrimSpace(svc.Product + " " + svc.Version); product != "" {
		parts = append(parts, product)
	}
	if svc.Tunnel == "ssl" {
		parts = append(parts, "over TLS")
	}
	if svc.Guessed {
		parts = append(parts, "guessed from port")
	}
	return strings.Join(parts, " · ")
}

func joinInts(nums []int, sep string) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, sep)
}

func formatDuration(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 0 && seconds < 0.1 {
		return fmt.Sprintf("%.2fs", seconds)
	}
	if seconds >= 60 {
		return fmt.Sprintf("%dm %ds", int(seconds)/60, int(seconds)%60)
	}
	return fmt.Sprintf("%.1fs", seconds)
}

// suggestedTarget is one address the user may scan, for placeholders and the
// "Scan this" button. A single host keeps that first scan quick.
func suggestedTarget(allowed []netip.Prefix) string {
	if tools.TargetAllowed("127.0.0.1", allowed) {
		return "127.0.0.1"
	}
	p := allowed[0]
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.Masked().Addr().Next().String() // like 192.168.1.1 for 192.168.1.0/24
}

// interfaceAddrs lists this machine's addresses. Tests swap it out.
var interfaceAddrs = net.InterfaceAddrs

// localNetwork returns the first private IPv4 network this machine is on,
// like "192.168.1.0/24", for the "use my network" button. Networks bigger
// than a /24 are cut down to the /24 around our address, so one click never
// means a huge scan. It returns "" when there's none.
func localNetwork() string {
	addrs, err := interfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() || !ip.IsPrivate() {
			continue
		}
		bits, _ := ipnet.Mask.Size()
		if bits < 24 {
			bits = 24
		}
		return netip.PrefixFrom(ip, bits).Masked().String()
	}
	return ""
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
