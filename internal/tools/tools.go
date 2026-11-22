// Package tools holds the shared actions used by the CLI, HTTP API and web UI.
//
// Putting validation, scope enforcement, check lookup and scan execution in one
// place guarantees that the CLI, JSON API and web UI always enforce the same
// rules and return the same results.
package tools

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/target"
)

// ValidationError marks user-supplied scan settings that failed validation
// before a scan could start.
type ValidationError struct {
	Message string
}

// Error returns the human-readable validation message.
func (e *ValidationError) Error() string {
	return e.Message
}

// CheckInfo describes one built-in vulnerability check for display and API output.
type CheckInfo struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Fix      string   `json:"fix"`
	Ports    []int    `json:"ports"`
	Services []string `json:"services"`
}

// Status describes the running engine, loaded checks and configured scan scope.
type Status struct {
	Engine       string   `json:"engine"`
	Version      string   `json:"version"`
	Runner       string   `json:"runner"`
	Uptime       string   `json:"uptime"`
	Modules      int      `json:"modules"`
	Loaded       []string `json:"loaded"`
	Addr         string   `json:"addr"`
	AllowedScope string   `json:"allowed_scope,omitempty"`
	Status       string   `json:"status"`
}

// ScanRequest holds raw scan parameters from the CLI, JSON API or web UI.
type ScanRequest struct {
	Target       string `json:"target"`
	Ports        string `json:"ports"`
	TopPorts     int    `json:"top_ports,omitempty"`
	LightVersion bool   `json:"light_version,omitempty"`
	SkipPing     bool   `json:"skip_ping"`
	Force        bool   `json:"force"`
	Workers      int    `json:"workers"`
	Timeout      string `json:"timeout"`
}

// ValidatedScan holds cleaned, checked scan settings ready to run.
type ValidatedScan struct {
	Targets      []string
	Ports        string
	TopPorts     int
	LightVersion bool
	SkipPing     bool
	Workers      int
	Timeout      time.Duration
}

// Service runs Nuqs actions using a shared scanner, check list and target policy.
type Service struct {
	Version      string
	RunnerName   string
	NewRunner    func() nmap.Runner
	Checks       func() []check.Check
	AllowedScope []netip.Prefix
	EnforceScope bool
	MaxWorkers   int
	StartedAt    time.Time
}

// ListChecks returns metadata for every registered check.
func (s *Service) ListChecks() []CheckInfo {
	all := s.Checks()
	items := make([]CheckInfo, 0, len(all))
	for _, c := range all {
		info := c.Info()
		items = append(items, CheckInfo{
			ID:       info.ID,
			Severity: info.Severity.String(),
			Title:    info.Title,
			Fix:      info.Fix,
			Ports:    info.Ports,
			Services: info.Services,
		})
	}
	return items
}

// FilterChecks returns checks matching query across title, ID, severity, services and ports.
func (s *Service) FilterChecks(query string) []CheckInfo {
	items := s.ListChecks()
	term := strings.ToLower(strings.TrimSpace(query))
	if term == "" {
		return items
	}
	matched := make([]CheckInfo, 0, len(items))
	for _, item := range items {
		if checkMatches(item, term) {
			matched = append(matched, item)
		}
	}
	return matched
}

func checkMatches(item CheckInfo, term string) bool {
	if strings.Contains(strings.ToLower(item.Title), term) ||
		strings.Contains(strings.ToLower(item.ID), term) ||
		strings.Contains(strings.ToLower(item.Severity), term) {
		return true
	}
	for _, svc := range item.Services {
		if strings.Contains(strings.ToLower(svc), term) {
			return true
		}
	}
	for _, port := range item.Ports {
		if strings.Contains(strconv.Itoa(port), term) {
			return true
		}
	}
	return false
}

// Status returns a snapshot of the engine status and loaded checks.
func (s *Service) Status(addr string) Status {
	all := s.Checks()
	ids := make([]string, 0, len(all))
	for _, c := range all {
		ids = append(ids, c.Info().ID)
	}
	version := s.Version
	if version == "" {
		version = "dev"
	}
	runner := s.RunnerName
	if runner == "" {
		runner = "nmap"
	}
	started := s.StartedAt
	if started.IsZero() {
		started = time.Now()
	}
	return Status{
		Engine:       "nuqs",
		Version:      version,
		Runner:       runner,
		Uptime:       time.Since(started).Truncate(time.Second).String(),
		Modules:      len(all),
		Loaded:       ids,
		Addr:         addr,
		AllowedScope: FormatAllowedScope(s.AllowedScope),
		Status:       "READY",
	}
}

// ValidateScan checks targets, scope, ports, concurrency and timeout before starting a scan.
func (s *Service) ValidateScan(req ScanRequest) (ValidatedScan, error) {
	rawTarget := strings.TrimSpace(req.Target)
	if rawTarget == "" {
		return ValidatedScan{}, &ValidationError{Message: "Enter a target to scan, such as 127.0.0.1."}
	}
	limit := int64(target.DefaultLimit)
	if req.Force {
		limit = 0
	}
	targets, _, err := target.Parse([]string{rawTarget}, limit)
	if err != nil {
		if errors.Is(err, target.ErrTooMany) {
			return ValidatedScan{}, &ValidationError{
				Message: fmt.Sprintf("That target covers more than %d addresses. Confirm the big scan under the target to scan it anyway.", target.DefaultLimit),
			}
		}
		return ValidatedScan{}, &ValidationError{
			Message: fmt.Sprintf("Couldn't understand target (%v). Use an IP like 127.0.0.1, a CIDR like 192.168.1.0/24, a range like 192.168.1.1-20, or a hostname.", err),
		}
	}
	if s.EnforceScope {
		for i, spec := range targets {
			if spec == "localhost" {
				targets[i] = "127.0.0.1"
				spec = "127.0.0.1"
			}
			if !TargetAllowed(spec, s.AllowedScope) {
				if len(s.AllowedScope) == 0 {
					return ValidatedScan{}, &ValidationError{
						Message: "This server only scans loopback targets (127.0.0.0/8) by default. To scan other networks, restart with: nuqs serve --allow 192.168.1.0/24",
					}
				}
				return ValidatedScan{}, &ValidationError{
					Message: fmt.Sprintf("Target %q is outside the allowed scope (%s). Restart with --allow to expand it.", spec, FormatAllowedScope(s.AllowedScope)),
				}
			}
		}
	}

	ports := strings.TrimSpace(req.Ports)
	topPorts := req.TopPorts
	if topPorts < 0 || topPorts > 65535 {
		return ValidatedScan{}, &ValidationError{
			Message: "Top ports must be between 1 and 65535.",
		}
	}
	if ports != "" {
		normalized, ok := NormalizePorts(ports)
		if !ok {
			return ValidatedScan{}, &ValidationError{
				Message: "Enter valid ports such as 22,80,443 or 1-1000.",
			}
		}
		ports = normalized
		topPorts = 0
	}

	workers := req.Workers
	if workers == 0 {
		workers = engine.DefaultWorkers
	}
	if workers < 1 || (s.MaxWorkers > 0 && workers > s.MaxWorkers) {
		if s.MaxWorkers > 0 {
			return ValidatedScan{}, &ValidationError{
				Message: fmt.Sprintf("Concurrent checks must be between 1 and %d.", s.MaxWorkers),
			}
		}
		return ValidatedScan{}, &ValidationError{Message: "Concurrent checks must be at least 1."}
	}

	timeout := engine.DefaultCheckTimeout
	if req.Timeout != "" {
		timeout, err = time.ParseDuration(req.Timeout)
		if err != nil || timeout <= 0 {
			return ValidatedScan{}, &ValidationError{
				Message: "Enter a positive check timeout with a unit, such as 30s.",
			}
		}
	}

	return ValidatedScan{
		Targets:      targets,
		Ports:        ports,
		TopPorts:     topPorts,
		LightVersion: req.LightVersion,
		SkipPing:     req.SkipPing,
		Workers:      workers,
		Timeout:      timeout,
	}, nil
}

// RunScan validates req and runs the scan against the shared engine.
func (s *Service) RunScan(ctx context.Context, req ScanRequest, onEvent func(engine.Event)) (*engine.Report, error) {
	scan, err := s.ValidateScan(req)
	if err != nil {
		return nil, err
	}
	return s.RunValidated(ctx, scan, onEvent)
}

// RunValidated executes an already-validated scan using the shared engine.
func (s *Service) RunValidated(ctx context.Context, scan ValidatedScan, onEvent func(engine.Event)) (*engine.Report, error) {
	var runner nmap.Runner
	if s.NewRunner != nil {
		runner = s.NewRunner()
	}
	eng := &engine.Engine{
		Scanner: nmap.Scanner{
			Runner: runner,
			Options: nmap.Options{
				Ports:        scan.Ports,
				TopPorts:     scan.TopPorts,
				LightVersion: scan.LightVersion,
				SkipPing:     scan.SkipPing,
			},
		},
		Checks:       s.Checks(),
		Workers:      scan.Workers,
		CheckTimeout: scan.Timeout,
		OnEvent:      onEvent,
	}
	return eng.Run(ctx, scan.Targets)
}

// NmapInstallHint returns an OS-appropriate instruction for installing Nmap.
func NmapInstallHint() string {
	return nmapInstallHintFor(runtime.GOOS)
}

func nmapInstallHintFor(goos string) string {
	switch goos {
	case "darwin":
		return "Install it with: brew install nmap"
	case "windows":
		return "Install it with: winget install Insecure.Nmap (or download from https://nmap.org/download.html)"
	default:
		return "Install it with your package manager (e.g. sudo apt install nmap or sudo dnf install nmap)"
	}
}

// FriendlyError turns low-level engine and Nmap errors into plain, actionable messages.
func FriendlyError(err error) string {
	if err == nil {
		return ""
	}
	var valErr *ValidationError
	if errors.As(err, &valErr) {
		return valErr.Message
	}
	if errors.Is(err, context.Canceled) {
		return "Scan stopped before finishing."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Scan timed out before finishing."
	}
	msg := strings.TrimSpace(err.Error())
	lower := strings.ToLower(msg)
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) ||
		strings.Contains(lower, "executable file not found") ||
		strings.Contains(lower, "command not found") ||
		strings.Contains(lower, "cannot find the file") ||
		strings.Contains(lower, "no such file or directory") {
		return fmt.Sprintf("Nmap isn't installed or couldn't be found. %s, or pass --nmap /path/to/nmap.", NmapInstallHint())
	}
	if errors.Is(err, os.ErrPermission) ||
		strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "requires root") {
		return "Permission denied while running Nmap. Make sure the nmap binary is executable and you have permission to scan this target."
	}
	if strings.Contains(lower, "failed to resolve") {
		return "Couldn't resolve that target hostname. Check the spelling or enter an IP address like 127.0.0.1."
	}
	if strings.Contains(lower, "reading nmap xml") {
		return "Nmap stopped unexpectedly and didn't return a complete result. Try running the scan again."
	}
	msg = strings.TrimPrefix(msg, "discovery failed: ")
	return msg
}

// NormalizePorts validates and strips spaces from comma-separated TCP/UDP port
// numbers and ranges like "22, 80, 443" or "1-1000" so Nmap receives a clean -p value.
func NormalizePorts(spec string) (string, bool) {
	if strings.HasPrefix(spec, "-") {
		return "", false
	}
	parts := strings.Split(spec, ",")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", false
		}
		prefix := ""
		if len(part) >= 2 && part[1] == ':' && (part[0] == 'T' || part[0] == 'U') {
			prefix = part[:2]
			part = part[2:]
		}
		if startStr, endStr, hasRange := strings.Cut(part, "-"); hasRange {
			start, err1 := strconv.Atoi(startStr)
			end, err2 := strconv.Atoi(endStr)
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return "", false
			}
			clean = append(clean, fmt.Sprintf("%s%d-%d", prefix, start, end))
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return "", false
			}
			clean = append(clean, fmt.Sprintf("%s%d", prefix, p))
		}
	}
	return strings.Join(clean, ","), true
}

// ParseAllowedScope parses a comma-separated list of allowed CIDRs or IP addresses.
// An empty string returns nil, which means the default IPv4 loopback scope (127.0.0.0/8).
func ParseAllowedScope(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if ip, err := netip.ParseAddr(item); err == nil {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		return nil, fmt.Errorf("invalid allowed target %q: use an IP address or CIDR block", item)
	}
	return out, nil
}

// FormatAllowedScope formats allowed prefixes for status responses and error messages.
func FormatAllowedScope(allowed []netip.Prefix) string {
	if len(allowed) == 0 {
		return ""
	}
	parts := make([]string, 0, len(allowed))
	for _, p := range allowed {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

// TargetAllowed reports whether a cleaned target spec falls within allowed.
// When allowed is empty, only IPv4 loopback addresses and ranges (127.0.0.0/8) are permitted.
func TargetAllowed(spec string, allowed []netip.Prefix) bool {
	if len(allowed) == 0 {
		return isLoopbackTarget(spec)
	}
	if prefix, err := netip.ParsePrefix(spec); err == nil {
		for _, a := range allowed {
			if a.Contains(prefix.Addr()) && prefix.Bits() >= a.Bits() {
				return true
			}
		}
		return false
	}
	first, endStr, hasRange := strings.Cut(spec, "-")
	ip, err := netip.ParseAddr(first)
	if err != nil {
		return false
	}
	last := ip
	if hasRange && ip.Is4() {
		endOctet, convErr := strconv.Atoi(endStr)
		if convErr != nil || endOctet < 0 || endOctet > 255 {
			return false
		}
		b := ip.As4()
		b[3] = byte(endOctet)
		last = netip.AddrFrom4(b)
	}
	for _, a := range allowed {
		if a.Contains(ip) && a.Contains(last) {
			return true
		}
	}
	return false
}

func isLoopbackTarget(spec string) bool {
	if prefix, err := netip.ParsePrefix(spec); err == nil {
		return prefix.Addr().Is4() && prefix.Addr().IsLoopback() && prefix.Bits() >= 8
	}
	first, _, _ := strings.Cut(spec, "-")
	ip, err := netip.ParseAddr(first)
	return err == nil && ip.Is4() && ip.IsLoopback()
}
