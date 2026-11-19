// Package output prints a scan report, either as a table for people or as JSON for tools.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
)

// JSON writes the full report as indented JSON.
func JSON(w io.Writer, r *engine.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text writes a short, readable summary: hosts, findings with their fix,
// and any checks that failed to run.
func Text(w io.Writer, r *engine.Report) error {
	p := &printer{w: w}
	p.f("Scanned %s in %s\n", strings.Join(r.Targets, ", "), r.Finished.Sub(r.Started).Round(100*time.Millisecond))
	p.f("Hosts up: %d, open services: %d\n\n", len(r.Hosts), countServices(r))

	if len(r.Findings) == 0 {
		p.f("No findings.\n")
	} else {
		p.f("Findings (%d):\n", len(r.Findings))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tCONFIDENCE\tHOST\tPORT\tCHECK\tTITLE")
		for _, f := range r.Findings {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d/%s\t%s\t%s\n", strings.ToUpper(f.Severity.String()), confidence(f), f.Host, f.Port, f.Protocol, f.CheckID, f.Title)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		p.f("\nDetails:\n")
		for _, f := range r.Findings {
			p.f("  [%s] %s on %s:%d (%s)\n", strings.ToUpper(f.Severity.String()), f.Title, f.Host, f.Port, confidence(f))
			p.f("    Evidence: %s\n", f.Evidence)
			p.f("    Fix: %s\n", f.Fix)
		}
	}

	if len(r.Errors) > 0 {
		p.f("\nChecks that could not finish (%d):\n", len(r.Errors))
		for _, e := range r.Errors {
			p.f("  %s on %s:%d: %s\n", e.CheckID, e.Host, e.Port, firstLine(e.Error))
		}
	}
	return p.err
}

// printer remembers the first write error so we don't check every line.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) f(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

// confidence treats an empty value as confirmed, the same rule the engine uses.
func confidence(f model.Finding) model.Confidence {
	if f.Confidence == "" {
		return model.Confirmed
	}
	return f.Confidence
}

func countServices(r *engine.Report) int {
	n := 0
	for _, h := range r.Hosts {
		n += len(h.Services)
	}
	return n
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
