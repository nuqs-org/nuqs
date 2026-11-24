// Prints a comparison of two scans, as text for people or as JSON for tools.

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/nuqs-org/nuqs/internal/diff"
)

// DiffJSON writes the comparison as indented JSON.
func DiffJSON(w io.Writer, d diff.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

// DiffText writes what changed between two scans, one table per kind of change.
func DiffText(w io.Writer, d diff.Result) error {
	p := &printer{w: w}
	p.f("Comparing %s with %s\n", scanName(d.Old), scanName(d.New))
	p.f("Targets: %s\n\n", strings.Join(d.New.Targets, ", "))
	if len(d.Added)+len(d.Fixed)+len(d.Open)+len(d.NotChecked) == 0 {
		p.f("No findings in either scan.\n")
		return p.err
	}
	p.f("%s\n", d.Summary())
	sections := []struct {
		title string
		items []diff.Item
		last  string // header of the extra last column
		extra func(diff.Item) string
	}{
		{"New", d.Added, "", nil},
		{"Fixed", d.Fixed, "WHY", func(it diff.Item) string { return it.Reason }},
		{"Still open", d.Open, "SINCE", func(it diff.Item) string {
			if it.FirstSeen.IsZero() {
				return ""
			}
			return it.FirstSeen.Local().Format("2006-01-02")
		}},
		{"Not checked this time", d.NotChecked, "WHY", func(it diff.Item) string { return it.Reason }},
	}
	for _, s := range sections {
		if len(s.items) == 0 || p.err != nil {
			continue
		}
		p.f("\n%s (%d):\n", s.title, len(s.items))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		header := "  SEVERITY\tHOST\tPORT\tCHECK\tTITLE"
		if s.extra != nil {
			header += "\t" + s.last
		}
		fmt.Fprintln(tw, header)
		for _, it := range s.items {
			line := fmt.Sprintf("  %s\t%s\t%d/%s\t%s\t%s", strings.ToUpper(it.Severity.String()), it.Host, it.Port, it.Protocol, it.CheckID, it.Title)
			if s.extra != nil {
				line += "\t" + s.extra(it)
			}
			fmt.Fprintln(tw, line)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return p.err
}

func scanName(s diff.Scan) string {
	name := "scan"
	if s.ID != 0 {
		name = fmt.Sprintf("scan %d", s.ID)
	}
	return fmt.Sprintf("%s (%s)", name, s.Started.Local().Format("2006-01-02 15:04"))
}
