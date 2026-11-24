// Tests the text and JSON comparison of two scans.

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/engine"
)

func TestDiffText(t *testing.T) {
	old := sample()
	newer := sample()
	newer.Hosts = nil // the host didn't answer this time
	newer.Findings = nil
	d := diff.Compare(old, newer)
	d.Old.ID, d.New.ID = 3, 7
	var b bytes.Buffer
	if err := DiffText(&b, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Comparing scan 3 (", "with scan 7 (", "0 new, 0 fixed, 0 still open, 1 not checked",
		"Not checked this time (1):", "WHY", "host didn't answer"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "Fixed") {
		t.Errorf("empty sections should be left out:\n%s", b.String())
	}

	b.Reset()
	empty := &engine.Report{}
	if err := DiffText(&b, diff.Compare(empty, empty)); err != nil || !strings.Contains(b.String(), "Comparing scan (") ||
		!strings.Contains(b.String(), "No findings in either scan.") {
		t.Errorf("no findings: %v\n%s", err, b.String())
	}
}

func TestDiffTextFixedSaysWhy(t *testing.T) {
	newer := sample()
	newer.Findings = nil
	var b bytes.Buffer
	if err := DiffText(&b, diff.Compare(sample(), newer)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Fixed (1):") || !strings.Contains(b.String(), "WHY") || !strings.Contains(b.String(), diff.CheckPassed) {
		t.Errorf("fixed findings should say why:\n%s", b.String())
	}
}

func TestDiffJSON(t *testing.T) {
	var b bytes.Buffer
	if err := DiffJSON(&b, diff.Compare(&engine.Report{}, sample())); err != nil {
		t.Fatal(err)
	}
	var d diff.Result
	if err := json.Unmarshal(b.Bytes(), &d); err != nil || len(d.Added) != len(sample().Findings) {
		t.Errorf("round trip: %v %+v", err, d)
	}
}

func TestDiffWriteErrors(t *testing.T) {
	d := diff.Compare(&engine.Report{}, sample())
	if err := DiffText(failWriter{}, d); err == nil {
		t.Error("DiffText should return write errors")
	}
	if err := DiffJSON(failWriter{}, d); err == nil {
		t.Error("DiffJSON should return write errors")
	}
}
