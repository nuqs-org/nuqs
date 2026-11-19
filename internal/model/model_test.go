// Tests severities, finding IDs and the JSON shape.

package model

import (
	"encoding/json"
	"testing"
)

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{Info: "info", Low: "low", Medium: "medium", High: "high", Critical: "critical", Severity(9): "severity(9)", Severity(-1): "severity(-1)"}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for _, in := range []string{"info", "LOW", " Medium ", "high", "Critical"} {
		if _, err := ParseSeverity(in); err != nil {
			t.Errorf("ParseSeverity(%q) failed: %v", in, err)
		}
	}
	if got, _ := ParseSeverity("High"); got != High {
		t.Errorf("ParseSeverity(High) = %v", got)
	}
	for _, in := range []string{"", "severe", "3"} {
		if _, err := ParseSeverity(in); err == nil {
			t.Errorf("ParseSeverity(%q) should fail", in)
		}
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for s := Info; s <= Critical; s++ {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != `"`+s.String()+`"` {
			t.Errorf("json of %v = %s", s, b)
		}
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil || back != s {
			t.Errorf("round trip %v gave %v, %v", s, back, err)
		}
	}
	if _, err := json.Marshal(Severity(7)); err == nil {
		t.Error("marshalling an invalid severity should fail")
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Error("unmarshalling a bad name should fail")
	}
}

func TestFindingID(t *testing.T) {
	a := FindingID("10.0.0.1", "telnet-open", 23, "tcp")
	if a != "telnet-open|10.0.0.1|23/tcp" {
		t.Errorf("unexpected ID %q", a)
	}
	if a != FindingID("10.0.0.1", "telnet-open", 23, "tcp") {
		t.Error("IDs must be stable")
	}
	if a == FindingID("10.0.0.1", "telnet-open", 2323, "tcp") {
		t.Error("different ports must give different IDs")
	}
}

func TestFindingJSONShape(t *testing.T) {
	f := Finding{ID: "x", CheckID: "c", Title: "t", Severity: High, Confidence: Inferred, Host: "h", Port: 1, Protocol: "tcp", Evidence: "e", Fix: "f"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "check_id", "title", "severity", "confidence", "host", "port", "protocol", "evidence", "fix"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON is missing %q", k)
		}
	}
	if m["severity"] != "high" {
		t.Errorf("severity should be a name, got %v", m["severity"])
	}
}

func TestConfidenceValid(t *testing.T) {
	for _, c := range []Confidence{Confirmed, Inferred} {
		if !c.Valid() {
			t.Errorf("%q should be valid", c)
		}
	}
	for _, c := range []Confidence{"", "maybe", "Confirmed"} {
		if c.Valid() {
			t.Errorf("%q should not be valid", c)
		}
	}
}

func TestConfidenceJSON(t *testing.T) {
	var f Finding
	if err := json.Unmarshal([]byte(`{"confidence": "inferred"}`), &f); err != nil || f.Confidence != Inferred {
		t.Errorf("reading inferred: %v, %v", f.Confidence, err)
	}
	for _, bad := range []string{`{"confidence": "maybe"}`, `{"confidence": ""}`} {
		if err := json.Unmarshal([]byte(bad), &f); err == nil {
			t.Errorf("%s should fail", bad)
		}
	}
}
