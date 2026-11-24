// Tests sorting findings into new, fixed, still open and not checked.

package diff

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
)

func finding(check, host string, port int, sev model.Severity) model.Finding {
	return model.Finding{ID: model.FindingID(host, check, port, "tcp"), CheckID: check, Host: host, Port: port, Protocol: "tcp", Severity: sev, Title: check}
}

func report(hosts []string, findings ...model.Finding) *engine.Report {
	r := &engine.Report{Targets: []string{"10.0.0.0/30"}, Started: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)}
	for _, h := range hosts {
		r.Hosts = append(r.Hosts, model.Host{Address: h})
	}
	r.Findings = findings
	return r
}

func ids(items []Item) string {
	var out []string
	for _, it := range items {
		out = append(out, it.CheckID+"@"+it.Host)
	}
	return strings.Join(out, " ")
}

var (
	telnet = finding("telnet-open", "10.0.0.1", 23, model.Medium)
	redis  = finding("redis-no-auth", "10.0.0.1", 6379, model.High)
	ftp    = finding("ftp-anonymous-login", "10.0.0.2", 21, model.Medium)
	both   = []string{"10.0.0.1", "10.0.0.2"}
)

func TestCompare(t *testing.T) {
	cases := []struct {
		name                     string
		old, new                 *engine.Report
		added, fixed, open, gone string
	}{
		{"no change", report(both, telnet, ftp), report(both, telnet, ftp), "", "", "telnet-open@10.0.0.1 ftp-anonymous-login@10.0.0.2", ""},
		{"all fixed", report(both, telnet, ftp), report(both), "", "telnet-open@10.0.0.1 ftp-anonymous-login@10.0.0.2", "", ""},
		{"all new", report(both), report(both, redis, telnet), "redis-no-auth@10.0.0.1 telnet-open@10.0.0.1", "", "", ""},
		{"mixed", report(both, telnet, ftp), report(both, redis, ftp), "redis-no-auth@10.0.0.1", "telnet-open@10.0.0.1", "ftp-anonymous-login@10.0.0.2", ""},
		{"host gone", report(both, telnet, ftp), report([]string{"10.0.0.1"}, telnet), "", "", "telnet-open@10.0.0.1", "ftp-anonymous-login@10.0.0.2"},
		{"nothing at all", report(nil), report(nil), "", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Compare(c.old, c.new)
			for _, got := range []struct{ name, got, want string }{
				{"new", ids(d.Added), c.added}, {"fixed", ids(d.Fixed), c.fixed},
				{"open", ids(d.Open), c.open}, {"not checked", ids(d.NotChecked), c.gone},
			} {
				if got.got != got.want {
					t.Errorf("%s: got %q, want %q", got.name, got.got, got.want)
				}
			}
		})
	}
}

func TestFailedCheckIsNotFixed(t *testing.T) {
	newer := report(both)
	newer.Errors = []engine.CheckError{{CheckID: "telnet-open", Host: "10.0.0.1", Port: 23, Error: "timeout"}}
	d := Compare(report(both, telnet, ftp), newer)
	if len(d.NotChecked) != 1 || d.NotChecked[0].CheckID != "telnet-open" || d.NotChecked[0].Reason != CheckFailed {
		t.Errorf("a check that couldn't finish isn't a fix: %+v", d.NotChecked)
	}
	if ids(d.Fixed) != "ftp-anonymous-login@10.0.0.2" {
		t.Errorf("fixed: %q", ids(d.Fixed))
	}
	gone := Compare(report(both, ftp), report([]string{"10.0.0.1"}))
	if len(gone.NotChecked) != 1 || gone.NotChecked[0].Reason != HostDown {
		t.Errorf("host down: %+v", gone.NotChecked)
	}
}

// A finding is fixed when the host is still up and either its port closed or
// the check ran again and passed. Stopping a service is a fix, so a missing
// port must count as fixed, not as "not checked".
func TestWhyFixed(t *testing.T) {
	withPort := func(port int, protocol string) *engine.Report {
		r := report(both)
		r.Hosts[0].Services = []model.Service{{Port: port, Protocol: protocol, Name: "redis"}}
		return r
	}
	cases := []struct {
		name string
		new  *engine.Report
		want string
	}{
		{"redis stopped, host still up", report(both), PortClosed},
		{"redis still running, check passed", withPort(6379, "tcp"), CheckPassed},
		{"only the udp port is open", withPort(6379, "udp"), PortClosed},
	}
	for _, c := range cases {
		d := Compare(report(both, redis), c.new)
		if len(d.Fixed) != 1 || len(d.NotChecked) != 0 || d.Fixed[0].Reason != c.want {
			t.Errorf("%s: fixed %+v, not checked %+v, want fixed because %q", c.name, d.Fixed, d.NotChecked, c.want)
		}
	}
}

func TestWorstFirst(t *testing.T) {
	crit := finding("x", "10.0.0.2", 1, model.Critical)
	low := finding("y", "10.0.0.1", 1, model.Low)
	d := Compare(report(both), report(both, low, telnet, crit, redis))
	if got := ids(d.Added); got != "x@10.0.0.2 redis-no-auth@10.0.0.1 telnet-open@10.0.0.1 y@10.0.0.1" {
		t.Errorf("order: %s", got)
	}
}

func TestSummaryAndSeen(t *testing.T) {
	d := Compare(report(both, telnet, ftp), report([]string{"10.0.0.1"}, redis, telnet))
	if got := d.Summary(); got != "1 new, 0 fixed, 1 still open, 1 not checked" {
		t.Errorf("summary: %s", got)
	}
	if got := Compare(report(both), report(both)).Summary(); got != "0 new, 0 fixed, 0 still open" {
		t.Errorf("empty summary: %s", got)
	}
	if len(d.IDs()) != 3 {
		t.Errorf("IDs: %v", d.IDs())
	}
	first := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	last := first.Add(48 * time.Hour)
	d.SetSeen(func(id string) (time.Time, time.Time) {
		if id == telnet.ID {
			return first, last
		}
		return time.Time{}, time.Time{}
	})
	if !d.Open[0].FirstSeen.Equal(first) || !d.Open[0].LastSeen.Equal(last) || !d.Added[0].FirstSeen.IsZero() {
		t.Errorf("first seen: %+v %+v", d.Open[0], d.Added[0])
	}
}

func TestJSONShape(t *testing.T) {
	b, err := json.Marshal(Compare(report(both), report(both)))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"new_findings":[]`, `"fixed":[]`, `"still_open":[]`, `"not_checked":[]`, `"old":{"started"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON is missing %s:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), `"id":0`) {
		t.Errorf("unset scan IDs should be left out:\n%s", b)
	}
}
