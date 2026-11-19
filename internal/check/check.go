// Package check defines what a check is. This is the main extension point of Nuqs.
//
// A check looks at one service on one host and says whether it found a problem.
// To add a check you write a type with two methods, Info and Run, and add it to
// the list in package checks. That's it.
package check

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/nuqs-org/nuqs/internal/model"
)

// Info describes a check. The engine uses it to decide where the check runs
// and to fill in the finding, so Run only has to return evidence.
type Info struct {
	ID       string         // short and unique, like "telnet-open"
	Title    string         // one line shown to users
	Severity model.Severity // how bad it is when found
	Fix      string         // what the user should do about it

	// Where the check applies. A service matches if its port is in Ports OR
	// its Nmap service name is in Services. Leave both empty to match every service.
	Ports    []int
	Services []string
}

// Target is what a check runs against: one host and one of its services.
type Target struct {
	Host    string
	Service model.Service
}

// Address returns "host:port", with brackets around IPv6 hosts.
func (t Target) Address() string {
	if strings.Contains(t.Host, ":") {
		return fmt.Sprintf("[%s]:%d", t.Host, t.Service.Port)
	}
	return fmt.Sprintf("%s:%d", t.Host, t.Service.Port)
}

// Result is what a check returns when it finds something.
type Result struct {
	Evidence string // what we saw, in plain words, for example "server sent 230 after anonymous login"

	// Confidence is how sure the check is. Leave it empty when the check saw
	// the problem itself, that counts as model.Confirmed. Set model.Inferred
	// when the finding comes only from a version number.
	Confidence model.Confidence
}

// Check is the interface every check implements.
//
// Run returns nil, nil when the service is fine. It returns an error only when
// it couldn't do its job (connection refused, timeout and so on), never to say
// "vulnerable". Run must respect ctx, the engine uses it for timeouts.
type Check interface {
	Info() Info
	Run(ctx context.Context, t Target) (*Result, error)
}

// Applies reports whether a check with this info should run on the service.
func Applies(info Info, svc model.Service) bool {
	if len(info.Ports) == 0 && len(info.Services) == 0 {
		return true
	}
	if slices.Contains(info.Ports, svc.Port) {
		return true
	}
	return slices.Contains(info.Services, strings.ToLower(svc.Name))
}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Validate makes sure a list of checks is usable: every ID is well formed
// and unique, and every check has a title and a fix. The engine calls this
// before a scan so a broken check fails loudly instead of silently.
func Validate(checks []Check) error {
	seen := map[string]bool{}
	var errs []error
	for _, c := range checks {
		if c == nil {
			errs = append(errs, errors.New("nil check in list"))
			continue
		}
		in := c.Info()
		switch {
		case !idPattern.MatchString(in.ID):
			errs = append(errs, fmt.Errorf("check %q: ID must be lowercase words joined by dashes", in.ID))
		case seen[in.ID]:
			errs = append(errs, fmt.Errorf("check %q: duplicate ID", in.ID))
		}
		seen[in.ID] = true
		if strings.TrimSpace(in.Title) == "" {
			errs = append(errs, fmt.Errorf("check %q: missing title", in.ID))
		}
		if strings.TrimSpace(in.Fix) == "" {
			errs = append(errs, fmt.Errorf("check %q: missing fix", in.ID))
		}
		if in.Severity < model.Info || in.Severity > model.Critical {
			errs = append(errs, fmt.Errorf("check %q: invalid severity", in.ID))
		}
		for _, p := range in.Ports {
			if p < 1 || p > 65535 {
				errs = append(errs, fmt.Errorf("check %q: invalid port %d", in.ID, p))
			}
		}
		for _, s := range in.Services {
			if s != strings.ToLower(s) || s == "" {
				errs = append(errs, fmt.Errorf("check %q: service names must be lowercase", in.ID))
			}
		}
	}
	return errors.Join(errs...)
}
