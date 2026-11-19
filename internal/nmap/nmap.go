// Package nmap runs Nmap and turns its XML output into model.Host values.
//
// Nmap does the hard low-level work (finding hosts, open ports and what runs
// on them). We only build the command, run it and read the result.
package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/nuqs-org/nuqs/internal/model"
)

// Options controls how Nmap is run.
type Options struct {
	// Ports to scan, in Nmap syntax like "22,80,443" or "1-1000".
	// Empty means Nmap's default top 1000 ports.
	Ports string
	// SkipPing scans hosts even if they don't answer ping (Nmap's -Pn).
	SkipPing bool
}

// Args builds the Nmap arguments for the given targets.
// Targets must already be validated by the target package.
func Args(targets []string, opt Options) []string {
	args := []string{
		"-sT",      // TCP connect scan, works without root
		"-sV",      // detect service names and versions
		"--open",   // only report open ports
		"-T4",      // sensible speed for normal networks
		"-oX", "-", // XML to stdout
	}
	if opt.Ports != "" {
		args = append(args, "-p", opt.Ports)
	}
	if opt.SkipPing {
		args = append(args, "-Pn")
	}
	args = append(args, "--")
	return append(args, targets...)
}

// Runner runs Nmap with the given arguments and returns its stdout.
// Tests swap this out so they don't need Nmap installed.
type Runner interface {
	Run(ctx context.Context, args []string) ([]byte, error)
}

// ExecRunner runs the real nmap binary.
type ExecRunner struct {
	// Path to nmap. Empty means "nmap" from PATH.
	Path string
}

// Run executes nmap and returns stdout. If nmap fails, the error includes
// the end of its stderr so the user can see why.
func (r ExecRunner) Run(ctx context.Context, args []string) ([]byte, error) {
	path := r.Path
	if path == "" {
		path = "nmap"
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[len(msg)-500:]
		}
		if msg != "" {
			return nil, fmt.Errorf("nmap failed: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("nmap failed: %w", err)
	}
	return stdout.Bytes(), nil
}

// Scanner finds hosts and services with Nmap.
type Scanner struct {
	Runner  Runner
	Options Options
}

// Scan runs Nmap against the targets and returns the hosts that are up.
func (s Scanner) Scan(ctx context.Context, targets []string) ([]model.Host, error) {
	if s.Runner == nil {
		return nil, errors.New("nmap: no runner set")
	}
	out, err := s.Runner.Run(ctx, Args(targets, s.Options))
	if err != nil {
		return nil, err
	}
	return Parse(bytes.NewReader(out))
}

// These structs mirror only the parts of Nmap's XML that we use.
type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   string `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name    string `xml:"name,attr"`
			Product string `xml:"product,attr"`
			Version string `xml:"version,attr"`
			Tunnel  string `xml:"tunnel,attr"`
			Method  string `xml:"method,attr"` // "probed" or "table" (guessed from the port)
		} `xml:"service"`
	} `xml:"ports>port"`
}

// Parse reads Nmap XML and returns hosts that are up, with their open ports.
// Hosts and ports that are down, closed or filtered are left out.
func Parse(r io.Reader) ([]model.Host, error) {
	var run xmlRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("reading nmap XML: %w", err)
	}

	var hosts []model.Host
	for _, xh := range run.Hosts {
		if xh.Status.State != "up" {
			continue
		}
		h := model.Host{Address: pickAddress(xh)}
		if h.Address == "" {
			continue
		}
		for _, hn := range xh.Hostnames {
			if hn.Name != "" {
				h.Hostnames = append(h.Hostnames, hn.Name)
			}
		}
		for _, p := range xh.Ports {
			if p.State.State != "open" {
				continue
			}
			port, err := strconv.Atoi(p.PortID)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("reading nmap XML: bad port %q", p.PortID)
			}
			h.Services = append(h.Services, model.Service{
				Port:     port,
				Protocol: p.Protocol,
				Name:     p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
				Tunnel:   p.Service.Tunnel,
				Guessed:  p.Service.Method == "table",
			})
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// pickAddress prefers IPv4, then IPv6, and never returns a MAC address.
func pickAddress(h xmlHost) string {
	var v6 string
	for _, a := range h.Addresses {
		switch a.Type {
		case "ipv4":
			return a.Addr
		case "ipv6":
			if v6 == "" {
				v6 = a.Addr
			}
		}
	}
	return v6
}
