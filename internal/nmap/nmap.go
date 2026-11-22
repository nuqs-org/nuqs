// Package nmap runs Nmap and turns its XML output into model.Host values.
//
// Nmap does the hard low-level work (finding hosts, open ports and what runs
// on them). We only build the command, run it and read the result.
//
// The XML is read while Nmap is still running. Nmap writes each host when it's
// done with it, so Stream hands hosts and progress updates on as they arrive.
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
	"time"

	"github.com/nuqs-org/nuqs/internal/model"
)

// Options controls how Nmap is run.
type Options struct {
	// Ports to scan, in Nmap syntax like "22,80,443" or "1-1000".
	// Empty means Nmap's default top 1000 ports (unless TopPorts is set).
	Ports string
	// TopPorts scans the N most common ports (--top-ports N). Ignored when Ports is set.
	TopPorts int
	// LightVersion uses faster, lighter version detection (--version-light).
	LightVersion bool
	// SkipPing scans hosts even if they don't answer ping (Nmap's -Pn).
	SkipPing bool
}

// Args builds the Nmap arguments for the given targets.
// Targets must already be validated by the target package.
func Args(targets []string, opt Options) []string {
	args := []string{
		"-sT",                 // TCP connect scan, works without root
		"-sV",                 // detect service names and versions
		"--open",              // only report open ports
		"-T4",                 // sensible speed for normal networks
		"--stats-every", "5s", // a progress update in the XML every 5 seconds
		"-oX", "-", // XML to stdout
	}
	if opt.LightVersion {
		args = append(args, "--version-light")
	}
	if opt.Ports != "" {
		args = append(args, "-p", opt.Ports)
	} else if opt.TopPorts > 0 {
		args = append(args, "--top-ports", strconv.Itoa(opt.TopPorts))
	}
	if opt.SkipPing {
		args = append(args, "-Pn")
	}
	args = append(args, "--")
	return append(args, targets...)
}

// Runner runs Nmap with the given arguments and writes its stdout to out as
// it comes. Tests swap this out so they don't need Nmap installed.
type Runner interface {
	Run(ctx context.Context, args []string, out io.Writer) error
}

// ExecRunner runs the real nmap binary.
type ExecRunner struct {
	// Path to nmap. Empty means "nmap" from PATH.
	Path string
}

// Run executes nmap and copies its stdout to out while it runs. If nmap
// fails, the error includes the end of its stderr so the user can see why.
func (r ExecRunner) Run(ctx context.Context, args []string, out io.Writer) error {
	path := r.Path
	if path == "" {
		path = "nmap"
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = out
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second // don't wait forever on output after nmap is killed
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[len(msg)-500:]
		}
		if msg != "" {
			return fmt.Errorf("nmap failed: %w: %s", err, msg)
		}
		return fmt.Errorf("nmap failed: %w", err)
	}
	return nil
}

// Progress is one of Nmap's progress updates, like "Service scan, 40% done".
type Progress struct {
	Task      string        // what Nmap is doing, like "Connect Scan" or "Service scan"
	Percent   float64       // how much of that task is done, 0 to 100
	Remaining time.Duration // Nmap's guess of the time left for the task, 0 if it has none
}

// Events are called while a scan runs. Either can be nil. They're called one
// at a time, from the goroutine that called Stream.
type Events struct {
	Host     func(model.Host) // a host that is up, with its open ports
	Progress func(Progress)
}

// Scanner finds hosts and services with Nmap.
type Scanner struct {
	Runner  Runner
	Options Options
}

// Scan runs Nmap against the targets and returns the hosts that are up.
func (s Scanner) Scan(ctx context.Context, targets []string) ([]model.Host, error) {
	var hosts []model.Host
	err := s.Stream(ctx, targets, Events{Host: func(h model.Host) { hosts = append(hosts, h) }})
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

// Stream runs Nmap against the targets and calls ev for each host and
// progress update as Nmap reports them. It returns when Nmap is done. If
// the output can't be read, Nmap is stopped and the error is returned, but
// hosts already passed to ev stay valid. A slow ev slows Nmap down too,
// because Nmap waits for us to read its output.
func (s Scanner) Stream(ctx context.Context, targets []string, ev Events) error {
	if s.Runner == nil {
		return errors.New("nmap: no runner set")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := s.Runner.Run(ctx, Args(targets, s.Options), pw)
		if err != nil {
			pw.CloseWithError(&runError{err}) // so we can tell it apart from bad XML
		} else {
			_ = pw.Close() // EOF for the reader
		}
		done <- err
	}()

	readErr := read(pr, ev)
	var re *runError
	if readErr != nil && !errors.As(readErr, &re) {
		cancel()                   // bad XML: stop nmap, the rest of its output is no use
		pr.CloseWithError(readErr) // and unblock it if it's mid write
	}
	runErr := <-done
	if re != nil {
		return runErr // nmap itself failed or was cancelled, that's the real reason
	}
	return readErr
}

// runError marks an error from the runner as it passes through the pipe.
type runError struct{ err error }

func (e *runError) Error() string { return e.err.Error() }

// xmlHost mirrors only the parts of Nmap's <host> element that we use.
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
	var hosts []model.Host
	if err := read(r, Events{Host: func(h model.Host) { hosts = append(hosts, h) }}); err != nil {
		return nil, err
	}
	return hosts, nil
}

// read goes through Nmap XML one element at a time and calls ev for each
// host and progress update, so it works while Nmap is still writing.
func read(r io.Reader, ev Events) error {
	d := xml.NewDecoder(r)
	sawRun := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			if !sawRun {
				return errors.New("reading nmap XML: no <nmaprun> in the output")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading nmap XML: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "nmaprun":
			sawRun = true
		case "host":
			var xh xmlHost
			if err := d.DecodeElement(&xh, &start); err != nil {
				return fmt.Errorf("reading nmap XML: %w", err)
			}
			h, up, err := toHost(xh)
			if err != nil {
				return err
			}
			if up && ev.Host != nil {
				ev.Host(h)
			}
		case "taskprogress":
			if p, ok := toProgress(start); ok && ev.Progress != nil {
				ev.Progress(p)
			}
		}
	}
}

// toHost turns one <host> into a model.Host. up is false for hosts that are
// down or have no IP address, those are left out.
func toHost(xh xmlHost) (h model.Host, up bool, err error) {
	if xh.Status.State != "up" {
		return h, false, nil
	}
	h.Address = pickAddress(xh)
	if h.Address == "" {
		return h, false, nil
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
			return h, false, fmt.Errorf("reading nmap XML: bad port %q", p.PortID)
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
	return h, true, nil
}

// toProgress reads a <taskprogress task="..." percent="..." remaining="..."/>.
// Updates we can't make sense of are skipped, they're only for show.
func toProgress(e xml.StartElement) (Progress, bool) {
	var p Progress
	pct, rem := "", ""
	for _, a := range e.Attr {
		switch a.Name.Local {
		case "task":
			p.Task = a.Value
		case "percent":
			pct = a.Value
		case "remaining":
			rem = a.Value
		}
	}
	f, err := strconv.ParseFloat(pct, 64)
	if p.Task == "" || err != nil || !(f >= 0 && f <= 100) { // also catches NaN, which JSON can't encode
		return Progress{}, false
	}
	p.Percent = f
	if sec, err := strconv.Atoi(rem); err == nil && sec > 0 {
		p.Remaining = time.Duration(sec) * time.Second
	}
	return p, true
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
