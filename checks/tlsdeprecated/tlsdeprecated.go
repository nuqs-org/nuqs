// Package tlsdeprecated checks if a server still accepts TLS 1.0 or TLS 1.1.
//
// This is a "handshake" check. It first does a normal TLS handshake to make
// sure the service speaks TLS at all, then tries again allowing only TLS 1.0,
// then only TLS 1.1. It hangs up after each handshake and sends no data.
//
// A server that turns an old version down sends a TLS alert, or Go hangs up
// because the server picked a newer version. A connection that just drops
// (closed or reset mid handshake) proves nothing on its own, so we try once
// more. If it drops again but a TLS 1.2 or 1.3 handshake still works, the
// server refuses old versions by hanging up. If that fails too, we give an
// error instead of calling the server clean.
//
// Both versions are deprecated (RFC 8996) and every current browser has
// dropped them. SSL 3.0 isn't tested, Go can't speak it.
package tlsdeprecated

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// Check reports TLS servers that accept TLS 1.0 or 1.1.
type Check struct{}

// tlsNames are Nmap service names that always mean TLS. Other services, like
// "http", count only when Nmap saw TLS on them (Tunnel is "ssl").
var tlsNames = []string{"https", "https-alt", "ssl", "imaps", "pop3s", "smtps", "submissions", "ldaps", "ftps"}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:       "tls-deprecated-protocols",
		Title:    "Server accepts old TLS versions",
		Severity: model.Medium,
		Fix:      "Allow only TLS 1.2 and 1.3. In nginx set ssl_protocols TLSv1.2 TLSv1.3; in Apache set SSLProtocol -all +TLSv1.2 +TLSv1.3.",
		Ports:    []int{443, 465, 636, 993, 995, 8443},
		Services: append([]string{"http", "http-alt", "http-proxy"}, tlsNames...),
	}
}

// old are the versions we try, in order.
var old = []struct {
	version uint16
	name    string
}{
	{tls.VersionTLS10, "TLS 1.0"},
	{tls.VersionTLS11, "TLS 1.1"},
}

// Run tries a handshake with each old version and lists the ones that worked.
func (Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.Service.Tunnel != "ssl" && !slices.Contains(tlsNames, strings.ToLower(t.Service.Name)) {
		return nil, nil // plain text service, nothing to check
	}
	if ok, err := handshake(ctx, t, tls.VersionTLS10, tls.VersionTLS13); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("no TLS handshake with any version, this may not be a TLS service")
	}

	var accepted []string
	for _, v := range old {
		ok, err := handshake(ctx, t, v.version, v.version)
		if errors.Is(err, errDropped) {
			ok, err = handshake(ctx, t, v.version, v.version) // one retry, drops can be a hiccup
		}
		if errors.Is(err, errDropped) {
			// Some servers (IIS for one) refuse an old version by hanging up
			// instead of sending an alert. If a normal handshake still works
			// right after, the hang up was a refusal. If not, the server is
			// flaky and we can't tell.
			if modern, merr := handshake(ctx, t, tls.VersionTLS12, tls.VersionTLS13); merr == nil && modern {
				ok, err = false, nil
			} else {
				return nil, fmt.Errorf("couldn't test %s: %w", v.name, err)
			}
		}
		if err != nil {
			return nil, err
		}
		if ok {
			accepted = append(accepted, v.name)
		}
	}
	if len(accepted) == 0 {
		return nil, nil
	}
	return &check.Result{Evidence: "server completed a handshake with " + strings.Join(accepted, " and ")}, nil
}

// errDropped means the connection was closed or reset during the handshake,
// so we can't tell if the server would have accepted the version.
var errDropped = errors.New("server dropped the connection during the handshake")

// handshake connects and tries one TLS handshake with versions min to max.
// It returns false when the server refused, errDropped when the connection
// dropped, and another error when we couldn't connect.
func handshake(ctx context.Context, t check.Target, minV, maxV uint16) (bool, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.Address())
	if err != nil {
		return false, err
	}
	defer conn.Close()

	var suites []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, s.ID)
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // we test which versions work, not who the server is
		MinVersion:         minV,
		MaxVersion:         maxV,
		CipherSuites:       suites, // old versions need old ciphers, so offer them all
	}
	if net.ParseIP(t.Host) == nil {
		cfg.ServerName = t.Host
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if dropped(err) {
			return false, errDropped
		}
		return false, nil
	}
	_ = tc.Close()
	return true, nil
}

// dropped reports whether a handshake error came from the network instead of
// from TLS. A refusal is an alert from the server or a version Go won't accept.
// A drop is EOF or a network error like "connection reset". Go wraps alerts
// from the server in a net.OpError too, with Op "remote error", so those are
// left out.
func dropped(err error) bool {
	var ne *net.OpError
	if errors.As(err, &ne) {
		return ne.Op != "remote error"
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
