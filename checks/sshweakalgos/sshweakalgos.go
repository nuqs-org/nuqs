// Package sshweakalgos checks if an SSH server still offers weak algorithms.
//
// This is a "handshake" check. It reads the list of algorithms the server
// sends before encryption starts, then hangs up. It never logs in.
//
// Weak means broken or close to it: SHA-1 key exchange and host key
// signatures, CBC and RC4 ciphers, and MD5 or truncated MACs. Things modern
// OpenSSH still offers by default (like hmac-sha1 or umac-64) aren't flagged,
// so a default install never shows up here.
package sshweakalgos

import (
	"context"
	"fmt"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/sshprobe"
)

// Check reports SSH servers that offer weak algorithms.
type Check struct{}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:       "ssh-weak-algorithms",
		Title:    "SSH server allows weak algorithms",
		Severity: model.Low,
		Fix:      "Remove the weak algorithms from KexAlgorithms, HostKeyAlgorithms, Ciphers and MACs in sshd_config, or update OpenSSH. Its defaults are fine.",
		Ports:    []int{22},
		Services: []string{"ssh"},
	}
}

// The weak algorithms, by kind. A name ending in "*" matches any name that
// starts with it, a name starting with "*" matches any name that ends with it.
var (
	weakKex = []string{
		"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
		"rsa1024-sha1", "gss-group1-sha1-*", "gss-group14-sha1-*", "gss-gex-sha1-*",
	}
	weakHostKeys = []string{"ssh-dss", "ssh-rsa", "ssh-dss-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"}
	weakCiphers  = []string{"*-cbc", "rijndael-cbc@lysator.liu.se", "arcfour", "arcfour128", "arcfour256", "none"}
	weakMACs     = []string{
		"hmac-md5", "hmac-md5-96", "hmac-sha1-96",
		"hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "none",
	}
)

// Run reads the server's algorithms and lists the weak ones it offers.
func (Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	s, err := sshprobe.Hello(ctx, t.Address())
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, k := range []struct {
		what   string
		offers []string
		weak   []string
	}{
		{"key exchange", s.Kex, weakKex},
		{"host key", s.HostKeys, weakHostKeys},
		{"cipher", s.Ciphers, weakCiphers},
		{"MAC", s.MACs, weakMACs},
	} {
		if found := matching(k.offers, k.weak); len(found) > 0 {
			parts = append(parts, k.what+" ("+strings.Join(found, ", ")+")")
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return &check.Result{Evidence: fmt.Sprintf("%s offers weak algorithms: %s", s.Banner, strings.Join(parts, ", "))}, nil
}

// matching returns the names in offers that match a pattern in weak, in the server's order.
func matching(offers, weak []string) []string {
	var out []string
	for _, name := range offers {
		for _, w := range weak {
			ok := name == w ||
				(strings.HasSuffix(w, "*") && strings.HasPrefix(name, strings.TrimSuffix(w, "*"))) ||
				(strings.HasPrefix(w, "*") && strings.HasSuffix(name, strings.TrimPrefix(w, "*")))
			if ok {
				out = append(out, name)
				break
			}
		}
	}
	return out
}
