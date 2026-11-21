// Package sshpasswordauth checks if an SSH server lets people log in with a password.
//
// This is a "login probe" check, but it never sends a password. It does the
// SSH key exchange, asks to log in as "nuqs" with no credentials, and reads
// the list of login methods the server offers back. Servers send that same
// list for users that don't exist, so the user name doesn't matter.
//
// A server that lets us in with no credentials at all is left to the
// ssh-no-auth check, so it doesn't show up here as a password problem.
//
// Only the "password" method is flagged. "keyboard-interactive" is often a
// password too, but it's also used for one-time codes, so it isn't a sure sign.
package sshpasswordauth

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/sshprobe"
)

// user is who we ask to log in as. Any name works.
const user = "nuqs"

// Check reports SSH servers that accept password logins.
type Check struct {
	// Ask asks the server for its login methods. Nil means sshprobe.AuthMethods.
	Ask func(ctx context.Context, addr, user string) (*sshprobe.Auth, error)
}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:       "ssh-password-auth",
		Title:    "SSH server allows password login",
		Severity: model.Medium,
		Fix:      "Use SSH keys and set PasswordAuthentication no in sshd_config. Passwords can be guessed, keys can't.",
		Ports:    []int{22},
		Services: []string{"ssh"},
	}
}

// Run asks for the login methods and reports a finding if "password" is one of them.
func (c Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	ask := c.Ask
	if ask == nil {
		ask = sshprobe.AuthMethods
	}
	a, err := ask(ctx, t.Address(), user)
	if err != nil {
		return nil, err
	}
	if a.NoAuth || !slices.Contains(a.Methods, "password") {
		return nil, nil
	}
	return &check.Result{
		Evidence: fmt.Sprintf("%s offers these login methods: %s", a.Banner, strings.Join(a.Methods, ", ")),
	}, nil
}
