// Package checks lists every check that ships with Nuqs.
//
// To add a check, create a folder next to the others, implement check.Check,
// write its tests and add it to All below. The tests in this package make sure
// every check in the list is valid and has its own tests.
package checks

import (
	"github.com/nuqs-org/nuqs/checks/ftpanon"
	"github.com/nuqs-org/nuqs/checks/httpheaders"
	"github.com/nuqs-org/nuqs/checks/mongodbnoauth"
	"github.com/nuqs-org/nuqs/checks/redisnoauth"
	"github.com/nuqs-org/nuqs/checks/sshnoauth"
	"github.com/nuqs-org/nuqs/checks/sshpasswordauth"
	"github.com/nuqs-org/nuqs/checks/sshweakalgos"
	"github.com/nuqs-org/nuqs/checks/telnet"
	"github.com/nuqs-org/nuqs/checks/tlsdeprecated"
	"github.com/nuqs-org/nuqs/internal/check"
)

// All returns a fresh list of every built-in check.
func All() []check.Check {
	return []check.Check{
		ftpanon.Check{},
		httpheaders.Check{},
		mongodbnoauth.Check{},
		redisnoauth.Check{},
		sshnoauth.Check{},
		sshpasswordauth.Check{},
		sshweakalgos.Check{},
		telnet.Check{},
		tlsdeprecated.Check{},
	}
}
