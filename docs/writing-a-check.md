# Writing a check

Adding a check takes three small steps. Let's write one that flags Redis servers with no password.

## 1. Create the check

Make a folder `checks/redisnoauth/` and add `redisnoauth.go`:

```go
// Package redisnoauth flags Redis servers that answer without a password.
package redisnoauth

import (
	"context"
	"net"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// Check reports Redis servers with no password.
type Check struct{}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:       "redis-no-auth",
		Title:    "Redis server has no password",
		Severity: model.High,
		Fix:      "Set requirepass in redis.conf, or bind Redis to localhost only.",
		Ports:    []int{6379},
		Services: []string{"redis"},
	}
}

// Run sends PING and reports a finding if Redis answers PONG.
func (Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.Address())
	if err != nil {
		return nil, err // couldn't check, that's an error and not a finding
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(string(buf[:n]), "+PONG") {
		return &check.Result{Evidence: "sent PING without a password and got +PONG"}, nil
	}
	return nil, nil // asked for a password, all good
}
```

## 2. Write its tests

Add `redisnoauth_test.go` next to it. Every check needs **at least one positive test** (finds the problem) and **one negative test** (doesn't find it when it's fixed). Use a tiny fake server, see `checks/ftpanon/ftpanon_test.go` for an example. Tests must never touch the real network.

Also test what happens when the server is down, slow or sends garbage.

## 3. Add it to the list

Open `checks/checks.go` and add it to `All`:

```go
redisnoauth.Check{},
```

That's it. Run the tests:

```bash
go test ./checks/...
```

If you forget step 2 or 3, `checks/checks_test.go` fails and tells you.

## Rules for checks

- **Be safe.** Never change anything on the target, never send exploits. Read only.
- **Return evidence.** Say what you saw in plain words, like "sent PING without a password and got +PONG".
- **Say how sure you are.** If you saw the problem yourself (a login worked, a header is missing), leave `Confidence` empty, it counts as `confirmed`. If you only know it from a version number, set `Confidence: model.Inferred`, because distros often patch old versions.
- **Errors aren't findings.** If you couldn't check, return an error. Only return a Result when you're sure.
- **Respect ctx.** Use `DialContext` and set deadlines. The engine uses ctx for timeouts.
- **Limit reads.** Never read an unlimited amount from a server, a hostile one can send gigabytes.
- **IDs** are lowercase words joined by dashes, like `redis-no-auth`, and must never change once released.
