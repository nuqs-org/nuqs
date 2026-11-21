// Tests the SSH no-credentials login check with canned server answers. The SSH talking itself is tested in internal/sshprobe.

package sshnoauth

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/sshprobe"
)

var target = check.Target{Host: "10.0.0.5", Service: model.Service{Port: 22, Protocol: "tcp", Name: "ssh"}}

// answer returns a Check whose server always answers a and err, and records what it was asked.
func answer(a *sshprobe.Auth, err error, asked *string) Check {
	return Check{Ask: func(_ context.Context, addr, u string) (*sshprobe.Auth, error) {
		if asked != nil {
			*asked = addr + " as " + u
		}
		return a, err
	}}
}

func TestInfo(t *testing.T) {
	if err := check.Validate([]check.Check{Check{}}); err != nil {
		t.Fatal(err)
	}
	if !check.Applies(Check{}.Info(), model.Service{Port: 2222, Name: "ssh"}) {
		t.Error("should apply to SSH on any port")
	}
}

func TestNoAuth(t *testing.T) {
	var asked string
	res, err := answer(&sshprobe.Auth{Banner: "SSH-2.0-dropbear", NoAuth: true}, nil, &asked).Run(context.Background(), target)
	if err != nil || res == nil {
		t.Fatalf("want a finding, got %+v, %v", res, err)
	}
	if want := `SSH-2.0-dropbear let us log in as "nuqs" with no password or key`; res.Evidence != want {
		t.Errorf("evidence %q, want %q", res.Evidence, want)
	}
	if res.Confidence != "" {
		t.Errorf("the server let us in, so it's confirmed, got %q", res.Confidence)
	}
	if asked != "10.0.0.5:22 as nuqs" {
		t.Errorf("asked %q", asked)
	}
}

func TestNeedsLogin(t *testing.T) {
	for _, m := range [][]string{{"publickey", "password"}, {"publickey"}, nil} {
		res, err := answer(&sshprobe.Auth{Methods: m}, nil, nil).Run(context.Background(), target)
		if err != nil || res != nil {
			t.Errorf("methods %v: want no finding, got %+v, %v", m, res, err)
		}
	}
}

func TestError(t *testing.T) {
	res, err := answer(nil, errors.New("key exchange: no cipher in common"), nil).Run(context.Background(), target)
	if err == nil || res != nil {
		t.Errorf("want the error and no finding, got %+v, %v", res, err)
	}
}

func TestDefaultUsesSSH(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	res, err := Check{}.Run(context.Background(), check.Target{Host: "127.0.0.1", Service: model.Service{Port: port, Name: "ssh"}})
	if err == nil || res != nil {
		t.Errorf("a closed port must be an error, got %+v, %v", res, err)
	}
}
