// Tests the old TLS versions check against local TLS servers set to different versions.

package tlsdeprecated

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// server starts a TLS server that allows versions min to max.
func server(t *testing.T, minV, maxV uint16) check.Target {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.TLS = &tls.Config{MinVersion: minV, MaxVersion: maxV}
	s.StartTLS()
	t.Cleanup(s.Close)
	return target(t, s.Listener.Addr().String(), "http", "ssl")
}

func target(t *testing.T, addr, name, tunnel string) check.Target {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	return check.Target{Host: host, Service: model.Service{Port: p, Protocol: "tcp", Name: name, Tunnel: tunnel}}
}

func run(t *testing.T, tgt check.Target) (*check.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return Check{}.Run(ctx, tgt)
}

func TestInfo(t *testing.T) {
	if err := check.Validate([]check.Check{Check{}}); err != nil {
		t.Fatal(err)
	}
	in := Check{}.Info()
	for _, s := range []model.Service{{Port: 443}, {Port: 8443, Name: "https-alt"}, {Port: 8080, Name: "http", Tunnel: "ssl"}, {Port: 993, Name: "imaps"}} {
		if !check.Applies(in, s) {
			t.Errorf("should apply to %+v", s)
		}
	}
}

func TestOldVersions(t *testing.T) {
	cases := []struct {
		name     string
		min, max uint16
		want     string // empty means no finding
	}{
		{"1.0 to 1.3", tls.VersionTLS10, tls.VersionTLS13, "server completed a handshake with TLS 1.0 and TLS 1.1"},
		{"only 1.0", tls.VersionTLS10, tls.VersionTLS10, "server completed a handshake with TLS 1.0"},
		{"1.1 and up", tls.VersionTLS11, tls.VersionTLS13, "server completed a handshake with TLS 1.1"},
		{"1.2 and up", tls.VersionTLS12, tls.VersionTLS13, ""},
		{"only 1.3", tls.VersionTLS13, tls.VersionTLS13, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := run(t, server(t, c.min, c.max))
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case c.want == "" && res != nil:
				t.Errorf("want no finding, got %q", res.Evidence)
			case c.want != "" && (res == nil || res.Evidence != c.want):
				t.Errorf("want %q, got %+v", c.want, res)
			}
		})
	}
}

func TestPlainTextIsSkipped(t *testing.T) {
	// Nothing listens here, so if the check tried to connect it would fail.
	res, err := run(t, target(t, "127.0.0.1:1", "http", ""))
	if err != nil || res != nil {
		t.Errorf("plain HTTP must be skipped, got %+v, %v", res, err)
	}
}

func TestNotTLS(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	res, err := run(t, target(t, s.Listener.Addr().String(), "https", ""))
	if err == nil || res != nil {
		t.Errorf("a service that doesn't speak TLS must be an error, got %+v, %v", res, err)
	}
}

func TestServerDown(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	res, err := run(t, target(t, addr, "https", ""))
	if err == nil || res != nil {
		t.Errorf("want an error, got %+v, %v", res, err)
	}
}

func TestSlowServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(3 * time.Second)
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := Check{}.Run(ctx, target(t, l.Addr().String(), "https", ""))
	if err == nil || res != nil {
		t.Errorf("want a timeout error, got %+v, %v", res, err)
	}
	if time.Since(start) > time.Second {
		t.Error("didn't stop when the context ended")
	}
}
