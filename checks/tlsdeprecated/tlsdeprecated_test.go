// Tests the old TLS versions check against local TLS servers set to different versions.

package tlsdeprecated

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
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

// flaky sits in front of real. It passes the first connection through (the
// baseline handshake), drops the next drops connections right after the
// ClientHello, then passes everything through again.
func flaky(t *testing.T, real check.Target, drops int32) check.Target {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if i := n.Add(1); i > 1 && i <= 1+drops {
				_, _ = c.Read(make([]byte, 512))
				c.Close()
				continue
			}
			up, err := net.Dial("tcp", real.Address())
			if err != nil {
				c.Close()
				continue
			}
			go func() { _, _ = io.Copy(up, c); up.Close() }()
			go func() { _, _ = io.Copy(c, up); c.Close() }()
		}
	}()
	return target(t, l.Addr().String(), "https", "")
}

func TestDroppedIsNotClean(t *testing.T) {
	// The server would accept TLS 1.0, but every old version try gets dropped.
	// That must be an error, never "no finding".
	res, err := run(t, flaky(t, server(t, tls.VersionTLS10, tls.VersionTLS13), 100))
	if err == nil || res != nil {
		t.Fatalf("want an error and no finding, got %+v, %v", res, err)
	}
	if !strings.Contains(err.Error(), "couldn't test TLS 1.0") {
		t.Errorf("error should say which version, got %v", err)
	}
}

func TestDroppedOnceIsRetried(t *testing.T) {
	res, err := run(t, flaky(t, server(t, tls.VersionTLS10, tls.VersionTLS13), 1))
	if err != nil || res == nil || res.Evidence != "server completed a handshake with TLS 1.0 and TLS 1.1" {
		t.Errorf("a single drop should be retried, got %+v, %v", res, err)
	}
}

func TestDroppedOnModernServer(t *testing.T) {
	// Even when the server would refuse, a drop means we don't know, so it's an error.
	res, err := run(t, flaky(t, server(t, tls.VersionTLS12, tls.VersionTLS13), 100))
	if err == nil || res != nil {
		t.Errorf("want an error and no finding, got %+v, %v", res, err)
	}
}

// hangsUpOnOld sits in front of real and drops any connection whose
// ClientHello asks for less than TLS 1.2, like IIS does, instead of sending an alert.
func hangsUpOnOld(t *testing.T, real check.Target) check.Target {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// 5 bytes record header, 4 bytes handshake header, then the client version.
			hello := make([]byte, 11)
			if _, err := io.ReadFull(c, hello); err != nil || int(hello[9])<<8|int(hello[10]) < tls.VersionTLS12 {
				c.Close()
				continue
			}
			up, err := net.Dial("tcp", real.Address())
			if err != nil {
				c.Close()
				continue
			}
			_, _ = up.Write(hello)
			go func() { _, _ = io.Copy(up, c); up.Close() }()
			go func() { _, _ = io.Copy(c, up); c.Close() }()
		}
	}()
	return target(t, l.Addr().String(), "https", "")
}

func TestHangUpIsRefusal(t *testing.T) {
	res, err := run(t, hangsUpOnOld(t, server(t, tls.VersionTLS10, tls.VersionTLS13)))
	if err != nil || res != nil {
		t.Errorf("a server that hangs up on old versions but does TLS 1.2 is clean, got %+v, %v", res, err)
	}
}
