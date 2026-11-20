// Tests the weak SSH algorithms check against a fake server that only sends its algorithm list.

package sshweakalgos

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// algos is what the fake server offers.
type algos struct{ kex, hostKeys, ciphers, macs string }

var modern = algos{
	kex:      "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256",
	hostKeys: "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
	ciphers:  "chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com",
	macs:     "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,hmac-sha2-256,hmac-sha1",
}

// kexInit builds an unencrypted KEXINIT packet.
func kexInit(a algos) []byte {
	payload := append([]byte{20}, make([]byte, 16)...)
	for _, s := range []string{a.kex, a.hostKeys, a.ciphers, a.ciphers, a.macs, a.macs, "none", "none", "", ""} {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(s)))
		payload = append(payload, s...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	p := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
	p = append(p, byte(pad))
	p = append(p, payload...)
	return append(p, make([]byte, pad)...)
}

// serve starts a fake SSH server that sends greeting and closes.
func serve(t *testing.T, greeting []byte) check.Target {
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
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write(greeting)
				buf := make([]byte, 64)
				c.Read(buf) // wait for the client's version line
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	p, _ := strconv.Atoi(port)
	return check.Target{Host: host, Service: model.Service{Port: p, Protocol: "tcp", Name: "ssh"}}
}

func run(t *testing.T, a algos) (*check.Result, error) {
	t.Helper()
	g := append([]byte("SSH-2.0-OpenSSH_7.4\r\n"), kexInit(a)...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return Check{}.Run(ctx, serve(t, g))
}

func TestInfo(t *testing.T) {
	if err := check.Validate([]check.Check{Check{}}); err != nil {
		t.Fatal(err)
	}
	in := Check{}.Info()
	if !check.Applies(in, model.Service{Port: 2222, Name: "ssh"}) || !check.Applies(in, model.Service{Port: 22}) {
		t.Error("should apply to SSH by name or port 22")
	}
	if check.Applies(in, model.Service{Port: 80, Name: "http"}) {
		t.Error("shouldn't apply to HTTP")
	}
}

func TestModernIsClean(t *testing.T) {
	res, err := run(t, modern)
	if err != nil || res != nil {
		t.Fatalf("a modern OpenSSH default must not be flagged, got %+v, %v", res, err)
	}
}

func TestWeak(t *testing.T) {
	cases := []struct {
		name string
		a    algos
		want string
	}{
		{"sha1 kex", algos{modern.kex + ",diffie-hellman-group14-sha1", modern.hostKeys, modern.ciphers, modern.macs}, "key exchange (diffie-hellman-group14-sha1)"},
		{"gss kex", algos{"gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==," + modern.kex, modern.hostKeys, modern.ciphers, modern.macs}, "key exchange (gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==)"},
		{"dss host key", algos{modern.kex, modern.hostKeys + ",ssh-rsa,ssh-dss", modern.ciphers, modern.macs}, "host key (ssh-rsa, ssh-dss)"},
		{"cbc", algos{modern.kex, modern.hostKeys, modern.ciphers + ",aes128-cbc,3des-cbc", modern.macs}, "cipher (aes128-cbc, 3des-cbc)"},
		{"rc4", algos{modern.kex, modern.hostKeys, "arcfour256," + modern.ciphers, modern.macs}, "cipher (arcfour256)"},
		{"md5", algos{modern.kex, modern.hostKeys, modern.ciphers, modern.macs + ",hmac-md5,hmac-sha1-96"}, "MAC (hmac-md5, hmac-sha1-96)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := run(t, c.a)
			if err != nil || res == nil {
				t.Fatalf("want a finding, got %+v, %v", res, err)
			}
			want := "SSH-2.0-OpenSSH_7.4 offers weak algorithms: " + c.want
			if res.Evidence != want {
				t.Errorf("evidence\n got %q\nwant %q", res.Evidence, want)
			}
		})
	}
}

func TestEverythingWeak(t *testing.T) {
	res, err := run(t, algos{"diffie-hellman-group1-sha1", "ssh-dss", "3des-cbc", "hmac-md5"})
	if err != nil || res == nil {
		t.Fatalf("want a finding, got %+v, %v", res, err)
	}
	want := "key exchange (diffie-hellman-group1-sha1), host key (ssh-dss), cipher (3des-cbc), MAC (hmac-md5)"
	if !strings.HasSuffix(res.Evidence, want) {
		t.Errorf("evidence %q should end with %q", res.Evidence, want)
	}
}

func TestNotSSH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := Check{}.Run(ctx, serve(t, []byte("HTTP/1.1 400 Bad Request\r\n\r\n")))
	if err == nil || res != nil {
		t.Errorf("want an error and no finding, got %+v, %v", res, err)
	}
}

func TestServerDown(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	res, err := Check{}.Run(context.Background(), check.Target{Host: "127.0.0.1", Service: model.Service{Port: addr.Port, Name: "ssh"}})
	if err == nil || res != nil {
		t.Errorf("want an error and no finding, got %+v, %v", res, err)
	}
}
