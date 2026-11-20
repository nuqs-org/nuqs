// Tests the SSH probe against a small fake SSH server written from the RFCs.

package sshprobe

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeSSH is a tiny SSH server. It does a real key exchange, then answers
// the "none" login request.
type fakeSSH struct {
	preLines []string // sent before the version line
	banner   string   // our version line, default "SSH-2.0-FakeSSH_1.0"
	kex      []string // default: what the probe speaks
	hostKeys []string
	ciphers  []string
	macs     []string
	methods  string // reply to the login request, like "publickey,password"
	noAuth   bool   // let the client in without credentials
	userBan  string // send a login banner first
	garbage  string // send this instead of a version line

	addr    string
	gotUser chan string
}

func (f *fakeSSH) start(t *testing.T) *fakeSSH {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f.addr = l.Addr().String()
	f.gotUser = make(chan string, 10)
	if f.banner == "" {
		f.banner = "SSH-2.0-FakeSSH_1.0"
	}
	if f.kex == nil {
		f.kex = []string{"curve25519-sha256"}
	}
	if f.hostKeys == nil {
		f.hostKeys = []string{"ssh-ed25519"}
	}
	if f.ciphers == nil {
		f.ciphers = []string{"aes128-ctr"}
	}
	if f.macs == nil {
		f.macs = []string{"hmac-sha2-256"}
	}
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(nc)
		}
	}()
	return f
}

func (f *fakeSSH) serve(nc net.Conn) {
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(5 * time.Second))
	if f.garbage != "" {
		io.WriteString(nc, f.garbage)
		return
	}
	for _, l := range f.preLines {
		io.WriteString(nc, l+"\r\n")
	}
	io.WriteString(nc, f.banner+"\r\n")

	c := &conn{nc: nc, r: bufio.NewReader(nc), in: direction{blockSize: 8}, out: direction{blockSize: 8}}
	clientLine, err := c.readLine()
	if err != nil || !strings.HasPrefix(clientLine, "SSH-2.0-") {
		return
	}

	is := newMsg(msgKexInit).raw(make([]byte, 16)).
		nameList(f.kex).nameList(f.hostKeys).
		nameList(f.ciphers).nameList(f.ciphers).
		nameList(f.macs).nameList(f.macs).
		nameList([]string{"none"}).nameList([]string{"none"}).
		nameList(nil).nameList(nil).bool(false).uint32(0).bytes()
	if c.writePacket(is) != nil {
		return
	}
	ic, err := c.readPacket()
	if err != nil || ic[0] != msgKexInit {
		return
	}
	client, err := parseKexInit(ic)
	if err != nil {
		return
	}
	alg := ""
	for _, a := range client.kex {
		if slices.Contains(f.kex, a) {
			alg = a
			break
		}
	}
	if alg == "" {
		c.writePacket(newMsg(msgDisconnect).uint32(3).str("no kex in common").str("").bytes())
		return
	}
	init, err := c.readPacket()
	if err != nil || init[0] != msgKexInitDH {
		return
	}

	newHash := sha256.New
	if alg == "diffie-hellman-group14-sha1" {
		newHash = sha1.New
	}
	h := newHash()
	str := func(b []byte) { h.Write(newMsg(0).blob(b).bytes()[1:]) }
	str([]byte(clientLine))
	str([]byte(f.banner))
	str(ic)
	str(is)
	hostKey := newMsg(0).str("ssh-ed25519").blob(make([]byte, 32)).bytes()[1:]
	str(hostKey)

	r := reader{b: init[1:]}
	var reply *msg
	var secret []byte
	if strings.HasPrefix(alg, "curve25519") {
		qc := r.blob()
		priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		peer, err := ecdh.X25519().NewPublicKey(qc)
		if err != nil {
			return
		}
		secret, _ = priv.ECDH(peer)
		qs := priv.PublicKey().Bytes()
		str(qc)
		str(qs)
		reply = newMsg(msgKexReply).blob(hostKey).blob(qs)
	} else {
		e := new(big.Int).SetBytes(r.blob())
		y, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		fv := new(big.Int).Exp(big.NewInt(2), y, group14)
		secret = new(big.Int).Exp(e, y, group14).Bytes()
		h.Write(appendMpint(nil, e.Bytes()))
		h.Write(appendMpint(nil, fv.Bytes()))
		reply = newMsg(msgKexReply).blob(hostKey).mpint(fv.Bytes())
	}
	k := appendMpint(nil, secret)
	h.Write(k)
	hh := h.Sum(nil)
	if c.writePacket(reply.blob([]byte("fake signature")).bytes()) != nil {
		return
	}

	if c.writePacket([]byte{msgNewKeys}) != nil {
		return
	}
	nk, err := c.readPacket()
	if err != nil || nk[0] != msgNewKeys {
		return
	}
	key := func(l byte, n int) []byte { return testDerive(newHash, k, hh, l, n) }
	macHash, size := macAlg(f.macs[0])
	c.out.setKeys(key('B', 16), key('D', 16), macHash, key('F', size))
	c.in.setKeys(key('A', 16), key('C', 16), macHash, key('E', size))

	sr, err := c.readPacket()
	if err != nil || sr[0] != msgServiceRequest {
		return
	}
	c.writePacket(newMsg(msgIgnore).str("noise").bytes())
	c.writePacket(newMsg(msgServiceAccept).str("ssh-userauth").bytes())
	ar, err := c.readPacket()
	if err != nil || ar[0] != msgUserauthRequest {
		return
	}
	rr := reader{b: ar[1:]}
	f.gotUser <- rr.string() + "|" + rr.string() + "|" + rr.string()
	if f.userBan != "" {
		c.writePacket(newMsg(msgUserauthBanner).str(f.userBan).str("").bytes())
	}
	if f.noAuth {
		c.writePacket([]byte{msgUserauthSuccess})
	} else {
		c.writePacket(newMsg(msgUserauthFailure).str(f.methods).bool(false).bytes())
	}
	io.Copy(io.Discard, c.r) // wait for the client to leave
}

// testDerive is written separately from deriveKey on purpose, straight from RFC 4253 7.2.
func testDerive(newHash func() hash.Hash, k, h []byte, letter byte, n int) []byte {
	sum := func(parts ...[]byte) []byte {
		x := newHash()
		for _, p := range parts {
			x.Write(p)
		}
		return x.Sum(nil)
	}
	out := sum(k, h, []byte{letter}, h) // session ID is H for the first exchange
	for len(out) < n {
		out = append(out, sum(k, h, out)...)
	}
	return out[:n]
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestHello(t *testing.T) {
	f := (&fakeSSH{
		preLines: []string{"Welcome to the fake server"},
		kex:      []string{"curve25519-sha256", "diffie-hellman-group1-sha1"},
		hostKeys: []string{"ssh-ed25519", "ssh-dss"},
		ciphers:  []string{"aes128-ctr", "3des-cbc"},
		macs:     []string{"hmac-sha2-256", "hmac-md5"},
	}).start(t)
	s, err := Hello(ctx(t), f.addr)
	if err != nil {
		t.Fatal(err)
	}
	if s.Banner != "SSH-2.0-FakeSSH_1.0" {
		t.Errorf("banner %q", s.Banner)
	}
	if !slices.Equal(s.Kex, f.kex) || !slices.Equal(s.HostKeys, f.hostKeys) || !slices.Equal(s.Ciphers, f.ciphers) || !slices.Equal(s.MACs, f.macs) {
		t.Errorf("wrong algorithms: %+v", s)
	}
}

func TestAuthMethods(t *testing.T) {
	for _, kex := range ourKex {
		for _, mac := range ourMACs {
			t.Run(kex+"/"+mac, func(t *testing.T) {
				f := (&fakeSSH{kex: []string{kex}, macs: []string{mac}, methods: "publickey,password", userBan: "Authorized use only"}).start(t)
				a, err := AuthMethods(ctx(t), f.addr, "nuqs")
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(a.Methods, []string{"publickey", "password"}) || a.NoAuth || a.Banner != "SSH-2.0-FakeSSH_1.0" {
					t.Errorf("unexpected answer: %+v", a)
				}
				if got := <-f.gotUser; got != "nuqs|ssh-connection|none" {
					t.Errorf("login request was %q, want user nuqs with method none", got)
				}
			})
		}
	}
}

func TestAuthMethodsNoAuth(t *testing.T) {
	f := (&fakeSSH{noAuth: true}).start(t)
	a, err := AuthMethods(ctx(t), f.addr, "nuqs")
	if err != nil || !a.NoAuth {
		t.Fatalf("want NoAuth, got %+v, %v", a, err)
	}
}

func TestAuthMethodsNothingInCommon(t *testing.T) {
	f := (&fakeSSH{kex: []string{"sntrup761x25519-sha512"}}).start(t)
	if _, err := AuthMethods(ctx(t), f.addr, "nuqs"); err == nil || !strings.Contains(err.Error(), "key exchange") {
		t.Errorf("want a key exchange error, got %v", err)
	}
	f = (&fakeSSH{ciphers: []string{"chacha20-poly1305@openssh.com"}}).start(t)
	if _, err := AuthMethods(ctx(t), f.addr, "nuqs"); err == nil || !strings.Contains(err.Error(), "cipher") {
		t.Errorf("want a cipher error, got %v", err)
	}
}

func TestNotSSH(t *testing.T) {
	for name, g := range map[string]string{
		"http":     "HTTP/1.1 400 Bad Request\r\n\r\n",
		"ssh1":     "SSH-1.5-Old\r\n",
		"long":     strings.Repeat("x", 1000),
		"closed":   "\r\n",
		"no lines": "",
	} {
		t.Run(name, func(t *testing.T) {
			f := (&fakeSSH{garbage: g + " "}).start(t)
			if _, err := Hello(ctx(t), f.addr); err == nil {
				t.Error("want an error")
			}
			if _, err := AuthMethods(ctx(t), f.addr, "nuqs"); err == nil {
				t.Error("want an error")
			}
		})
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
	c, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Hello(c, l.Addr().String()); err == nil {
		t.Error("want a timeout error")
	}
	if time.Since(start) > time.Second {
		t.Error("didn't stop when the context ended")
	}
}

func TestMpint(t *testing.T) {
	cases := map[string]string{
		"":         "00000000",
		"\x00\x00": "00000000",
		"\x7f":     "000000017f",
		"\x80":     "000000020080",
		"\x00\x80": "000000020080",
		"\x01\x02": "000000020102",
	}
	for in, want := range cases {
		got := ""
		for _, b := range appendMpint(nil, []byte(in)) {
			got += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&15])
		}
		if got != want {
			t.Errorf("mpint(%x) = %s, want %s", in, got, want)
		}
	}
}

func FuzzReadPacket(f *testing.F) {
	f.Add([]byte("\x00\x00\x00\x0c\x0a\x14hello\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := &conn{r: bufio.NewReader(strings.NewReader(string(data))), in: direction{blockSize: 8}}
		p, err := c.readPacket()
		if err == nil && len(p) == 0 {
			t.Error("empty packet without an error")
		}
		if err == nil {
			parseKexInit(p)
			r := reader{b: p}
			r.nameList()
			r.blob()
		}
	})
}
