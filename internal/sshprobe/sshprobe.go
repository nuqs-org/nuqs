// Package sshprobe talks just enough SSH to answer two questions about a server:
// which algorithms it offers, and which login methods it allows.
//
// It never logs in and never sends a password. Hello only reads what the
// server says before encryption starts. AuthMethods does a full key exchange
// and then asks for the "none" login method, which every server answers with
// the list of methods it accepts.
//
// It only speaks a small set of algorithms (curve25519 or Diffie-Hellman
// group 14 for key exchange, aes128-ctr, hmac-sha2-256 or hmac-sha1), which
// every OpenSSH from the last ten years supports. The server's host key
// signature isn't verified: we learn nothing secret and send nothing secret,
// so there's nothing to protect.
package sshprobe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// clientBanner is what we send as our SSH version line.
const clientBanner = "SSH-2.0-Nuqs"

// maxRead caps how much we read from one server, so a hostile one can't make
// us use lots of memory.
const maxRead = 1 << 20

// Server is what a server says about itself before encryption starts.
type Server struct {
	Banner   string   // like "SSH-2.0-OpenSSH_9.6"
	Kex      []string // key exchange methods
	HostKeys []string // host key types
	Ciphers  []string // ciphers, both directions, in the server's order
	MACs     []string // MACs, both directions, in the server's order
}

// Hello connects, swaps version lines and reads the server's list of
// algorithms. It doesn't start a key exchange.
func Hello(ctx context.Context, addr string) (*Server, error) {
	c, err := dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer c.close()
	if err := c.hello(); err != nil {
		return nil, err
	}
	payload, err := c.next()
	if err != nil {
		return nil, fmt.Errorf("reading the server's algorithms: %w", err)
	}
	k, err := parseKexInit(payload)
	if err != nil {
		return nil, err
	}
	return &Server{
		Banner:   c.serverBanner,
		Kex:      k.kex,
		HostKeys: k.hostKeys,
		Ciphers:  union(k.ciphersC2S, k.ciphersS2C),
		MACs:     union(k.macsC2S, k.macsS2C),
	}, nil
}

// Auth is what a server answered when asked to log in with no credentials.
type Auth struct {
	Banner  string   // the server's version line
	Methods []string // methods it accepts, like "publickey" and "password"
	NoAuth  bool     // true if it let us in without any credentials at all
}

// AuthMethods does a key exchange, asks to log in as user with the "none"
// method and returns what the server said. It disconnects right after.
func AuthMethods(ctx context.Context, addr, user string) (*Auth, error) {
	c, err := dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer c.close()
	if err := c.hello(); err != nil {
		return nil, err
	}
	if err := c.keyExchange(); err != nil {
		return nil, fmt.Errorf("key exchange: %w", err)
	}

	if err := c.writePacket(newMsg(msgServiceRequest).str("ssh-userauth").bytes()); err != nil {
		return nil, err
	}
	if _, err := c.expect(msgServiceAccept); err != nil {
		return nil, fmt.Errorf("asking for the login service: %w", err)
	}
	req := newMsg(msgUserauthRequest).str(user).str("ssh-connection").str("none")
	if err := c.writePacket(req.bytes()); err != nil {
		return nil, err
	}
	for {
		p, err := c.next()
		if err != nil {
			return nil, fmt.Errorf("reading the login reply: %w", err)
		}
		switch p[0] {
		case msgUserauthBanner:
			continue // a message for humans, the real answer comes next
		case msgUserauthSuccess:
			c.disconnect()
			return &Auth{Banner: c.serverBanner, NoAuth: true}, nil
		case msgUserauthFailure:
			r := reader{b: p[1:]}
			methods := r.nameList()
			if r.err != nil {
				return nil, fmt.Errorf("bad login reply: %w", r.err)
			}
			c.disconnect()
			return &Auth{Banner: c.serverBanner, Methods: methods}, nil
		default:
			return nil, fmt.Errorf("unexpected message %d after the login request", p[0])
		}
	}
}

// conn is one SSH connection, with whatever keys are in use so far.
type conn struct {
	nc           net.Conn
	r            *bufio.Reader
	stop         func() bool
	serverBanner string
	in, out      direction
	sessionID    []byte
}

func dial(ctx context.Context, addr string) (*conn, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	} else {
		_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	}
	// Close the connection if ctx is cancelled, which unblocks any read.
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	return &conn{
		nc:   nc,
		r:    bufio.NewReader(io.LimitReader(nc, maxRead)),
		stop: stop,
		in:   direction{blockSize: 8},
		out:  direction{blockSize: 8},
	}, nil
}

func (c *conn) close() {
	c.stop()
	_ = c.nc.Close()
}

// hello sends our version line and reads the server's. Servers may send
// other lines first, which we skip.
func (c *conn) hello() error {
	if _, err := io.WriteString(c.nc, clientBanner+"\r\n"); err != nil {
		return err
	}
	for range 50 {
		line, err := c.readLine()
		if err != nil {
			return fmt.Errorf("reading the SSH version line: %w", err)
		}
		if !strings.HasPrefix(line, "SSH-") {
			continue
		}
		if !strings.HasPrefix(line, "SSH-2.0-") && !strings.HasPrefix(line, "SSH-1.99-") {
			return fmt.Errorf("server only speaks an old SSH version: %q", line)
		}
		c.serverBanner = line
		return nil
	}
	return errors.New("no SSH version line from the server")
}

// readLine reads one line of at most 255 bytes, without the line ending.
func (c *conn) readLine() (string, error) {
	var b []byte
	for len(b) <= 255 {
		ch, err := c.r.ReadByte()
		if err != nil {
			return "", err
		}
		if ch == '\n' {
			return strings.TrimSuffix(string(b), "\r"), nil
		}
		b = append(b, ch)
	}
	return "", errors.New("line too long, this isn't an SSH server")
}

// next returns the next packet, skipping the ones that carry no meaning.
func (c *conn) next() ([]byte, error) {
	for {
		p, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		switch p[0] {
		case msgIgnore, msgDebug, msgUnimplemented:
			continue
		case msgDisconnect:
			r := reader{b: p[1:]}
			_ = r.uint32()
			return nil, fmt.Errorf("server disconnected: %s", r.string())
		}
		return p, nil
	}
}

// expect returns the next packet and fails if it isn't of type want.
func (c *conn) expect(want byte) ([]byte, error) {
	p, err := c.next()
	if err != nil {
		return nil, err
	}
	if p[0] != want {
		return nil, fmt.Errorf("expected message %d, got %d", want, p[0])
	}
	return p, nil
}

// disconnect says goodbye politely. Errors don't matter, we're leaving.
func (c *conn) disconnect() {
	_ = c.writePacket(newMsg(msgDisconnect).uint32(11).str("bye").str("").bytes()) // 11: by application
}

// union returns a followed by the items of b that aren't in a.
func union(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, s := range b {
		found := false
		for _, t := range out {
			if s == t {
				found = true
				break
			}
		}
		if !found {
			out = append(out, s)
		}
	}
	return out
}
