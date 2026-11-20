// Builds and reads the basic SSH data types: bytes, numbers, strings and lists.

package sshprobe

import (
	"encoding/binary"
	"errors"
	"strings"
)

// SSH message numbers we use, from RFC 4250.
const (
	msgDisconnect      = 1
	msgIgnore          = 2
	msgUnimplemented   = 3
	msgDebug           = 4
	msgServiceRequest  = 5
	msgServiceAccept   = 6
	msgKexInit         = 20
	msgNewKeys         = 21
	msgKexReply        = 31 // KEXDH_REPLY and KEX_ECDH_REPLY share this number
	msgKexInitDH       = 30 // KEXDH_INIT and KEX_ECDH_INIT share this number
	msgUserauthRequest = 50
	msgUserauthFailure = 51
	msgUserauthSuccess = 52
	msgUserauthBanner  = 53
)

// msg builds one message.
type msg struct{ b []byte }

func newMsg(t byte) *msg { return &msg{b: []byte{t}} }

func (m *msg) bytes() []byte { return m.b }

func (m *msg) byte(v byte) *msg {
	m.b = append(m.b, v)
	return m
}

func (m *msg) raw(v []byte) *msg {
	m.b = append(m.b, v...)
	return m
}

func (m *msg) uint32(v uint32) *msg {
	m.b = binary.BigEndian.AppendUint32(m.b, v)
	return m
}

func (m *msg) bool(v bool) *msg {
	if v {
		return m.byte(1)
	}
	return m.byte(0)
}

func (m *msg) str(s string) *msg { return m.blob([]byte(s)) }

func (m *msg) blob(v []byte) *msg {
	m.uint32(uint32(len(v)))
	return m.raw(v)
}

func (m *msg) nameList(names []string) *msg { return m.str(strings.Join(names, ",")) }

// mpint adds a non-negative number given as big-endian bytes.
func (m *msg) mpint(v []byte) *msg {
	m.b = appendMpint(m.b, v)
	return m
}

// appendMpint encodes a non-negative big-endian number the SSH way: no
// leading zeros, plus one zero byte when the top bit is set so it doesn't
// read as negative.
func appendMpint(b, v []byte) []byte {
	for len(v) > 0 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) > 0 && v[0]&0x80 != 0 {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)+1))
		b = append(b, 0)
		return append(b, v...)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

var errShort = errors.New("message too short")

// reader reads fields from a message. After the first error every read
// returns a zero value, so callers only check r.err once at the end.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errShort
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) byte() byte {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}

func (r *reader) uint32() uint32 {
	v := r.take(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (r *reader) bool() bool { return r.byte() != 0 }

func (r *reader) blob() []byte {
	n := r.uint32()
	if r.err == nil && n > uint32(len(r.b)) {
		r.err = errShort
		return nil
	}
	return r.take(int(n))
}

func (r *reader) string() string { return string(r.blob()) }

func (r *reader) nameList() []string {
	s := r.string()
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
