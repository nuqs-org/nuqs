// Reads and writes SSH packets, in plain text before the key exchange and encrypted after it.

package sshprobe

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// maxPacket is the biggest packet we accept. RFC 4253 says 35000 bytes is
// enough for everyone.
const maxPacket = 35000

// direction holds the state for one way of the connection.
type direction struct {
	blockSize int
	stream    cipher.Stream    // nil before the key exchange
	mac       func() hash.Hash // nil before the key exchange
	macKey    []byte
	seq       uint32 // counts every packet, encrypted or not
}

// macOf returns the MAC of a plain text packet with its sequence number.
func (d *direction) macOf(packet []byte) []byte {
	m := hmac.New(d.mac, d.macKey)
	_ = binary.Write(m, binary.BigEndian, d.seq)
	m.Write(packet)
	return m.Sum(nil)
}

func (c *conn) writePacket(payload []byte) error {
	d := &c.out
	pad := d.blockSize - (5+len(payload))%d.blockSize
	if pad < 4 {
		pad += d.blockSize
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
	packet = append(packet, byte(pad))
	packet = append(packet, payload...)
	padding := make([]byte, pad)
	_, _ = rand.Read(padding)
	packet = append(packet, padding...)

	var mac []byte
	if d.stream != nil {
		mac = d.macOf(packet)
		d.stream.XORKeyStream(packet, packet)
	}
	d.seq++
	_, err := c.nc.Write(append(packet, mac...))
	return err
}

func (c *conn) readPacket() ([]byte, error) {
	d := &c.in
	first := make([]byte, d.blockSize)
	if _, err := io.ReadFull(c.r, first); err != nil {
		return nil, err
	}
	if d.stream != nil {
		d.stream.XORKeyStream(first, first)
	}
	length := binary.BigEndian.Uint32(first)
	if length < 5 || length > maxPacket || (length+4)%uint32(d.blockSize) != 0 {
		return nil, fmt.Errorf("bad packet length %d", length)
	}
	packet := make([]byte, 4+length)
	copy(packet, first)
	if _, err := io.ReadFull(c.r, packet[len(first):]); err != nil {
		return nil, err
	}
	if d.stream != nil {
		d.stream.XORKeyStream(packet[len(first):], packet[len(first):])
		got := make([]byte, d.mac().Size())
		if _, err := io.ReadFull(c.r, got); err != nil {
			return nil, err
		}
		if !hmac.Equal(got, d.macOf(packet)) {
			return nil, errors.New("packet MAC doesn't match")
		}
	}
	d.seq++

	pad := int(packet[4])
	if pad < 4 || 5+pad >= len(packet) {
		return nil, fmt.Errorf("bad padding length %d", pad)
	}
	return packet[5 : len(packet)-pad], nil
}
