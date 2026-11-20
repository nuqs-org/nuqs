// Writes and reads just enough BSON, MongoDB's binary JSON, for one command and its reply.

package mongodbnoauth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

// element is one field of a BSON document. raw holds the value's bytes.
type element struct {
	name string
	kind byte
	raw  []byte
}

// BSON types we read or write.
const (
	bsonDouble = 0x01
	bsonString = 0x02
	bsonDoc    = 0x03
	bsonArray  = 0x04
	bsonBool   = 0x08
	bsonInt32  = 0x10
	bsonInt64  = 0x12
)

var errBadBSON = errors.New("bad BSON")

// elements splits a BSON document into its fields.
func elements(doc []byte) ([]element, error) {
	if len(doc) < 5 || int(binary.LittleEndian.Uint32(doc)) != len(doc) || doc[len(doc)-1] != 0 {
		return nil, errBadBSON
	}
	b := doc[4 : len(doc)-1]
	var out []element
	for len(b) > 0 {
		kind := b[0]
		end := strings.IndexByte(string(b[1:]), 0)
		if end < 0 {
			return nil, errBadBSON
		}
		name := string(b[1 : 1+end])
		b = b[2+end:]
		n, err := valueSize(kind, b)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", name, err)
		}
		out = append(out, element{name: name, kind: kind, raw: b[:n]})
		b = b[n:]
	}
	return out, nil
}

// fixed is the size of every BSON type that has one.
var fixed = map[byte]int{
	0x01: 8, 0x06: 0, 0x07: 12, 0x08: 1, 0x09: 8, 0x0A: 0,
	0x10: 4, 0x11: 8, 0x12: 8, 0x13: 16, 0xFF: 0, 0x7F: 0,
}

// valueSize returns how many bytes a value of this kind takes at the start of b.
func valueSize(kind byte, b []byte) (int, error) {
	n := 0
	if f, ok := fixed[kind]; ok {
		n = f
	} else {
		if len(b) < 4 {
			return 0, errBadBSON
		}
		l := int(int32(binary.LittleEndian.Uint32(b)))
		switch kind {
		case 0x02, 0x0D, 0x0E: // string, JavaScript, symbol: length then text
			n = 4 + l
		case 0x03, 0x04, 0x0F: // document, array, code with scope: length includes itself
			n = l
		case 0x05: // binary: length, subtype, bytes
			n = 5 + l
		case 0x0C: // DB pointer: string then a 12-byte ID
			n = 4 + l + 12
		default:
			return 0, fmt.Errorf("unknown BSON type 0x%02x", kind)
		}
		if l < 0 || n < 4 {
			return 0, errBadBSON
		}
	}
	if n > len(b) {
		return 0, errBadBSON
	}
	return n, nil
}

// str returns a string value, or "" if e isn't a string.
func (e element) str() string {
	if e.kind != bsonString || len(e.raw) < 5 {
		return ""
	}
	return string(e.raw[4 : len(e.raw)-1])
}

// num returns a number value as a float, for "ok" and "code".
func (e element) num() (float64, bool) {
	switch e.kind {
	case bsonDouble:
		return math.Float64frombits(binary.LittleEndian.Uint64(e.raw)), true
	case bsonInt32:
		return float64(int32(binary.LittleEndian.Uint32(e.raw))), true
	case bsonInt64:
		return float64(int64(binary.LittleEndian.Uint64(e.raw))), true
	case bsonBool:
		if e.raw[0] != 0 {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// bsonField is one field to write.
type bsonField struct {
	name  string
	value any // int32, bool or string
}

// encode writes a BSON document with the given fields in order.
func encode(fields ...bsonField) []byte {
	b := []byte{0, 0, 0, 0}
	for _, f := range fields {
		switch v := f.value.(type) {
		case int32:
			b = append(b, bsonInt32)
			b = append(append(b, f.name...), 0)
			b = binary.LittleEndian.AppendUint32(b, uint32(v))
		case bool:
			b = append(b, bsonBool)
			b = append(append(b, f.name...), 0)
			if v {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		case string:
			b = append(b, bsonString)
			b = append(append(b, f.name...), 0)
			b = binary.LittleEndian.AppendUint32(b, uint32(len(v)+1))
			b = append(append(b, v...), 0)
		default:
			panic(fmt.Sprintf("encode: unsupported type %T", v))
		}
	}
	b = append(b, 0)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}
