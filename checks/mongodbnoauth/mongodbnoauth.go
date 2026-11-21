// Package mongodbnoauth checks if a MongoDB server lets anyone read it without logging in.
//
// This is a "read-only probe" check. It sends one listDatabases command
// (names only) without logging in. A server with access control turned on
// answers "requires authentication". One without it lists its databases.
// Nothing is read from inside the databases and nothing is changed.
//
// It uses the OP_MSG message format, which MongoDB 3.6 and newer understand.
package mongodbnoauth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// maxReply caps the size of the reply we accept, so a hostile server can't
// make us use lots of memory. A database name list is tiny.
const maxReply = 1 << 20

// opMsg is MongoDB's message type for commands and their replies.
const opMsg = 2013

// codeUnauthorized is the error code MongoDB sends when you need to log in.
const codeUnauthorized = 13

// Check reports MongoDB servers with no access control.
type Check struct{}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:       "mongodb-no-auth",
		Title:    "MongoDB server has no password",
		Severity: model.High,
		Fix:      "Turn on access control (security.authorization: enabled in mongod.conf) and create users, or bind MongoDB to localhost only.",
		Ports:    []int{27017, 27018},
		Services: []string{"mongodb", "mongod"},
	}
}

// Run sends listDatabases and reports a finding if the server answers with a list.
func (Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.Service.Tunnel == "ssl" {
		return nil, fmt.Errorf("MongoDB over TLS isn't supported yet")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.Address())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	// Close the connection if ctx is cancelled, which unblocks any read.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	id := rand.Int32()
	cmd := encode(
		bsonField{"listDatabases", int32(1)},
		bsonField{"nameOnly", true},
		bsonField{"$db", "admin"},
	)
	if _, err := conn.Write(message(id, cmd)); err != nil {
		return nil, err
	}
	reply, err := readReply(conn, id)
	if err != nil {
		return nil, err
	}
	return judge(reply)
}

// message wraps a command document in an OP_MSG with no flags.
func message(id int32, doc []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(16+4+1+len(doc)))
	b = binary.LittleEndian.AppendUint32(b, uint32(id))
	b = binary.LittleEndian.AppendUint32(b, 0) // responseTo
	b = binary.LittleEndian.AppendUint32(b, opMsg)
	b = binary.LittleEndian.AppendUint32(b, 0) // flags
	b = append(b, 0)                           // section kind 0: the command body
	return append(b, doc...)
}

// readReply reads one OP_MSG reply to our request and returns its body document.
func readReply(r io.Reader, id int32) ([]byte, error) {
	head := make([]byte, 16)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("reading MongoDB reply: %w", err)
	}
	length := int(int32(binary.LittleEndian.Uint32(head)))
	responseTo := int32(binary.LittleEndian.Uint32(head[8:]))
	op := binary.LittleEndian.Uint32(head[12:])
	if length < 16+4+1+5 || length > maxReply {
		return nil, fmt.Errorf("bad MongoDB reply length %d, this may not be MongoDB", length)
	}
	if op != opMsg || responseTo != id {
		return nil, fmt.Errorf("unexpected MongoDB reply (op %d), this may be a MongoDB older than 3.6", op)
	}
	body := make([]byte, length-16)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("reading MongoDB reply: %w", err)
	}
	flags := binary.LittleEndian.Uint32(body)
	b := body[4:]
	if flags&1 != 0 { // checksumPresent: 4 bytes of CRC at the end
		if len(b) < 4 {
			return nil, errBadBSON
		}
		b = b[:len(b)-4]
	}
	for len(b) > 0 {
		kind := b[0]
		b = b[1:]
		if len(b) < 4 {
			return nil, errBadBSON
		}
		size := int(int32(binary.LittleEndian.Uint32(b)))
		if size < 5 || size > len(b) {
			return nil, errBadBSON
		}
		if kind == 0 {
			return b[:size], nil
		}
		b = b[size:] // kind 1, a document sequence, isn't used in replies we care about
	}
	return nil, errors.New("MongoDB reply has no body")
}

// judge decides what the reply means.
func judge(doc []byte) (*check.Result, error) {
	fields, err := elements(doc)
	if err != nil {
		return nil, err
	}
	var ok, code float64
	var codeName, errmsg string
	var names []string
	hasList := false
	for _, f := range fields {
		switch f.name {
		case "ok":
			ok, _ = f.num()
		case "code":
			code, _ = f.num()
		case "codeName":
			codeName = f.str()
		case "errmsg":
			errmsg = f.str()
		case "databases":
			if f.kind != bsonArray {
				return nil, errors.New(`"databases" isn't a list`)
			}
			hasList = true
			dbs, err := elements(f.raw)
			if err != nil {
				return nil, err
			}
			for _, db := range dbs {
				if db.kind != bsonDoc {
					continue
				}
				inner, err := elements(db.raw)
				if err != nil {
					return nil, err
				}
				for _, e := range inner {
					if e.name == "name" {
						names = append(names, e.str())
					}
				}
			}
		}
	}

	switch {
	case ok == 1 && !hasList:
		// Real MongoDB always sends the list, even an empty one. Without it we
		// can't say what we read, so don't claim a finding.
		return nil, errors.New(`MongoDB said ok but sent no "databases" list, this may not be MongoDB`)
	case ok == 1:
		return &check.Result{Evidence: "ran listDatabases without logging in and got " + list(names)}, nil
	case code == codeUnauthorized || codeName == "Unauthorized" || strings.Contains(errmsg, "requires authentication"):
		return nil, nil // access control is on
	default:
		return nil, fmt.Errorf("MongoDB said: %s (code %v)", errmsg, code)
	}
}

// list describes the database names, at most 10 of them.
func list(names []string) string {
	switch len(names) {
	case 0:
		return "an empty list of databases"
	case 1:
		return "1 database: " + names[0]
	}
	s := fmt.Sprintf("%d databases: ", len(names))
	if len(names) > 10 {
		return s + strings.Join(names[:10], ", ") + fmt.Sprintf(" and %d more", len(names)-10)
	}
	return s + strings.Join(names, ", ")
}
