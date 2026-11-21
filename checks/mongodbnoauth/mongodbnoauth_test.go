// Tests the MongoDB check against a fake MongoDB server that speaks OP_MSG.

package mongodbnoauth

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// doc builds a BSON document from already-encoded elements.
func doc(elems ...[]byte) []byte {
	b := []byte{0, 0, 0, 0}
	for _, e := range elems {
		b = append(b, e...)
	}
	b = append(b, 0)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

func el(kind byte, name string, value []byte) []byte {
	return append(append(append([]byte{kind}, name...), 0), value...)
}

func double(name string, v float64) []byte {
	b := make([]byte, 8)
	if v == 1 {
		binary.LittleEndian.PutUint64(b, 0x3FF0000000000000)
	}
	return el(bsonDouble, name, b)
}

func i32(name string, v int32) []byte {
	return el(bsonInt32, name, binary.LittleEndian.AppendUint32(nil, uint32(v)))
}

func str(name, v string) []byte {
	return el(bsonString, name, append(binary.LittleEndian.AppendUint32(nil, uint32(len(v)+1)), append([]byte(v), 0)...))
}

func dbList(names ...string) []byte {
	var items [][]byte
	for i, n := range names {
		items = append(items, el(bsonDoc, strconv.Itoa(i), doc(str("name", n))))
	}
	return el(bsonArray, "databases", doc(items...))
}

// Real replies, shaped like MongoDB 8 sends them.
var (
	openReply   = doc(dbList("admin", "config", "local"), double("ok", 1))
	lockedReply = doc(double("ok", 0), str("errmsg", "command listDatabases requires authentication"), i32("code", 13), str("codeName", "Unauthorized"))
)

// fakeMongo answers every OP_MSG with reply and records the command it got.
type fakeMongo struct {
	reply   []byte // body document
	raw     []byte // if set, sent as-is instead
	wrongTo bool
	got     chan []byte
	addr    string
}

func (f *fakeMongo) start(t *testing.T) *fakeMongo {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f.addr = l.Addr().String()
	f.got = make(chan []byte, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeMongo) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	head := make([]byte, 16)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	body := make([]byte, binary.LittleEndian.Uint32(head)-16)
	if _, err := io.ReadFull(c, body); err != nil {
		return
	}
	f.got <- body[5:] // skip flags and section kind
	if f.raw != nil {
		c.Write(f.raw)
		return
	}
	to := int32(binary.LittleEndian.Uint32(head[4:]))
	if f.wrongTo {
		to++
	}
	out := message(99, f.reply)
	binary.LittleEndian.PutUint32(out[8:], uint32(to))
	c.Write(out)
}

func (f *fakeMongo) target() check.Target {
	host, port, _ := net.SplitHostPort(f.addr)
	p, _ := strconv.Atoi(port)
	return check.Target{Host: host, Service: model.Service{Port: p, Protocol: "tcp", Name: "mongodb"}}
}

func run(t *testing.T, f *fakeMongo) (*check.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return Check{}.Run(ctx, f.target())
}

func TestInfo(t *testing.T) {
	if err := check.Validate([]check.Check{Check{}}); err != nil {
		t.Fatal(err)
	}
	if !check.Applies(Check{}.Info(), model.Service{Port: 12717, Name: "mongodb"}) {
		t.Error("should apply to MongoDB on any port")
	}
}

func TestOpen(t *testing.T) {
	f := (&fakeMongo{reply: openReply}).start(t)
	res, err := run(t, f)
	if err != nil || res == nil {
		t.Fatalf("want a finding, got %+v, %v", res, err)
	}
	if want := "ran listDatabases without logging in and got 3 databases: admin, config, local"; res.Evidence != want {
		t.Errorf("evidence %q, want %q", res.Evidence, want)
	}

	// The command must be exactly listDatabases, names only, on admin.
	fields, err := elements(<-f.got)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range fields {
		v := e.str()
		if n, ok := e.num(); ok {
			v = strconv.FormatFloat(n, 'f', -1, 64)
		}
		got = append(got, e.name+"="+v)
	}
	if strings.Join(got, " ") != "listDatabases=1 nameOnly=1 $db=admin" {
		t.Errorf("sent %v", got)
	}
}

func TestLocked(t *testing.T) {
	for name, reply := range map[string][]byte{
		"code 13":     lockedReply,
		"only errmsg": doc(double("ok", 0), str("errmsg", "command listDatabases requires authentication")),
		"codeName":    doc(i32("ok", 0), str("codeName", "Unauthorized")),
	} {
		t.Run(name, func(t *testing.T) {
			res, err := run(t, (&fakeMongo{reply: reply}).start(t))
			if err != nil || res != nil {
				t.Errorf("want clean, got %+v, %v", res, err)
			}
		})
	}
}

func TestEmptyList(t *testing.T) {
	// A server with no databases yet is still open, anyone can create one.
	res, err := run(t, (&fakeMongo{reply: doc(dbList(), double("ok", 1))}).start(t))
	if err != nil || res == nil || res.Evidence != "ran listDatabases without logging in and got an empty list of databases" {
		t.Errorf("got %+v, %v", res, err)
	}
}

func TestManyDatabases(t *testing.T) {
	var names []string
	for i := range 12 {
		names = append(names, "db"+strconv.Itoa(i))
	}
	res, err := run(t, (&fakeMongo{reply: doc(dbList(names...), i32("ok", 1))}).start(t))
	if err != nil || res == nil || !strings.HasSuffix(res.Evidence, "db9 and 2 more") {
		t.Errorf("got %+v, %v", res, err)
	}
}

func TestOtherErrors(t *testing.T) {
	cases := map[string]*fakeMongo{
		"other error":   {reply: doc(double("ok", 0), str("errmsg", "not primary"), i32("code", 10107))},
		"wrong reply":   {reply: openReply, wrongTo: true},
		"http":          {raw: []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")},
		"bad bson":      {reply: []byte{9, 0, 0, 0, 0x10, 'o', 'k', 0, 0}},
		"databases bad": {reply: doc(str("databases", "x"), double("ok", 1))},
		"no databases":  {reply: doc(double("ok", 1))},
		"closes":        {raw: []byte{}},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := run(t, f.start(t))
			if err == nil || res != nil {
				t.Errorf("want an error and no finding, got %+v, %v", res, err)
			}
		})
	}
}

func TestTLSNotSupported(t *testing.T) {
	_, err := Check{}.Run(context.Background(), check.Target{Host: "127.0.0.1", Service: model.Service{Port: 27017, Tunnel: "ssl"}})
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Errorf("got %v", err)
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
	f := &fakeMongo{addr: l.Addr().String()}
	if res, err := (Check{}).Run(ctx, f.target()); err == nil || res != nil {
		t.Errorf("want a timeout error, got %+v, %v", res, err)
	}
	if time.Since(start) > time.Second {
		t.Error("didn't stop when the context ended")
	}
}

func FuzzReply(f *testing.F) {
	f.Add(message(1, openReply))
	f.Add(message(1, lockedReply))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) >= 16 {
			binary.LittleEndian.PutUint32(data[8:], 1) // so responseTo matches
		}
		body, err := readReply(strings.NewReader(string(data)), 1)
		if err != nil {
			return
		}
		judge(body)
	})
}
