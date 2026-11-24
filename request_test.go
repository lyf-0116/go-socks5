package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/context"
)

// staticRewriter rewrites every request to a fixed destination.
type staticRewriter struct {
	target *AddrSpec
}

func (r *staticRewriter) Rewrite(ctx context.Context, req *Request) (context.Context, *AddrSpec) {
	return ctx, r.target
}

// blockInternalRules allows everything except destinations in 10.0.0.0/8.
type blockInternalRules struct{}

func (blockInternalRules) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	if ip4 := req.DestAddr.IP.To4(); ip4 != nil && ip4[0] == 10 {
		return ctx, false
	}
	return ctx, true
}

func newConnectRequestBuffer(ip net.IP, port int) *bytes.Buffer {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1})
	buf.Write(ip.To4())
	p := []byte{0, 0}
	binary.BigEndian.PutUint16(p, uint16(port))
	buf.Write(p)
	return buf
}

// A rewrite that redirects into a blocked internal range must be rejected
// by the rules instead of being dialed.
func TestRequest_Connect_RewrittenAddressCheckedByRules(t *testing.T) {
	dialed := make(chan string, 1)
	s := &Server{config: &Config{
		Rules:    blockInternalRules{},
		Resolver: DNSResolver{},
		Rewriter: &staticRewriter{target: &AddrSpec{IP: net.IPv4(10, 0, 0, 1), Port: 4444}},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed <- addr
			return nil, net.ErrClosed
		},
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}}

	// The client asks for a public-looking address; the rewriter would
	// redirect it to 10.0.0.1, which the rules forbid.
	req, err := NewRequest(newConnectRequestBuffer(net.IPv4(203, 0, 113, 5), 8080))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	resp := &MockConn{}
	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("expected rule failure, got: %v", err)
	}

	select {
	case addr := <-dialed:
		t.Fatalf("rewritten address must not be dialed when blocked, dialed: %v", addr)
	default:
	}

	out := resp.buf.Bytes()
	expected := []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(out, expected) {
		t.Fatalf("bad reply: %v", out)
	}
}

// The originally requested address must remain available for auditing,
// while DestAddr becomes the rewritten, dialed destination.
func TestRequest_Connect_RewritePreservesOriginalAndDialsRewrite(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer l.Close()
	lAddr := l.Addr().(*net.TCPAddr)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, conn)
		conn.Close()
	}()

	rewritten := &AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: lAddr.Port}
	var seenByRules *AddrSpec
	s := &Server{config: &Config{
		Rules: ruleFunc(func(ctx context.Context, req *Request) (context.Context, bool) {
			seenByRules = req.DestAddr
			return ctx, true
		}),
		Resolver: DNSResolver{},
		Rewriter: &staticRewriter{target: rewritten},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	req, err := NewRequest(newConnectRequestBuffer(net.IPv4(203, 0, 113, 5), 8080))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	resp := &MockConn{}
	if err := s.handleRequest(req, resp); err != nil {
		t.Fatalf("err: %v", err)
	}

	if req.OriginalDestAddr == nil || req.OriginalDestAddr.IP.Equal(rewritten.IP) {
		t.Fatalf("OriginalDestAddr should keep the requested address, got: %v", req.OriginalDestAddr)
	}
	if !req.OriginalDestAddr.IP.Equal(net.IPv4(203, 0, 113, 5)) || req.OriginalDestAddr.Port != 8080 {
		t.Fatalf("bad OriginalDestAddr: %v", req.OriginalDestAddr)
	}
	if req.DestAddr != rewritten {
		t.Fatalf("DestAddr should be the rewritten address, got: %v", req.DestAddr)
	}
	if seenByRules != rewritten {
		t.Fatalf("rules must evaluate the rewritten address, got: %v", seenByRules)
	}
}

type ruleFunc func(context.Context, *Request) (context.Context, bool)

func (f ruleFunc) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	return f(ctx, req)
}

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}
