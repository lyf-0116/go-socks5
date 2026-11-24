package socks5

import (
	"bytes"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"golang.org/x/net/context"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if _, ok := r.Allow(ctx, &Request{Command: ConnectCommand}, nil); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Command: BindCommand}, nil); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Command: AssociateCommand}, nil); ok {
		t.Fatalf("do not expect associate")
	}
}

type authCapturingRuleSet struct {
	authCh chan *AuthContext
}

func (r *authCapturingRuleSet) Allow(ctx context.Context, req *Request, auth *AuthContext) (context.Context, bool) {
	r.authCh <- auth
	return ctx, false
}

func TestRuleSetReceivesAuthContext(t *testing.T) {
	rules := &authCapturingRuleSet{authCh: make(chan *AuthContext, 1)}
	server, err := New(&Config{
		AuthMethods: []Authenticator{
			UserPassAuthenticator{Credentials: StaticCredentials{"foo": "bar"}},
		},
		Rules:  rules,
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer listener.Close()
	go server.Serve(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	var request bytes.Buffer
	request.Write([]byte{socks5Version, 1, UserPassAuth})
	request.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	request.Write([]byte{socks5Version, ConnectCommand, 0, ipv4Address, 127, 0, 0, 1, 0, 80})
	if _, err := conn.Write(request.Bytes()); err != nil {
		t.Fatalf("err: %v", err)
	}

	select {
	case auth := <-rules.authCh:
		if auth == nil {
			t.Fatal("rule received nil auth context")
		}
		if auth.Method != UserPassAuth {
			t.Fatalf("bad auth method: %v", auth.Method)
		}
		if username := auth.Payload["Username"]; username != "foo" {
			t.Fatalf("bad username: %q", username)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rule to receive auth context")
	}
}
