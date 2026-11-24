package socks5

import (
	"bytes"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != NoAuth {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, NoAuth}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}

	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != UserPassAuth {
		t.Fatal("Invalid Context Method")
	}

	val, ok := ctx.Payload["Username"]
	if !ok {
		t.Fatal("Missing key Username in auth context's payload")
	}

	if val != "foo" {
		t.Fatal("Invalid Username in auth context's payload")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != UserAuthFailed {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authFailure}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestNoSupportedAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != NoSupportedAuth {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, noAcceptable}) {
		t.Fatalf("bad: %v", out)
	}
}

type methodAlignmentAuthenticator struct {
	code    uint8
	context *AuthContext
}

func (a methodAlignmentAuthenticator) GetCode() uint8 {
	return a.code
}

func (a methodAlignmentAuthenticator) Authenticate(io.Reader, io.Writer) (*AuthContext, error) {
	return a.context, nil
}

func TestAuthenticateRejectsUnadvertisedContextMethod(t *testing.T) {
	authenticator := methodAlignmentAuthenticator{
		code:    UserPassAuth,
		context: &AuthContext{Method: NoAuth},
	}
	server, err := New(&Config{AuthMethods: []Authenticator{authenticator}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	request := bytes.NewBuffer([]byte{1, UserPassAuth})
	response := bytes.Buffer{}
	authContext, err := server.authenticate(&response, request)
	if err != InvalidAuth {
		t.Fatalf("expected InvalidAuth, got: %v", err)
	}
	if authContext != nil {
		t.Fatalf("expected nil context, got: %#v", authContext)
	}
}

func TestServeConnDisconnectsInvalidAuthContext(t *testing.T) {
	authenticator := methodAlignmentAuthenticator{
		code:    UserPassAuth,
		context: &AuthContext{Method: NoAuth},
	}
	server, err := New(&Config{
		AuthMethods: []Authenticator{authenticator},
		Logger:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- server.ServeConn(serverConn)
	}()

	if _, err := clientConn.Write([]byte{socks5Version, 1, UserPassAuth}); err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("err: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := clientConn.Read(buffer); err == nil {
		t.Fatal("expected invalid authentication to close the connection")
	}

	select {
	case serveErr := <-done:
		if serveErr == nil {
			t.Fatal("expected ServeConn to return an authentication error")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ServeConn to finish")
	}
}

func TestValidateAuthContextRejectsDifferentAdvertisedMethod(t *testing.T) {
	advertised := map[uint8]Authenticator{
		NoAuth:       NoAuthAuthenticator{},
		UserPassAuth: methodAlignmentAuthenticator{code: UserPassAuth},
	}

	err := validateAuthContext(&AuthContext{Method: NoAuth}, UserPassAuth, advertised)
	if err != InvalidAuth {
		t.Fatalf("expected InvalidAuth, got: %v", err)
	}
}

func TestValidateAuthContextAcceptsSelectedMethod(t *testing.T) {
	advertised := map[uint8]Authenticator{
		NoAuth: NoAuthAuthenticator{},
	}

	if err := validateAuthContext(&AuthContext{Method: NoAuth}, NoAuth, advertised); err != nil {
		t.Fatalf("err: %v", err)
	}
}
