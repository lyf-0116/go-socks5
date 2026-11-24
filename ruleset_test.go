package socks5

import (
	"bytes"
	"testing"

	"golang.org/x/net/context"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if _, ok := r.Allow(ctx, &Request{Command: ConnectCommand}); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Command: BindCommand}); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Command: AssociateCommand}); ok {
		t.Fatalf("do not expect associate")
	}
}

// userPermitRule permits a Connect only when the authenticated username
// matches the allow-list. It reads identity through the typed
// AuthContext.Username accessor instead of a string-literal payload key.
type userPermitRule struct {
	allowed map[string]struct{}
	seen    string
}

func (u *userPermitRule) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	username, ok := req.AuthContext.Username()
	if !ok {
		return ctx, false
	}
	u.seen = username
	_, permitted := u.allowed[username]
	return ctx, permitted
}

// authenticateUser runs the real user/pass handshake and returns the
// resulting AuthContext, mirroring Server.ServeConn.
func authenticateUser(t *testing.T, user, pass string) *AuthContext {
	t.Helper()
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, byte(len(user))})
	req.WriteString(user)
	req.Write([]byte{byte(len(pass))})
	req.WriteString(pass)

	s, err := New(&Config{
		AuthMethods: []Authenticator{
			UserPassAuthenticator{Credentials: StaticCredentials{"alice": "pw"}},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var resp bytes.Buffer
	authCtx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	return authCtx
}

// TestRule_ReceivesAuthenticatedUser is the regression test for identity
// propagation: the AuthContext produced during the handshake must be the
// one the RuleSet can read when authorizing the request.
func TestRule_ReceivesAuthenticatedUser(t *testing.T) {
	rule := &userPermitRule{allowed: map[string]struct{}{"alice": {}}}

	authCtx := authenticateUser(t, "alice", "pw")
	req := &Request{Command: ConnectCommand, AuthContext: authCtx}

	if _, ok := rule.Allow(context.Background(), req); !ok {
		t.Fatalf("alice must be permitted; rule observed username=%q", rule.seen)
	}
	if rule.seen != "alice" {
		t.Fatalf("rule saw username %q, want alice", rule.seen)
	}

	// An authenticated but unlisted user is denied.
	denied := &userPermitRule{allowed: map[string]struct{}{"alice": {}}}
	req.AuthContext = &AuthContext{
		Method:  UserPassAuth,
		Payload: map[string]string{PayloadUsername: "bob"},
	}
	if _, ok := denied.Allow(context.Background(), req); ok {
		t.Fatalf("bob must not be permitted")
	}

	// A request carrying no identity is denied rather than defaulting to allow.
	empty := &userPermitRule{allowed: map[string]struct{}{"alice": {}}}
	req.AuthContext = nil
	if _, ok := empty.Allow(context.Background(), req); ok {
		t.Fatalf("request without identity must not be permitted")
	}
}
