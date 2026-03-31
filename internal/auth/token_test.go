package auth

import (
	"strings"
	"testing"
	"time"

	"rgstr/internal/config"
)

func newTestSvc() *TokenService {
	return NewTokenService(&config.Config{
		AuthIssuer:  "test-issuer",
		AuthService: "test-service",
		AuthSecret:  "test-secret-1234567890",
		TokenTTL:    time.Hour,
	})
}

func TestTokenRoundTrip(t *testing.T) {
	svc := newTestSvc()
	access := []Access{{Type: "repository", Name: "myrepo", Actions: []string{"pull", "push"}}}

	token, err := svc.Issue("alice", access)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	claims, err := svc.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("subject: got %q want %q", claims.Subject, "alice")
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "myrepo" {
		t.Errorf("access mismatch: %+v", claims.Access)
	}
}

func TestTokenTamperedSignature(t *testing.T) {
	svc := newTestSvc()
	token, _ := svc.Issue("alice", nil)

	// Change the first character of the signature to a different character,
	// guaranteeing the HMAC value actually changes.
	parts := strings.SplitN(token, ".", 3)
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	if _, err := svc.Verify(tampered); err == nil {
		t.Error("expected error for tampered signature, got nil")
	}
}

func TestTokenExpired(t *testing.T) {
	svc := NewTokenService(&config.Config{
		AuthIssuer:  "test-issuer",
		AuthService: "test-service",
		AuthSecret:  "test-secret",
		TokenTTL:    -time.Hour, // already expired
	})
	token, _ := svc.Issue("alice", nil)
	if _, err := svc.Verify(token); err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestTokenWrongAudience(t *testing.T) {
	svc := NewTokenService(&config.Config{
		AuthIssuer:  "issuer",
		AuthService: "service-A",
		AuthSecret:  "secret",
		TokenTTL:    time.Hour,
	})
	token, _ := svc.Issue("alice", nil)

	// Verify with a different service name.
	_, err := verify(token, "secret", "service-B")
	if err == nil {
		t.Error("expected error for wrong audience, got nil")
	}
}

func TestParseScope(t *testing.T) {
	cases := []struct {
		scope   string
		wantLen int
		wantType, wantName string
	}{
		{"repository:myrepo:pull", 1, "repository", "myrepo"},
		{"repository:library/ubuntu:pull,push", 1, "repository", "library/ubuntu"},
		{"bad-scope", 0, "", ""},
	}
	for _, c := range cases {
		got := ParseScope(c.scope)
		if len(got) != c.wantLen {
			t.Errorf("ParseScope(%q) len: got %d want %d", c.scope, len(got), c.wantLen)
			continue
		}
		if c.wantLen > 0 {
			if got[0].Type != c.wantType || got[0].Name != c.wantName {
				t.Errorf("ParseScope(%q): got {%s %s}, want {%s %s}",
					c.scope, got[0].Type, got[0].Name, c.wantType, c.wantName)
			}
		}
	}
}
