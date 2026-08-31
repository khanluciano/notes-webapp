package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// setTestSecret installs a fixed signing key so tokens are reproducible.
func setTestSecret(t *testing.T) {
	t.Helper()
	sessionSecret = []byte("test-secret-key-for-session-tests")
}

func TestSessionRoundTrip(t *testing.T) {
	setTestSecret(t)

	token := signSession(42, time.Now().Add(time.Hour))
	id, ok := parseSession(token)
	if !ok {
		t.Fatalf("expected token %q to verify", token)
	}
	if id != 42 {
		t.Errorf("expected user id 42, got %d", id)
	}
}

func TestSessionRejectsTamperedUserID(t *testing.T) {
	setTestSecret(t)

	token := signSession(42, time.Now().Add(time.Hour))
	parts := strings.Split(token, ".")

	// Swap in a different user id while keeping the original signature —
	// the impersonation attempt the plaintext cookie previously allowed.
	forged := "43." + parts[1] + "." + parts[2]
	if _, ok := parseSession(forged); ok {
		t.Error("expected a token with a swapped user id to be rejected")
	}
}

func TestSessionRejectsTamperedSignature(t *testing.T) {
	setTestSecret(t)

	token := signSession(7, time.Now().Add(time.Hour))
	if _, ok := parseSession(token + "x"); ok {
		t.Error("expected a token with a modified signature to be rejected")
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	setTestSecret(t)

	token := signSession(7, time.Now().Add(-time.Minute))
	if _, ok := parseSession(token); ok {
		t.Error("expected an expired token to be rejected")
	}
}

func TestSessionRejectsForeignSecret(t *testing.T) {
	setTestSecret(t)
	token := signSession(7, time.Now().Add(time.Hour))

	// Simulates a restart with a different SESSION_SECRET.
	sessionSecret = []byte("a-completely-different-secret")
	if _, ok := parseSession(token); ok {
		t.Error("expected a token signed with another secret to be rejected")
	}
}

func TestSessionRejectsMalformed(t *testing.T) {
	setTestSecret(t)

	for _, token := range []string{"", "42", "42.", "42.999", "abc.def.ghi", "....."} {
		if _, ok := parseSession(token); ok {
			t.Errorf("expected malformed token %q to be rejected", token)
		}
	}
}

func TestSetUserCookieIsSignedAndHardened(t *testing.T) {
	setTestSecret(t)

	rec := httptest.NewRecorder()
	setUserCookie(rec, 99)

	res := http.Response{Header: rec.Header()}
	var session *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatalf("expected a %q cookie to be set", sessionCookieName)
	}

	// The raw id must not be the entire cookie value anymore.
	if session.Value == "99" {
		t.Error("session cookie still carries a bare user id")
	}
	if !session.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie should be SameSite=Lax")
	}

	id, ok := parseSession(session.Value)
	if !ok || id != 99 {
		t.Errorf("cookie value did not verify as user 99 (id=%d ok=%v)", id, ok)
	}
}

func TestLogoutClearsSessionCookies(t *testing.T) {
	rec := httptest.NewRecorder()
	Logout(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))

	res := http.Response{Header: rec.Header()}
	cleared := map[string]bool{}
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}

	// Both the new signed cookie and the legacy plaintext one must be expired.
	for _, name := range []string{sessionCookieName, "user_id"} {
		if !cleared[name] {
			t.Errorf("expected cookie %q to be cleared on logout", name)
		}
	}
}
