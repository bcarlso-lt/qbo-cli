package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIsLocalRedirect(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"http://localhost:8844/callback", true},
		{"http://127.0.0.1:8844/callback", true},
		{"http://[::1]:8844/callback", true},
		{"https://qbo-auth.leantechniques.com/callback", false},
		{"https://developer.intuit.com/v2/OAuth2Playground/RedirectUrl", false},
		{"://not a url", false},
	}
	for _, c := range cases {
		if got := isLocalRedirect(c.uri); got != c.want {
			t.Errorf("isLocalRedirect(%q) = %v, want %v", c.uri, got, c.want)
		}
	}
}

// TestLoginInteractiveBouncer exercises bouncer mode end to end: a hosted
// (non-local) redirect URI goes to Intuit in the auth URL and the token
// exchange, while the callback itself lands on the local listener, as the
// hosted bouncer page would forward it.
func TestLoginInteractiveBouncer(t *testing.T) {
	const hosted = "https://qbo-auth.example.com/callback"

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("token request parse: %v", err)
		}
		if got := r.Form.Get("redirect_uri"); got != hosted {
			t.Errorf("token exchange redirect_uri = %q, want %q", got, hosted)
		}
		if got := r.Form.Get("code"); got != "test-code" {
			t.Errorf("token exchange code = %q, want %q", got, "test-code")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt","token_type":"bearer","expires_in":3600}`)
	}))
	defer tokenSrv.Close()

	origTokenURL := tokenURL
	tokenURL = tokenSrv.URL
	defer func() { tokenURL = origTokenURL }()

	authURLCh := make(chan string, 1)
	origOpen := openBrowser
	openBrowser = func(u string) { authURLCh <- u }
	defer func() { openBrowser = origOpen }()

	type loginResult struct {
		res *AuthResult
		err error
	}
	done := make(chan loginResult, 1)
	go func() {
		res, err := LoginInteractive(context.Background(), "client-id", "client-secret", hosted, false)
		done <- loginResult{res, err}
	}()

	var authURL string
	select {
	case authURL = <-authURLCh:
	case <-time.After(5 * time.Second):
		t.Fatal("login never produced an auth URL")
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("auth URL unparseable: %v", err)
	}
	q := u.Query()
	if got := q.Get("redirect_uri"); got != hosted {
		t.Errorf("auth URL redirect_uri = %q, want %q", got, hosted)
	}
	state := q.Get("state")
	if state == "" {
		t.Fatal("auth URL missing state")
	}

	callback := fmt.Sprintf("http://127.0.0.1:%d/callback?state=%s&code=test-code&realmId=42", DefaultCallbackPort, url.QueryEscape(state))
	resp, err := http.Get(callback)
	if err != nil {
		t.Fatalf("callback request failed — bouncer mode did not start the local listener: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback returned %d: %s", resp.StatusCode, body)
	}

	select {
	case lr := <-done:
		if lr.err != nil {
			t.Fatalf("LoginInteractive: %v", lr.err)
		}
		if lr.res.RealmID != "42" {
			t.Errorf("RealmID = %q, want %q", lr.res.RealmID, "42")
		}
		if lr.res.Token.AccessToken != "at" {
			t.Errorf("AccessToken = %q, want %q", lr.res.Token.AccessToken, "at")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("login did not complete after callback")
	}
}

// TestLoginInteractiveStateMismatch confirms a forged callback is rejected.
func TestLoginInteractiveStateMismatch(t *testing.T) {
	authURLCh := make(chan string, 1)
	origOpen := openBrowser
	openBrowser = func(u string) { authURLCh <- u }
	defer func() { openBrowser = origOpen }()

	done := make(chan error, 1)
	go func() {
		_, err := LoginInteractive(context.Background(), "client-id", "client-secret", "", false)
		done <- err
	}()

	select {
	case <-authURLCh:
	case <-time.After(5 * time.Second):
		t.Fatal("login never produced an auth URL")
	}

	callback := fmt.Sprintf("http://127.0.0.1:%d/callback?state=wrong&code=x&realmId=1", DefaultCallbackPort)
	resp, err := http.Get(callback)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("forged callback returned %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	select {
	case lerr := <-done:
		if lerr == nil {
			t.Fatal("LoginInteractive accepted a state mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("login did not fail after state mismatch")
	}
}
