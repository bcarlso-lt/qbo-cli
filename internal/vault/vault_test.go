package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/voska/qbo-cli/internal/auth"
	"github.com/voska/qbo-cli/internal/errfmt"
)

func exitCode(t *testing.T, err error) int {
	t.Helper()
	var e *errfmt.Error
	if !errors.As(err, &e) {
		t.Fatalf("not an errfmt error: %v", err)
	}
	return e.Code
}

func fakeVault(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	// httptest serves plain http on 127.0.0.1, which the real URL guard
	// rightly rejects — bypass it for fetch tests; it has its own test.
	orig := checkVaultURL
	checkVaultURL = func(string) error { return nil }
	t.Cleanup(func() { checkVaultURL = orig })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Query().Get("api-version") == "" {
			t.Error("missing api-version")
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The bearer token must never be attached to a request bound for a non-Azure
// or cleartext host — bootstrap.json is machine-scope but not tamper-proof.
func TestValidateVaultURL(t *testing.T) {
	valid := []string{
		"https://myvault.vault.azure.net",
		"https://MyVault.VAULT.AZURE.NET/",
		"https://gov.vault.usgovcloudapi.net",
	}
	for _, u := range valid {
		if err := validateVaultURL(u); err != nil {
			t.Errorf("validateVaultURL(%q) = %v, want nil", u, err)
		}
	}
	invalid := []string{
		"http://myvault.vault.azure.net",       // cleartext
		"https://attacker.example",             // arbitrary host
		"https://vault.azure.net.evil.example", // suffix spoof
		"not a url",
		"",
	}
	for _, u := range invalid {
		err := validateVaultURL(u)
		if err == nil {
			t.Errorf("validateVaultURL(%q) = nil, want error", u)
			continue
		}
		if got := exitCode(t, err); got != errfmt.ExitConfig {
			t.Errorf("validateVaultURL(%q) exit = %d, want %d", u, got, errfmt.ExitConfig)
		}
	}
}

// The guard runs before any request is built.
func TestFetchClientCredsRejectsBadVaultURL(t *testing.T) {
	_, err := FetchClientCreds(context.Background(), http.DefaultClient, "https://attacker.example", "s", "tok")
	if got := exitCode(t, err); got != errfmt.ExitConfig {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitConfig, err)
	}
}

func TestFetchClientCredsOK(t *testing.T) {
	srv := fakeVault(t, 200, map[string]string{
		"value": `{"client_id":"id","client_secret":"sec","redirect_uri":"https://cb"}`,
	})
	got, err := FetchClientCreds(context.Background(), srv.Client(), srv.URL, "qbo-creds", "tok")
	if err != nil {
		t.Fatal(err)
	}
	want := auth.ClientCreds{ClientID: "id", ClientSecret: "sec", RedirectURI: "https://cb", Origin: auth.CredsOriginBootstrap}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestFetchClientCredsForbidden(t *testing.T) {
	srv := fakeVault(t, 403, map[string]string{"error": "denied"})
	_, err := FetchClientCreds(context.Background(), srv.Client(), srv.URL, "qbo-creds", "tok")
	if got := exitCode(t, err); got != errfmt.ExitForbidden {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitForbidden, err)
	}
	if !strings.Contains(err.Error(), srv.URL+"/secrets/qbo-creds") {
		t.Fatalf("error should name the secret URL: %v", err)
	}
}

func TestFetchClientCredsNotFound(t *testing.T) {
	srv := fakeVault(t, 404, map[string]string{"error": "nope"})
	_, err := FetchClientCreds(context.Background(), srv.Client(), srv.URL, "qbo-creds", "tok")
	if got := exitCode(t, err); got != errfmt.ExitConfig {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitConfig, err)
	}
}

func TestFetchClientCredsServerError(t *testing.T) {
	srv := fakeVault(t, 503, map[string]string{"error": "down"})
	_, err := FetchClientCreds(context.Background(), srv.Client(), srv.URL, "qbo-creds", "tok")
	if got := exitCode(t, err); got != errfmt.ExitRetryable {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitRetryable, err)
	}
}

func TestFetchClientCredsUnreachable(t *testing.T) {
	srv := fakeVault(t, 200, nil)
	srv.Close() // connection refused from here on
	_, err := FetchClientCreds(context.Background(), http.DefaultClient, srv.URL, "qbo-creds", "tok")
	if got := exitCode(t, err); got != errfmt.ExitRetryable {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitRetryable, err)
	}
}

func TestFetchClientCredsMalformedSecret(t *testing.T) {
	for name, value := range map[string]string{
		"not json":       "hunter2",
		"missing fields": `{"client_id":"id"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := fakeVault(t, 200, map[string]string{"value": value})
			_, err := FetchClientCreds(context.Background(), srv.Client(), srv.URL, "qbo-creds", "tok")
			if got := exitCode(t, err); got != errfmt.ExitConfig {
				t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitConfig, err)
			}
		})
	}
}
