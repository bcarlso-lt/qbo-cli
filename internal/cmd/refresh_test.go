package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/voska/qbo-cli/internal/auth"
	"github.com/voska/qbo-cli/internal/config"
	"github.com/voska/qbo-cli/internal/errfmt"
	"golang.org/x/oauth2"
)

// stubRefresh replaces the Intuit refresh call; each element of results is
// consumed in order, and calls are recorded with the creds used.
type refreshCall struct{ clientID, clientSecret string }

func stubRefresh(t *testing.T, errs ...error) *[]refreshCall {
	t.Helper()
	orig := refreshAccessToken
	t.Cleanup(func() { refreshAccessToken = orig })
	var calls []refreshCall
	refreshAccessToken = func(_ context.Context, id, secret string, _ *oauth2.Token) (*oauth2.Token, error) {
		calls = append(calls, refreshCall{id, secret})
		if len(calls) <= len(errs) && errs[len(calls)-1] != nil {
			return nil, errs[len(calls)-1]
		}
		return &oauth2.Token{AccessToken: "fresh", Expiry: time.Now().Add(time.Hour)}, nil
	}
	return &calls
}

func stubFetch(t *testing.T, creds auth.ClientCreds, err error) *int {
	t.Helper()
	orig := fetchBootstrapCreds
	t.Cleanup(func() { fetchBootstrapCreds = orig })
	var calls int
	fetchBootstrapCreds = func(_ *Globals, _ *config.Bootstrap, deviceCode, silentOnly bool) (auth.ClientCreds, error) {
		calls++
		if deviceCode || !silentOnly {
			t.Error("self-heal must be silent: no device code, no interaction")
		}
		return creds, err
	}
	return &calls
}

func hermeticCmdKeyring(t *testing.T) {
	t.Helper()
	t.Setenv("QBO_KEYRING_BACKEND", "file")
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "test-passphrase")
	t.Setenv("QBO_CONFIG_DIR", t.TempDir())
	t.Setenv("QBO_CLIENT_ID", "")
	t.Setenv("QBO_CLIENT_SECRET", "")
}

var invalidClientErr error = &auth.InvalidClientError{Err: errfmt.Wrap(errfmt.ExitAuth, "token refresh failed", errfmt.New(errfmt.ExitAuth, `oauth2: "invalid_client"`))}

// Rotated org secret: refresh fails invalid_client, creds are re-fetched
// silently from the vault, and the retry succeeds with the new secret.
func TestRefreshSelfHealsRotatedBootstrapCreds(t *testing.T) {
	hermeticCmdKeyring(t)
	refreshes := stubRefresh(t, invalidClientErr, nil)
	rotated := auth.ClientCreds{ClientID: "id", ClientSecret: "new-sec", Origin: auth.CredsOriginBootstrap}
	fetches := stubFetch(t, rotated, nil)

	g := credsGlobals(&config.Config{},
		auth.ClientCreds{ClientID: "id", ClientSecret: "old-sec", Origin: auth.CredsOriginBootstrap},
		&config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	tok, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"})
	if err != nil || tok.AccessToken != "fresh" {
		t.Fatalf("refreshToken = %v, %v", tok, err)
	}
	if *fetches != 1 {
		t.Fatalf("fetches = %d, want 1", *fetches)
	}
	if got := *refreshes; len(got) != 2 || got[0].clientSecret != "old-sec" || got[1].clientSecret != "new-sec" {
		t.Fatalf("refresh calls = %+v", got)
	}
	if stored, ok, _ := auth.LoadClientCreds(); !ok || stored != rotated {
		t.Fatalf("rotated creds not persisted: %+v ok=%v", stored, ok)
	}
}

// User-supplied creds are never auto-replaced, whatever the error says.
func TestRefreshNeverHealsUserSuppliedCreds(t *testing.T) {
	hermeticCmdKeyring(t)
	stubRefresh(t, invalidClientErr)
	fetches := stubFetch(t, auth.ClientCreds{}, nil)

	g := credsGlobals(&config.Config{},
		auth.ClientCreds{ClientID: "id", ClientSecret: "sec"}, // set-client, no origin
		&config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	_, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"})
	if got := exitCode(err); got != errfmt.ExitAuth {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitAuth, err)
	}
	if !strings.Contains(err.Error(), "qbo auth login") {
		t.Fatalf("error should guide re-login: %v", err)
	}
	if *fetches != 0 {
		t.Fatalf("fetches = %d, want 0", *fetches)
	}
}

// A QBO_CLIENT_SECRET env override means the user supplied part of the
// credentials — never auto-replace, even with bootstrap-origin keyring creds.
func TestRefreshNeverHealsWithEnvSecretOverride(t *testing.T) {
	hermeticCmdKeyring(t)
	t.Setenv("QBO_CLIENT_SECRET", "user-rotated")
	stubRefresh(t, invalidClientErr)
	fetches := stubFetch(t, auth.ClientCreds{}, nil)

	g := credsGlobals(&config.Config{},
		auth.ClientCreds{ClientID: "id", ClientSecret: "old", Origin: auth.CredsOriginBootstrap},
		&config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	if _, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"}); err == nil {
		t.Fatal("want error")
	}
	if *fetches != 0 {
		t.Fatalf("fetches = %d, want 0", *fetches)
	}
}

// The vault secret's redirect_uri is optional: healing must not drop the
// redirect URI that login stored.
func TestSelfHealPreservesStoredRedirectURI(t *testing.T) {
	hermeticCmdKeyring(t)
	stubRefresh(t, invalidClientErr, nil)
	stubFetch(t, auth.ClientCreds{ClientID: "id", ClientSecret: "new", Origin: auth.CredsOriginBootstrap}, nil)

	g := credsGlobals(&config.Config{},
		auth.ClientCreds{ClientID: "id", ClientSecret: "old", RedirectURI: "https://prod/cb", Origin: auth.CredsOriginBootstrap},
		&config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	if _, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"}); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if stored, ok, _ := auth.LoadClientCreds(); !ok || stored.RedirectURI != "https://prod/cb" {
		t.Fatalf("redirect not preserved: %+v ok=%v", stored, ok)
	}
}

// A dead refresh token (non-invalid_client failure) guides re-login without
// touching the vault.
func TestRefreshDeadTokenGuidesRelogin(t *testing.T) {
	hermeticCmdKeyring(t)
	stubRefresh(t, errfmt.Wrap(errfmt.ExitAuth, "token refresh failed", errfmt.New(errfmt.ExitAuth, `oauth2: "invalid_grant"`)))
	fetches := stubFetch(t, auth.ClientCreds{}, nil)

	g := credsGlobals(&config.Config{},
		auth.ClientCreds{ClientID: "id", ClientSecret: "sec", Origin: auth.CredsOriginBootstrap},
		&config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	_, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"})
	if got := exitCode(err); got != errfmt.ExitAuth {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitAuth, err)
	}
	if !strings.Contains(err.Error(), "qbo auth login") {
		t.Fatalf("error should guide re-login: %v", err)
	}
	if *fetches != 0 {
		t.Fatalf("fetches = %d, want 0", *fetches)
	}
}

// The heal runs at most once per invocation, even if the retried refresh
// fails with invalid_client again.
func TestRefreshHealsAtMostOnce(t *testing.T) {
	hermeticCmdKeyring(t)
	refreshes := stubRefresh(t, invalidClientErr, invalidClientErr, invalidClientErr)
	fetches := stubFetch(t, auth.ClientCreds{ClientID: "id", ClientSecret: "s", Origin: auth.CredsOriginBootstrap}, nil)

	g := credsGlobals(&config.Config{},
		auth.ClientCreds{ClientID: "id", ClientSecret: "s", Origin: auth.CredsOriginBootstrap},
		&config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	if _, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"}); err == nil {
		t.Fatal("want error")
	}
	// A second refresh attempt in the same invocation must not re-heal.
	if _, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"}); err == nil {
		t.Fatal("want error")
	}
	if *fetches != 1 {
		t.Fatalf("fetches = %d, want 1", *fetches)
	}
	if len(*refreshes) != 3 {
		t.Fatalf("refresh calls = %d, want 3", len(*refreshes))
	}
}

// A failed vault re-fetch degrades to the guided re-login error.
func TestRefreshHealFetchFailureFallsBack(t *testing.T) {
	hermeticCmdKeyring(t)
	stubRefresh(t, invalidClientErr)
	fetches := stubFetch(t, auth.ClientCreds{}, errfmt.New(errfmt.ExitAuth, "no cached sign-in"))

	g := credsGlobals(&config.Config{},
		auth.ClientCreds{ClientID: "id", ClientSecret: "s", Origin: auth.CredsOriginBootstrap},
		&config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	_, err := g.refreshToken(&oauth2.Token{RefreshToken: "rt"})
	if got := exitCode(err); got != errfmt.ExitAuth {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitAuth, err)
	}
	if *fetches != 1 {
		t.Fatalf("fetches = %d, want 1", *fetches)
	}
}
